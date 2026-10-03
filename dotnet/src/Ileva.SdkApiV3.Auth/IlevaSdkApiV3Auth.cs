using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Ileva.SdkApiV3.Auth.Stores;

namespace Ileva.SdkApiV3.Auth;

/// <summary>
/// Obtém o token de acesso da API Ileva e mantém sua validade.
///
/// O token é guardado no store e reaproveitado enquanto for válido; perto de expirar, é renovado.
/// A API mantém um único token ativo por usuário — gerar um novo invalida o anterior —, então a
/// renovação é feita sob lock: só um processo pede o token e os outros esperam por ele no cache.
///
/// O token em cache só é devolvido a quem informa a mesma senha que o gerou: junto dele fica um
/// verificador da senha (PBKDF2), e uma senha diferente faz o SDK consultar a API. Assim a aplicação
/// pode usar o SDK no login dos seus usuários sem que o cache aceite qualquer senha.
///
/// Token obtido com código 2FA nunca é devolvido do cache: o SDK não tem como conferir o código (o
/// segredo fica no sistema Ileva), então cada uso vai à API com o código informado.
/// </summary>
public sealed partial class IlevaSdkApiV3Auth
{
    public const string DefaultBaseUrl = "https://api.ileva.com.br";

    private const string PasswordCheckAlgorithm = "pbkdf2-sha256";
    private const int PasswordCheckIterations = 100_000;

    // Um valor adulterado no cache não pode travar o processo com um número absurdo de iterações.
    private const int PasswordCheckMaxIterations = 1_000_000;

    private static readonly TimeSpan PollInterval = TimeSpan.FromMilliseconds(100);
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private static readonly char[] KeyTrimChars = { ' ', '\t', '\n', '\r', '\v', '\0' };

    // Cliente padrão, compartilhado: criar um HttpClient por instância esgota conexões.
    private static readonly Lazy<HttpClient> DefaultHttpClient = new(() => new HttpClient { Timeout = System.Threading.Timeout.InfiniteTimeSpan });

    // Chave aleatória do processo para o HMAC da senha usado na memorização das conferências.
    private static readonly byte[] ProcessSecret = RandomNumberGenerator.GetBytes(32);

    // Chamadas simultâneas no mesmo processo aguardam a mesma resolução, em vez de disputar o lock e
    // esperar pelo intervalo de consulta ao cache.
    private static readonly Dictionary<string, Task<Token>> Pending = new();
    private static readonly object PendingGate = new();

    // Conferências de senha já feitas no processo, por chave do token: o token conferido e o HMAC da
    // senha (nunca a senha). O PBKDF2 é pago uma vez por processo a cada token.
    private static readonly ConcurrentDictionary<string, (string AccessToken, byte[] PasswordDigest)> Verified = new();

    private readonly string _appKey;
    private readonly string _password;
    private readonly ITokenStore _store;
    private readonly HttpClient _http;
    private readonly Func<CancellationToken, Task<string>>? _twoFactorCode;
    private readonly TimeSpan _refreshMargin;
    private readonly TimeSpan _timeout;
    private readonly TimeSpan _lockWait;
    private readonly string _tokenKey;
    private readonly string _lockKey;
    private readonly byte[] _passwordDigest;
    private readonly string _pendingKey;

    /// <summary>
    /// Instâncias com a mesma app key e o mesmo usuário compartilham o token: sem Redis, pela memória
    /// do processo; com Redis, entre processos, servidores e com os SDKs de PHP, Node e Python.
    /// </summary>
    public IlevaSdkApiV3Auth(IlevaAuthOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (string.IsNullOrEmpty(options.AppKey) || string.IsNullOrEmpty(options.Username) || string.IsNullOrEmpty(options.Password))
        {
            throw new ArgumentException("app key, usuário e senha são obrigatórios.", nameof(options));
        }
        if (options.Redis is not null && options.Store is not null)
        {
            throw new ArgumentException("Informe Redis ou Store, não os dois.", nameof(options));
        }
        if (options.TwoFactorCode is not null && options.TwoFactorCodeAsync is not null)
        {
            throw new ArgumentException("Informe TwoFactorCode ou TwoFactorCodeAsync, não os dois.", nameof(options));
        }
        if (options.RefreshMargin < TimeSpan.Zero || options.Timeout <= TimeSpan.Zero || options.LockWait <= TimeSpan.Zero)
        {
            throw new ArgumentException("RefreshMargin não pode ser negativo; Timeout e LockWait devem ser positivos.", nameof(options));
        }

        BaseUrl = options.BaseUrl.TrimEnd('/');
        Username = options.Username;
        _appKey = options.AppKey;
        _password = options.Password;
        _store = options.Store ?? (options.Redis is not null ? new RedisTokenStore(options.Redis) : new InMemoryTokenStore());
        _http = options.HttpClient ?? DefaultHttpClient.Value;
        _twoFactorCode = options.TwoFactorCodeAsync
            ?? (options.TwoFactorCode is { } sync ? _ => Task.FromResult(sync()) : null);
        _refreshMargin = options.RefreshMargin;
        _timeout = options.Timeout;
        _lockWait = options.LockWait;

        // A chave identifica o token pelo ambiente, pela associação (app key) e pelo usuário — a mesma
        // combinação que a API usa para manter um token ativo. A senha fica fora, para que uma troca de
        // senha não deixe o token antigo órfão no cache. É o mesmo cálculo dos SDKs das outras
        // linguagens, para que todos compartilhem o token.
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
            $"{AsciiLower(BaseUrl)}\n{_appKey}\n{AsciiLower(Username.Trim(KeyTrimChars))}"))).ToLowerInvariant();
        _tokenKey = $"{options.KeyPrefix}:token:{hash}";
        _lockKey = $"{options.KeyPrefix}:lock:{hash}";
        _passwordDigest = HMACSHA256.HashData(ProcessSecret, Encoding.UTF8.GetBytes(_password));
        // Só chamadas com a mesma senha compartilham a requisição em andamento: uma senha errada não
        // pode receber o token que a requisição de quem acertou vai trazer.
        _pendingKey = $"{_tokenKey}:{Convert.ToHexString(_passwordDigest)}";
    }

    public string BaseUrl { get; }

    public string Username { get; }

    /// <summary>Token de acesso válido, gerado ou renovado se necessário.</summary>
    public async Task<string> GetTokenAsync(CancellationToken cancellationToken = default) =>
        (await ResolveTokenAsync(cancellationToken).ConfigureAwait(false)).AccessToken;

    /// <summary>Valor pronto para o header Authorization, ex.: "Bearer eyJ...".</summary>
    public async Task<string> GetAuthorizationHeaderAsync(CancellationToken cancellationToken = default) =>
        (await ResolveTokenAsync(cancellationToken).ConfigureAwait(false)).AuthorizationHeader();

    /// <summary>Token com o instante de expiração.</summary>
    public Task<Token> GetTokenDetailsAsync(CancellationToken cancellationToken = default) => ResolveTokenAsync(cancellationToken);

    /// <summary>
    /// Descarta o token do cache, para que a próxima chamada gere outro. Chame ao receber 401 da API,
    /// passando o token que foi recusado: se outro processo já o substituiu, o novo é preservado.
    /// </summary>
    public Task InvalidateAsync(string? rejectedToken = null, CancellationToken cancellationToken = default) =>
        _store.DeleteAsync(_tokenKey, rejectedToken, cancellationToken);

    /// <summary>Gera um token novo mesmo que o atual ainda seja válido.</summary>
    public async Task<string> RefreshAsync(CancellationToken cancellationToken = default)
    {
        await InvalidateAsync(null, cancellationToken).ConfigureAwait(false);
        return await GetTokenAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Não expõe a senha nem a app key em logs e no depurador.</summary>
    public override string ToString() => $"IlevaSdkApiV3Auth {{ BaseUrl = {BaseUrl}, Username = {Username} }}";

    /// <summary>Esquece as conferências de senha memorizadas no processo. Uso dos testes.</summary>
    internal static void ClearVerifiedForTests() => Verified.Clear();

    private Task<Token> ResolveTokenAsync(CancellationToken cancellationToken)
    {
        // Com 2FA, cada chamada vai à API com o próprio código. Compartilhar a requisição em andamento
        // entregaria o token a quem tem a senha certa e um código qualquer.
        if (_twoFactorCode is not null)
        {
            return ResolveTokenFromStoreAsync(cancellationToken);
        }

        Task<Token> shared;
        lock (PendingGate)
        {
            if (!Pending.TryGetValue(_pendingKey, out shared!))
            {
                // A requisição compartilhada não pode ser cancelada por um único chamador: cada um
                // espera por ela com o seu próprio token de cancelamento (WaitAsync, abaixo).
                shared = Task.Run(RunSharedAsync);
                Pending[_pendingKey] = shared;
            }
        }
        return shared.WaitAsync(cancellationToken);
    }

    private async Task<Token> RunSharedAsync()
    {
        try
        {
            return await ResolveTokenFromStoreAsync(CancellationToken.None).ConfigureAwait(false);
        }
        finally
        {
            lock (PendingGate)
            {
                Pending.Remove(_pendingKey);
            }
        }
    }

    private async Task<Token> ResolveTokenFromStoreAsync(CancellationToken cancellationToken)
    {
        var cached = await ReadCachedTokenAsync(cancellationToken).ConfigureAwait(false);
        if (cached is not null)
        {
            return cached;
        }

        // Espera o suficiente para outro processo terminar a requisição de token (timeout) e, se ele
        // tiver morrido segurando o lock, para o lock expirar e ser obtido aqui.
        var lockTtlMs = (long)(_timeout.TotalMilliseconds + 5_000);
        var deadline = DateTime.UtcNow + _lockWait;

        do
        {
            var owner = RandomNumberGenerator.GetHexString(32, lowercase: true);
            if (await _store.AcquireLockAsync(_lockKey, owner, lockTtlMs, cancellationToken).ConfigureAwait(false))
            {
                try
                {
                    // Outro processo pode ter renovado entre a leitura acima e a obtenção do lock.
                    return await ReadCachedTokenAsync(cancellationToken).ConfigureAwait(false)
                        ?? await RequestAndStoreTokenAsync(cancellationToken).ConfigureAwait(false);
                }
                finally
                {
                    // Solta o lock mesmo se a chamada foi cancelada: senão ele ficaria até expirar.
                    await _store.ReleaseLockAsync(_lockKey, owner, CancellationToken.None).ConfigureAwait(false);
                }
            }

            await Task.Delay(PollInterval, cancellationToken).ConfigureAwait(false);

            var token = await ReadCachedTokenAsync(cancellationToken).ConfigureAwait(false);
            if (token is not null)
            {
                return token;
            }
        }
        while (DateTime.UtcNow < deadline);

        throw new IlevaLockTimeoutException(
            $"O token não foi renovado por outro processo em {Math.Round(_lockWait.TotalSeconds)} segundos.");
    }

    /// <summary>
    /// Token do cache, se ainda válido e gerado com a mesma senha informada nesta instância. Com outra
    /// senha devolve null, como se o cache estivesse vazio: o SDK consulta a API, que recusa a senha
    /// errada — e o token de quem acertou continua no cache.
    /// </summary>
    private async Task<Token?> ReadCachedTokenAsync(CancellationToken cancellationToken)
    {
        var value = await _store.GetAsync(_tokenKey, cancellationToken).ConfigureAwait(false);
        if (value is null)
        {
            return null;
        }
        var token = Token.FromJson(value);
        if (token is null || !token.IsValid(NowSeconds(), (int)_refreshMargin.TotalSeconds))
        {
            return null;
        }
        // Servir do cache pularia o 2FA: quem soubesse só a senha receberia o token. Ele continua
        // gravado para substituir o token anterior do usuário, que a API invalidou ao gerar este.
        if (token.TwoFactor)
        {
            return null;
        }
        if (IsVerified(token))
        {
            return token;
        }
        var check = Token.PasswordCheckFromJson(value);
        if (check is null || !await PasswordMatchesAsync(check).ConfigureAwait(false))
        {
            return null;
        }
        MarkVerified(token);
        return token;
    }

    private async Task<Token> RequestAndStoreTokenAsync(CancellationToken cancellationToken)
    {
        var token = await RequestTokenAsync(cancellationToken).ConfigureAwait(false);
        var check = await CreatePasswordCheckAsync().ConfigureAwait(false);
        await _store.SetAsync(_tokenKey, token.ToJson(check), token.ExpiresAt - NowSeconds(), cancellationToken).ConfigureAwait(false);
        MarkVerified(token);
        return token;
    }

    private Task<string> CreatePasswordCheckAsync() => Task.Run(() =>
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var hash = Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(_password), salt, PasswordCheckIterations, HashAlgorithmName.SHA256, 32);
        return string.Join('$', PasswordCheckAlgorithm, PasswordCheckIterations, Convert.ToBase64String(salt), Convert.ToBase64String(hash));
    });

    /// <summary>Um verificador fora do formato conta como senha diferente.</summary>
    private Task<bool> PasswordMatchesAsync(string check)
    {
        var parts = check.Split('$');
        if (parts.Length != 4 || parts[0] != PasswordCheckAlgorithm || !DigitsRegex().IsMatch(parts[1]))
        {
            return Task.FromResult(false);
        }
        if (!int.TryParse(parts[1], out var iterations) || iterations < 1 || iterations > PasswordCheckMaxIterations)
        {
            return Task.FromResult(false);
        }
        var salt = DecodeBase64(parts[2]);
        var expected = DecodeBase64(parts[3]);
        if (salt is null || expected is null)
        {
            return Task.FromResult(false);
        }

        return Task.Run(() =>
        {
            var actual = Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(_password), salt, iterations, HashAlgorithmName.SHA256, expected.Length);
            return CryptographicOperations.FixedTimeEquals(expected, actual);
        });
    }

    private bool IsVerified(Token token) =>
        Verified.TryGetValue(_tokenKey, out var entry)
        && entry.AccessToken == token.AccessToken
        && CryptographicOperations.FixedTimeEquals(entry.PasswordDigest, _passwordDigest);

    private void MarkVerified(Token token) => Verified[_tokenKey] = (token.AccessToken, _passwordDigest);

    private async Task<Token> RequestTokenAsync(CancellationToken cancellationToken)
    {
        var url = $"{BaseUrl}/oauth/token";
        var body = await EncodeCredentialsAsync(cancellationToken).ConfigureAwait(false);

        var requestedAt = NowSeconds();
        using var request = new HttpRequestMessage(HttpMethod.Post, url)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json"),
        };
        request.Headers.TryAddWithoutValidation("Accept", "application/json");
        request.Headers.TryAddWithoutValidation("app_key", _appKey);

        // O timeout é do SDK (e não do HttpClient, que pode ser o da aplicação e ter outro valor).
        using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutSource.CancelAfter(_timeout);

        int status;
        string text;
        try
        {
            using var response = await _http.SendAsync(request, timeoutSource.Token).ConfigureAwait(false);
            status = (int)response.StatusCode;
            text = await response.Content.ReadAsStringAsync(timeoutSource.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new IlevaTransportException($"Falha ao conectar em {url}: timeout de {_timeout.TotalMilliseconds:0} ms");
        }
        catch (HttpRequestException error)
        {
            throw new IlevaTransportException($"Falha ao conectar em {url}: {error.Message}", error);
        }

        var data = ParseJsonObject(text);

        if (status != 200)
        {
            var message = data is not null && data.RootElement.TryGetProperty("mensagem", out var mensagem) && mensagem.ValueKind == JsonValueKind.String
                ? mensagem.GetString()!
                : $"A API respondeu HTTP {status} ao gerar o token.";
            data?.Dispose();
            if (status == 401)
            {
                throw new IlevaAuthenticationException(message);
            }
            throw new IlevaApiException(message, status);
        }

        using (data)
        {
            if (data is null
                || !data.RootElement.TryGetProperty("access_token", out var accessToken) || accessToken.ValueKind != JsonValueKind.String
                || !data.RootElement.TryGetProperty("expires_in", out var expiresIn) || !TryReadSeconds(expiresIn, out var expiresInSeconds))
            {
                throw new IlevaApiException("Resposta de token fora do formato esperado.", status);
            }

            var tokenType = data.RootElement.TryGetProperty("token_type", out var type) && type.ValueKind == JsonValueKind.String
                ? type.GetString()!
                : "Bearer";

            // Conta a validade a partir do envio, não da resposta: assim o tempo de rede nunca faz o SDK
            // achar que o token vale mais do que a API considera.
            return new Token(accessToken.GetString()!, tokenType, requestedAt + expiresInSeconds, _twoFactorCode is not null);
        }
    }

    // A senha e a app key só existem em campos privados e dentro do corpo da requisição: nunca vão
    // para a mensagem de uma exceção.
    private async Task<string> EncodeCredentialsAsync(CancellationToken cancellationToken)
    {
        var credentials = new Dictionary<string, string> { ["username"] = Username, ["password"] = _password };
        if (_twoFactorCode is not null)
        {
            credentials["two_fa"] = await _twoFactorCode(cancellationToken).ConfigureAwait(false);
        }

        // O serializador troca um caractere inválido por U+FFFD em silêncio, o que enviaria à API uma
        // senha diferente da informada. A mensagem não cita os valores nem guarda a exceção original.
        foreach (var value in credentials.Values)
        {
            if (!IsValidUtf16(value))
            {
                throw new ArgumentException("Usuário, senha ou código 2FA com caracteres que não são UTF-16 válido.");
            }
        }

        return JsonSerializer.Serialize(credentials);
    }

    private static bool IsValidUtf16(string value)
    {
        try
        {
            _ = StrictUtf8.GetByteCount(value);
            return true;
        }
        catch (EncoderFallbackException)
        {
            return false;
        }
    }

    // Normalização da chave, idêntica nos SDKs de todas as linguagens: minúsculas só em ASCII e trim só
    // de " \t\n\r\v\0". ToLower() e Trim() convertem e removem também caracteres Unicode, o que daria
    // chaves diferentes das do PHP, do Node e do Python.
    private static string AsciiLower(string value) =>
        string.Create(value.Length, value, static (span, source) =>
        {
            for (var i = 0; i < source.Length; i++)
            {
                var c = source[i];
                span[i] = c is >= 'A' and <= 'Z' ? (char)(c + 32) : c;
            }
        });

    /// <summary>Base64 estrito e não vazio; null para qualquer outra coisa.</summary>
    private static byte[]? DecodeBase64(string value)
    {
        if (value.Length == 0 || !Base64Regex().IsMatch(value))
        {
            return null;
        }
        try
        {
            var decoded = Convert.FromBase64String(value);
            return decoded.Length > 0 ? decoded : null;
        }
        catch (FormatException)
        {
            return null;
        }
    }

    private static long NowSeconds() => DateTimeOffset.UtcNow.ToUnixTimeSeconds();

    private static JsonDocument? ParseJsonObject(string text)
    {
        try
        {
            var document = JsonDocument.Parse(text);
            if (document.RootElement.ValueKind == JsonValueKind.Object)
            {
                return document;
            }
            document.Dispose();
            return null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    // A API pode devolver expires_in como número ou como texto numérico.
    private static bool TryReadSeconds(JsonElement element, out long seconds)
    {
        seconds = 0;
        if (element.ValueKind == JsonValueKind.Number && element.TryGetDouble(out var number) && double.IsFinite(number))
        {
            seconds = (long)Math.Truncate(number);
            return true;
        }
        if (element.ValueKind == JsonValueKind.String
            && double.TryParse(element.GetString(), System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var parsed)
            && double.IsFinite(parsed))
        {
            seconds = (long)Math.Truncate(parsed);
            return true;
        }
        return false;
    }

    [GeneratedRegex("^[0-9]+$")]
    private static partial Regex DigitsRegex();

    [GeneratedRegex("^[A-Za-z0-9+/]+={0,2}$")]
    private static partial Regex Base64Regex();
}
