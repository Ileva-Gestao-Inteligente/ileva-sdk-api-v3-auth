using System.Net;
using System.Reflection;
using System.Text.Json.Nodes;
using Ileva.SdkApiV3.Auth.Stores;
using StackExchange.Redis;
using Xunit;

namespace Ileva.SdkApiV3.Auth.Tests;

public sealed class IlevaSdkApiV3AuthTests : IDisposable
{
    private const string SegredoCheck = Keys.SegredoCheck;

    private const string InvalidCredentials = """{"status":401,"mensagem":"Usuário ou senha inválidos"}""";

    private readonly FakeHttp _http = new();
    private readonly InMemoryTokenStore _store = new();

    public IlevaSdkApiV3AuthTests()
    {
        Reset();
    }

    public void Dispose() => Reset();

    private static void Reset()
    {
        InMemoryTokenStore.Clear();
        IlevaSdkApiV3Auth.ClearVerifiedForTests();
    }

    private static long Now() => DateTimeOffset.UtcNow.ToUnixTimeSeconds();

    private IlevaSdkApiV3Auth Auth(Action<IlevaAuthOptions>? configure = null)
    {
        var options = new IlevaAuthOptions
        {
            AppKey = "app-key",
            Username = "integracao",
            Password = "segredo",
            HttpClient = _http.Client(),
            BaseUrl = "https://api.teste/",
        };
        configure?.Invoke(options);
        return new IlevaSdkApiV3Auth(options);
    }

    /// <summary>Grava um token no cache como o SDK grava: com o verificador da senha "segredo".</summary>
    private Task Seed(Token token, long ttl, string? passwordCheck = SegredoCheck) =>
        _store.SetAsync(Keys.TokenKey, token.ToJson(passwordCheck), ttl);

    [Fact]
    public async Task GeraOTokenComAAppKeyNoHeaderEAsCredenciaisNoBody()
    {
        _http.Token("tok-1");

        Assert.Equal("tok-1", await Auth().GetTokenAsync());

        var request = Assert.Single(_http.Requests);
        Assert.Equal("https://api.teste/oauth/token", request.Url);
        Assert.Equal("app-key", request.Header("app_key"));
        Assert.Equal("application/json", request.Message.Content!.Headers.ContentType!.MediaType);
        Assert.Equal("integracao", (string?)request.Body["username"]);
        Assert.Equal("segredo", (string?)request.Body["password"]);
        Assert.Equal(2, request.Body.Count);
    }

    [Fact]
    public async Task InstanciasComAsMesmasCredenciaisCompartilhamOTokenDaMemoria()
    {
        _http.Token("tok-1");
        await Auth().GetTokenAsync();

        var outra = Auth();
        Assert.Equal("tok-1", await outra.GetTokenAsync());
        Assert.Equal("Bearer tok-1", await outra.GetAuthorizationHeaderAsync());
        Assert.Single(_http.Requests);
    }

    [Fact]
    public async Task ChamadasSimultaneasNoProcessoGeramUmUnicoToken()
    {
        _http.DelayedToken("tok-1", 50);

        var tokens = await Task.WhenAll(Enumerable.Range(0, 10).Select(_ => Auth().GetTokenAsync()));

        Assert.All(tokens, token => Assert.Equal("tok-1", token));
        Assert.Single(_http.Requests);
    }

    [Fact]
    public async Task CancelarUmChamadorNaoCancelaARequisicaoCompartilhada()
    {
        _http.DelayedToken("tok-1", 100);
        using var cancellation = new CancellationTokenSource();

        var cancelled = Auth().GetTokenAsync(cancellation.Token);
        var other = Auth().GetTokenAsync();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => cancelled);
        Assert.Equal("tok-1", await other);
        Assert.Single(_http.Requests);
    }

    [Fact]
    public async Task UsuariosDaMesmaAppKeyTemTokensIndependentes()
    {
        _http.Token("tok-joao").Token("tok-maria");

        Assert.Equal("tok-joao", await Auth(o => o.Username = "joao").GetTokenAsync());
        Assert.Equal("tok-maria", await Auth(o => o.Username = "maria").GetTokenAsync());
        Assert.Equal("tok-joao", await Auth(o => o.Username = "joao").GetTokenAsync());
        Assert.Equal("tok-maria", await Auth(o => o.Username = "maria").GetTokenAsync());
        Assert.Equal(2, _http.Requests.Count);
    }

    [Fact]
    public async Task InvalidarUmUsuarioNaoAfetaOutro()
    {
        _http.Token("tok-joao").Token("tok-maria").Token("tok-joao-2");
        var joao = Auth(o => o.Username = "joao");
        var maria = Auth(o => o.Username = "maria");
        await joao.GetTokenAsync();
        await maria.GetTokenAsync();

        await joao.InvalidateAsync();

        Assert.Equal("tok-maria", await maria.GetTokenAsync());
        Assert.Equal("tok-joao-2", await joao.GetTokenAsync());
        Assert.Equal(3, _http.Requests.Count);
    }

    [Fact]
    public async Task OMesmoUsuarioEmAppKeysDiferentesTemTokensIndependentes()
    {
        _http.Token("tok-a").Token("tok-b");

        Assert.Equal("tok-a", await Auth(o => o.AppKey = "associacao-a").GetTokenAsync());
        Assert.Equal("tok-b", await Auth(o => o.AppKey = "associacao-b").GetTokenAsync());
        Assert.Equal("tok-a", await Auth(o => o.AppKey = "associacao-a").GetTokenAsync());
        Assert.Equal(2, _http.Requests.Count);
    }

    [Fact]
    public async Task AChaveDoCacheIgnoraACaixaDoUsuarioEABarraFinalDaUrl()
    {
        _http.Token("tok-1");
        await Auth().GetTokenAsync();

        Assert.NotNull(await _store.GetAsync(Keys.TokenKey));
        Assert.Equal("tok-1", await Auth(o => { o.Username = " Integracao "; o.BaseUrl = "https://api.teste"; }).GetTokenAsync());
        Assert.Single(_http.Requests);
    }

    [Fact]
    public async Task AChaveUsaMinusculasSoEmAsciiComoOsOutrosSdks()
    {
        // "Ã" não vira "ã": as funções de minúsculas de cada linguagem divergem fora do ASCII, e a
        // chave precisa ser igual em todas. Espaço Unicode ( ) também não é removido.
        _http.Token("tok-1").Token("tok-2");
        await Auth(o => o.Username = " JOÃO\t").GetTokenAsync();

        var key = $"ileva:auth:token:{Keys.Sha256Hex("https://api.teste\napp-key\njoÃo")}";
        Assert.NotNull(await _store.GetAsync(key));

        await Auth(o => o.Username = " integracao").GetTokenAsync();
        Assert.Equal(2, _http.Requests.Count);
    }

    [Fact]
    public async Task GravaNoCacheNoFormatoCompartilhadoComOsOutrosSdks()
    {
        _http.Token("tok-1", 3600);
        var before = Now();

        await Auth().GetTokenAsync();

        var stored = JsonNode.Parse((await _store.GetAsync(Keys.TokenKey))!)!.AsObject();
        Assert.Equal("tok-1", (string?)stored["access_token"]);
        Assert.Equal("Bearer", (string?)stored["token_type"]);
        Assert.InRange((long)stored["expires_at"]!, before + 3600, Now() + 3600);
        Assert.Equal(new[] { "access_token", "token_type", "expires_at", "password_check" }, stored.Select(p => p.Key));
    }

    [Fact]
    public async Task LeOTokenGravadoPeloSdkDePhp()
    {
        // Mesmo JSON que o Token::toJson() do PHP grava.
        await _store.SetAsync(
            Keys.TokenKey,
            $$"""{"access_token":"do-php","token_type":"Bearer","expires_at":{{Now() + 3600}},"password_check":"{{SegredoCheck}}"}""",
            3600);

        Assert.Equal("do-php", await Auth().GetTokenAsync());
        Assert.Empty(_http.Requests);
    }

    [Fact]
    public async Task RenovaOTokenDentroDaMargemDeRenovacao()
    {
        await Seed(new Token("velho", "Bearer", Now() + 200), 200);
        _http.Token("novo");

        Assert.Equal("novo", await Auth(o => o.RefreshMargin = TimeSpan.FromSeconds(300)).GetTokenAsync());
    }

    [Fact]
    public async Task UsaOTokenForaDaMargemDeRenovacao()
    {
        await Seed(new Token("atual", "Bearer", Now() + 400), 400);

        Assert.Equal("atual", await Auth(o => o.RefreshMargin = TimeSpan.FromSeconds(300)).GetTokenAsync());
        Assert.Empty(_http.Requests);
    }

    [Fact]
    public async Task ValorCorrompidoNoCacheETratadoComoVazio()
    {
        await _store.SetAsync(Keys.TokenKey, "nao-e-json", 60);
        _http.Token("tok-1");

        Assert.Equal("tok-1", await Auth().GetTokenAsync());
    }

    [Fact]
    public async Task InvalidateComTokenRecusadoPreservaOTokenNovoDeOutroProcesso()
    {
        await Seed(new Token("novo", "Bearer", Now() + 3600), 3600);
        var instance = Auth();

        await instance.InvalidateAsync("velho");

        Assert.Equal("novo", await instance.GetTokenAsync());
        Assert.Empty(_http.Requests);
    }

    [Fact]
    public async Task InvalidateComOTokenAtualForcaNovaGeracao()
    {
        _http.Token("tok-1").Token("tok-2");
        var instance = Auth();

        await instance.InvalidateAsync(await instance.GetTokenAsync());

        Assert.Equal("tok-2", await instance.GetTokenAsync());
    }

    [Fact]
    public async Task RefreshGeraTokenMesmoComTokenValido()
    {
        _http.Token("tok-1").Token("tok-2");
        var instance = Auth();
        await instance.GetTokenAsync();

        Assert.Equal("tok-2", await instance.RefreshAsync());
    }

    [Fact]
    public async Task GetTokenDetailsDevolveAValidade()
    {
        _http.Token("tok-1", 3600);
        var before = Now();

        var token = await Auth().GetTokenDetailsAsync();

        Assert.Equal("tok-1", token.AccessToken);
        Assert.InRange(token.ExpiresAt, before + 3600, Now() + 3600);
        Assert.DoesNotContain("tok-1", token.ToString());
    }

    [Fact]
    public async Task EnviaOCodigoDeDoisFatores()
    {
        _http.Token("tok-1").Token("tok-2");

        await Auth(o => o.TwoFactorCode = () => "123456").GetTokenAsync();
        InMemoryTokenStore.Clear();
        await Auth(o => o.TwoFactorCodeAsync = _ => Task.FromResult("654321")).GetTokenAsync();

        Assert.Equal("123456", (string?)_http.Requests[0].Body["two_fa"]);
        Assert.Equal("654321", (string?)_http.Requests[1].Body["two_fa"]);
    }

    [Fact]
    public async Task Erro401ViraAuthenticationExceptionComAMensagemDaApi()
    {
        _http.Json(HttpStatusCode.Unauthorized, InvalidCredentials);

        var error = await Assert.ThrowsAsync<IlevaAuthenticationException>(() => Auth().GetTokenAsync());

        Assert.Equal("Usuário ou senha inválidos", error.Message);
        Assert.Equal(401, error.Status);
    }

    [Fact]
    public async Task ErroDiferenteDe401ViraApiExceptionComOStatus()
    {
        _http.Json(HttpStatusCode.InternalServerError, "Internal Server Error");

        var error = await Assert.ThrowsAsync<IlevaApiException>(() => Auth().GetTokenAsync());

        Assert.Equal(500, error.Status);
    }

    [Theory]
    [InlineData("""{"expires_in":60}""")]
    [InlineData("""{"access_token":"x"}""")]
    [InlineData("""{"access_token":"x","expires_in":"abc"}""")]
    [InlineData("""{"access_token":5,"expires_in":60}""")]
    [InlineData("[]")]
    [InlineData("não é json")]
    public async Task RespostaForaDoFormatoViraApiException(string body)
    {
        _http.Json(HttpStatusCode.OK, body);

        await Assert.ThrowsAsync<IlevaApiException>(() => Auth().GetTokenAsync());
    }

    [Fact]
    public async Task AceitaExpiresInComoTexto()
    {
        _http.Json(HttpStatusCode.OK, """{"access_token":"tok-1","expires_in":"3600"}""");
        var before = Now();

        var token = await Auth().GetTokenDetailsAsync();

        Assert.Equal("Bearer", token.TokenType);
        Assert.InRange(token.ExpiresAt, before + 3600, Now() + 3600);
    }

    [Fact]
    public async Task FalhaDeRedeViraTransportExceptionComOErroOriginal()
    {
        _http.Fail(new HttpRequestException("connection refused"));

        var error = await Assert.ThrowsAsync<IlevaTransportException>(() => Auth().GetTokenAsync());

        Assert.Contains("connection refused", error.Message);
        Assert.IsType<HttpRequestException>(error.InnerException);
    }

    [Fact]
    public async Task TimeoutDaRequisicaoViraTransportException()
    {
        _http.Hang();

        await Assert.ThrowsAsync<IlevaTransportException>(() => Auth(o => o.Timeout = TimeSpan.FromMilliseconds(50)).GetTokenAsync());
    }

    [Fact]
    public async Task CancelamentoDoChamadorNaoViraTransportException()
    {
        _http.Hang();
        using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(50));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Auth(o => o.TwoFactorCode = () => "123456").GetTokenAsync(cancellation.Token));
    }

    [Fact]
    public async Task SenhaErradaComTokenEmCacheConsultaAApiERecebe401()
    {
        _http.Token("tok-certo");
        await Auth().GetTokenAsync();
        _http.Json(HttpStatusCode.Unauthorized, InvalidCredentials);

        await Assert.ThrowsAsync<IlevaAuthenticationException>(() => Auth(o => o.Password = "errada").GetTokenAsync());

        // A senha errada foi à API; o token de quem acertou continua no cache.
        Assert.Equal(2, _http.Requests.Count);
        Assert.Equal("errada", (string?)_http.Requests[1].Body["password"]);
        Assert.Equal("tok-certo", await Auth().GetTokenAsync());
        Assert.Equal(2, _http.Requests.Count);
    }

    [Fact]
    public async Task SenhaErradaNaoAproveitaAConferenciaMemorizadaDaSenhaCerta()
    {
        _http.Token("tok-certo");
        await Auth().GetTokenAsync();
        Assert.Equal("tok-certo", await Auth().GetTokenAsync()); // conferência memorizada no processo
        _http.Json(HttpStatusCode.Unauthorized, InvalidCredentials);

        await Assert.ThrowsAsync<IlevaAuthenticationException>(() => Auth(o => o.Password = "errada").GetTokenAsync());
    }

    [Fact]
    public async Task SenhaErradaSimultaneaNaoPegaCaronaNaRequisicaoDeQuemAcertou()
    {
        // A primeira requisição (senha certa) demora; a segunda (senha errada) chega enquanto ela está
        // em andamento e precisa ir à API por conta própria.
        _http.DelayedToken("tok-certo", 100).Json(HttpStatusCode.Unauthorized, InvalidCredentials);

        var certo = Auth().GetTokenAsync();
        var errado = Auth(o => o.Password = "errada").GetTokenAsync();

        Assert.Equal("tok-certo", await certo);
        await Assert.ThrowsAsync<IlevaAuthenticationException>(() => errado);
    }

    [Fact]
    public async Task AceitaOVerificadorGravadoPorOutroSdk()
    {
        await Seed(new Token("do-php", "Bearer", Now() + 3600), 3600, SegredoCheck);

        Assert.Equal("do-php", await Auth().GetTokenAsync());
        Assert.Empty(_http.Requests);
    }

    [Fact]
    public async Task TokenSemVerificadorETratadoComoCacheVazio()
    {
        await Seed(new Token("sem-verificador", "Bearer", Now() + 3600), 3600, null);
        _http.Token("tok-novo");

        Assert.Equal("tok-novo", await Auth().GetTokenAsync());
    }

    [Theory]
    [InlineData("pbkdf2-sha256$99999999$AQEBAQEBAQEBAQEBAQEBAQ==$MC4obyTDiJ9/piZiz+KFtXeenFNNoJQjr5MSPiDBgxM=")]
    [InlineData("md5$1$AQ==$AQ==")]
    [InlineData("pbkdf2-sha256$100000$@@@$AQ==")]
    [InlineData("pbkdf2-sha256$100000$AQEBAQEBAQEBAQEBAQEBAQ==$MC4obyTDiJ9/piZiz+KFtXeenFNNoJQjr5MSPiDBgxM=$extra")]
    [InlineData("pbkdf2-sha256$0$AQ==$AQ==")]
    [InlineData("lixo")]
    public async Task VerificadorAdulteradoETratadoComoSenhaDiferente(string check)
    {
        await Seed(new Token("adulterado", "Bearer", Now() + 3600), 3600, check);
        _http.Token("tok-novo");

        Assert.Equal("tok-novo", await Auth().GetTokenAsync());
    }

    [Fact]
    public async Task SenhaNovaCorretaSubstituiOTokenGeradoComASenhaAntiga()
    {
        _http.Token("tok-senha-antiga").Token("tok-senha-nova");
        await Auth(o => o.Password = "antiga").GetTokenAsync();

        Assert.Equal("tok-senha-nova", await Auth(o => o.Password = "nova").GetTokenAsync());
        Assert.Equal("tok-senha-nova", await Auth(o => o.Password = "nova").GetTokenAsync());
        Assert.Equal(2, _http.Requests.Count);
    }

    [Fact]
    public async Task TokenObtidoCom2faNaoEDevolvidoDoCacheSemOCodigo()
    {
        _http.Token("tok-com-2fa");
        await Auth(o => o.TwoFactorCode = () => "123456").GetTokenAsync();
        _http.Json(HttpStatusCode.Unauthorized, """{"status":401,"mensagem":"Informe o código de verificação de autenticação de dois fatores (two_fa)"}""");

        // Senha certa, sem o código: vai à API, que exige o 2FA.
        var error = await Assert.ThrowsAsync<IlevaAuthenticationException>(() => Auth().GetTokenAsync());

        Assert.Contains("dois fatores", error.Message);
        Assert.Equal(2, _http.Requests.Count);
        Assert.False(_http.Requests[1].Body.ContainsKey("two_fa"));
    }

    [Fact]
    public async Task CadaLoginCom2faConsultaAApi()
    {
        _http.Token("tok-1").Token("tok-2");

        Assert.Equal("tok-1", await Auth(o => o.TwoFactorCode = () => "111111").GetTokenAsync());
        Assert.Equal("tok-2", await Auth(o => o.TwoFactorCode = () => "222222").GetTokenAsync());

        Assert.Equal(2, _http.Requests.Count);
        Assert.Equal("222222", (string?)_http.Requests[1].Body["two_fa"]);
    }

    [Fact]
    public async Task Codigo2faErradoSimultaneoNaoPegaCaronaNoLoginDeQuemAcertou()
    {
        _http.DelayedToken("tok-vitima", 100).Json(HttpStatusCode.Unauthorized, """{"status":401,"mensagem":"Código de autenticação de dois fatores (two_fa) inválido"}""");

        var vitima = Auth(o => o.TwoFactorCode = () => "123456").GetTokenAsync();
        var atacante = Auth(o => o.TwoFactorCode = () => "000000").GetTokenAsync();

        Assert.Equal("tok-vitima", await vitima);
        await Assert.ThrowsAsync<IlevaAuthenticationException>(() => atacante);
        Assert.Equal(2, _http.Requests.Count);
    }

    [Fact]
    public async Task SemCodigoSimultaneoAoLoginCom2faNaoPegaCarona()
    {
        _http.DelayedToken("tok-vitima", 100).Json(HttpStatusCode.Unauthorized, """{"status":401,"mensagem":"Informe o código (two_fa)"}""");

        var vitima = Auth(o => o.TwoFactorCode = () => "123456").GetTokenAsync();
        var atacante = Auth().GetTokenAsync();

        Assert.Equal("tok-vitima", await vitima);
        await Assert.ThrowsAsync<IlevaAuthenticationException>(() => atacante);
    }

    [Fact]
    public async Task TokenCom2faFicaMarcadoNoCacheSem2faNao()
    {
        _http.Token("tok-1");
        await Auth(o => o.TwoFactorCode = () => "123456").GetTokenAsync();
        Assert.True((bool)JsonNode.Parse((await _store.GetAsync(Keys.TokenKey))!)!["two_factor"]!);

        InMemoryTokenStore.Clear();
        _http.Token("tok-2");
        await Auth().GetTokenAsync();
        Assert.False(JsonNode.Parse((await _store.GetAsync(Keys.TokenKey))!)!.AsObject().ContainsKey("two_factor"));
    }

    [Fact]
    public async Task RespeitaAMarcaDe2faGravadaPorOutroSdk()
    {
        await _store.SetAsync(
            Keys.TokenKey,
            $$"""{"access_token":"do-php-com-2fa","token_type":"Bearer","expires_at":{{Now() + 3600}},"password_check":"{{SegredoCheck}}","two_factor":true}""",
            3600);
        _http.Token("tok-novo");

        Assert.Equal("tok-novo", await Auth().GetTokenAsync());
    }

    [Fact]
    public async Task OCacheNaoGuardaASenha()
    {
        _http.Token("tok-1");
        await Auth().GetTokenAsync();

        var stored = (await _store.GetAsync(Keys.TokenKey))!;
        Assert.DoesNotContain("segredo", stored);
        Assert.Matches(@"^pbkdf2-sha256\$100000\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$", (string)JsonNode.Parse(stored)!["password_check"]!);
    }

    [Fact]
    public async Task FalhaNaGeracaoLiberaOLock()
    {
        _http.Json(HttpStatusCode.InternalServerError, "").Token("tok-1");
        var instance = Auth(o => o.LockWait = TimeSpan.FromMilliseconds(300));

        await Assert.ThrowsAsync<IlevaApiException>(() => instance.GetTokenAsync());

        // Se o lock tivesse ficado preso, esta chamada esperaria e daria IlevaLockTimeoutException.
        Assert.Equal("tok-1", await instance.GetTokenAsync());
    }

    [Fact]
    public async Task EsperaOTokenGeradoPorOutroProcessoQueSeguraOLock()
    {
        await _store.AcquireLockAsync(Keys.LockKey, "outro-processo", 10_000);
        var slowStore = new TokenAppearsAfterReadsStore(_store, 3, new Token("do-outro", "Bearer", Now() + 3600));

        Assert.Equal("do-outro", await Auth(o => o.Store = slowStore).GetTokenAsync());
        Assert.Empty(_http.Requests);
    }

    [Fact]
    public async Task LockPressoSemTokenEstouraOTempoDeEspera()
    {
        await _store.AcquireLockAsync(Keys.LockKey, "outro-processo", 10_000);

        await Assert.ThrowsAsync<IlevaLockTimeoutException>(() => Auth(o => o.LockWait = TimeSpan.FromMilliseconds(300)).GetTokenAsync());
    }

    [Fact]
    public void NaoExpoeSenhaNemAppKey()
    {
        var instance = Auth(o => { o.Password = "senha-secreta-123"; o.AppKey = "app-key-secreta"; });
        var options = new IlevaAuthOptions { AppKey = "app-key-secreta", Username = "integracao", Password = "senha-secreta-123" };

        foreach (var output in new[] { instance.ToString(), options.ToString() })
        {
            Assert.DoesNotContain("senha-secreta-123", output);
            Assert.DoesNotContain("app-key-secreta", output);
            Assert.Contains("integracao", output);
        }
    }

    [Fact]
    public async Task ErrosNaoExpoemSenhaNemAppKey()
    {
        _http.Fail(new HttpRequestException("falhou"));
        var instance = Auth(o => { o.Password = "senha-secreta-123"; o.AppKey = "app-key-secreta"; });

        var error = await Assert.ThrowsAsync<IlevaTransportException>(() => instance.GetTokenAsync());

        Assert.DoesNotContain("senha-secreta-123", error.ToString());
        Assert.DoesNotContain("app-key-secreta", error.ToString());
    }

    [Fact]
    public void RecusaRedisEStoreJuntos()
    {
        var database = DispatchProxy.Create<IDatabase, NullProxy>();

        Assert.Throws<ArgumentException>(() => Auth(o => { o.Redis = database; o.Store = _store; }));
    }

    [Fact]
    public void RecusaDoisCodigosDe2fa()
    {
        Assert.Throws<ArgumentException>(() => Auth(o => { o.TwoFactorCode = () => "1"; o.TwoFactorCodeAsync = _ => Task.FromResult("1"); }));
    }

    [Theory]
    [InlineData("", "usuario", "senha")]
    [InlineData("app", "", "senha")]
    [InlineData("app", "usuario", "")]
    public void RecusaCredenciaisVazias(string appKey, string username, string password)
    {
        Assert.Throws<ArgumentException>(() => Auth(o => { o.AppKey = appKey; o.Username = username; o.Password = password; }));
    }

    [Fact]
    public void RecusaValoresInvalidos()
    {
        Assert.Throws<ArgumentException>(() => Auth(o => o.RefreshMargin = TimeSpan.FromSeconds(-1)));
        Assert.Throws<ArgumentException>(() => Auth(o => o.Timeout = TimeSpan.Zero));
        Assert.Throws<ArgumentException>(() => Auth(o => o.LockWait = TimeSpan.Zero));
    }

    [Fact]
    public async Task RecusaCaracteresInvalidosNasCredenciaisSemVazarASenha()
    {
        var instance = Auth(o => o.Password = "senha-\ud800-secreta");

        var error = await Assert.ThrowsAsync<ArgumentException>(() => instance.GetTokenAsync());

        Assert.DoesNotContain("senha-", error.ToString());
    }

    public class NullProxy : DispatchProxy
    {
        protected override object? Invoke(MethodInfo? targetMethod, object?[]? args) => null;
    }
}
