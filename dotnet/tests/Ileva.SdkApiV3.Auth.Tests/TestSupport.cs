using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Ileva.SdkApiV3.Auth.Stores;
using StackExchange.Redis;
using Xunit;

// Os stores em memória e a memorização das conferências de senha são estáticos (de propósito, como
// no SDK): testes em paralelo se atrapalhariam.
[assembly: CollectionBehavior(DisableTestParallelization = true)]

namespace Ileva.SdkApiV3.Auth.Tests;

public sealed record RecordedRequest(string Url, HttpRequestMessage Message, JsonObject Body)
{
    public string? Header(string name) => Message.Headers.TryGetValues(name, out var values) ? values.Single() : null;
}

/// <summary>Transporte falso: devolve as respostas enfileiradas, na ordem, e registra as requisições.</summary>
public sealed class FakeHttp : HttpMessageHandler
{
    private readonly Queue<Func<CancellationToken, Task<HttpResponseMessage>>> _responses = new();
    private readonly object _gate = new();

    public List<RecordedRequest> Requests { get; } = new();

    public HttpClient Client() => new(this);

    public FakeHttp Token(string accessToken, int expiresIn = 86400) =>
        Json(HttpStatusCode.OK, $$"""{"access_token":"{{accessToken}}","token_type":"Bearer","expires_in":{{expiresIn}}}""");

    public FakeHttp Json(HttpStatusCode status, string body)
    {
        _responses.Enqueue(_ => Task.FromResult(new HttpResponseMessage(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") }));
        return this;
    }

    public FakeHttp DelayedToken(string accessToken, int delayMs)
    {
        _responses.Enqueue(async ct =>
        {
            await Task.Delay(delayMs, ct);
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent($$"""{"access_token":"{{accessToken}}","token_type":"Bearer","expires_in":86400}""", Encoding.UTF8, "application/json"),
            };
        });
        return this;
    }

    public FakeHttp Fail(Exception error)
    {
        _responses.Enqueue(_ => throw error);
        return this;
    }

    public FakeHttp Hang()
    {
        _responses.Enqueue(async ct =>
        {
            await Task.Delay(Timeout.Infinite, ct);
            return new HttpResponseMessage();
        });
        return this;
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var body = JsonNode.Parse(await request.Content!.ReadAsStringAsync(cancellationToken))!.AsObject();
        Func<CancellationToken, Task<HttpResponseMessage>>? next;
        lock (_gate)
        {
            Requests.Add(new RecordedRequest(request.RequestUri!.ToString(), request, body));
            _responses.TryDequeue(out next);
        }
        if (next is null)
        {
            throw new InvalidOperationException("Requisição de token inesperada.");
        }
        return await next(cancellationToken);
    }
}

public static class Keys
{
    public static string Sha256Hex(string value) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();

    /// <summary>Chave do token para app key "app-key", usuário "integracao" e URL "https://api.teste".</summary>
    public static readonly string Hash = Sha256Hex("https://api.teste\napp-key\nintegracao");

    /// <summary>
    /// Verificador da senha "segredo" gerado com salt fixo (16 bytes 0x01). Os SDKs de PHP, Node e
    /// Python testam o mesmo valor: todos precisam aceitar o verificador gravado pelos outros.
    /// </summary>
    public const string SegredoCheck = "pbkdf2-sha256$100000$AQEBAQEBAQEBAQEBAQEBAQ==$MC4obyTDiJ9/piZiz+KFtXeenFNNoJQjr5MSPiDBgxM=";

    public static readonly string TokenKey = $"ileva:auth:token:{Hash}";

    public static readonly string LockKey = $"ileva:auth:lock:{Hash}";
}

/// <summary>Teste que usa um Redis real (ILEVA_TEST_REDIS_HOST/PORT); é pulado sem conexão.</summary>
public sealed class RedisFactAttribute : FactAttribute
{
    public RedisFactAttribute()
    {
        if (RedisEnv.Connection is null)
        {
            Skip = $"Redis indisponível em {RedisEnv.Host}:{RedisEnv.Port}";
        }
    }
}

public static class RedisEnv
{
    public static readonly string Host = Environment.GetEnvironmentVariable("ILEVA_TEST_REDIS_HOST") ?? "127.0.0.1";

    public static readonly int Port = int.TryParse(Environment.GetEnvironmentVariable("ILEVA_TEST_REDIS_PORT"), out var port) ? port : 6379;

    private static readonly Lazy<ConnectionMultiplexer?> Lazy = new(() =>
    {
        try
        {
            return ConnectionMultiplexer.Connect(new ConfigurationOptions
            {
                EndPoints = { { Host, Port } },
                ConnectTimeout = 1000,
                AbortOnConnectFail = true,
            });
        }
        catch (RedisConnectionException)
        {
            return null;
        }
    });

    public static ConnectionMultiplexer? Connection => Lazy.Value;

    public static IDatabase Database => Connection!.GetDatabase();

    public static string NewPrefix() => $"ileva:auth:test:{Guid.NewGuid():N}";
}

/// <summary>Teste contra a API real; só roda com ILEVA_APP_KEY, ILEVA_USUARIO e ILEVA_SENHA definidos.</summary>
public sealed class LiveApiFactAttribute : FactAttribute
{
    public LiveApiFactAttribute()
    {
        if (LiveApi.AppKey is null || LiveApi.Username is null || LiveApi.Password is null)
        {
            Skip = "Defina ILEVA_APP_KEY, ILEVA_USUARIO e ILEVA_SENHA para testar contra a API.";
        }
    }
}

public static class LiveApi
{
    public static readonly string? AppKey = Environment.GetEnvironmentVariable("ILEVA_APP_KEY");
    public static readonly string? Username = Environment.GetEnvironmentVariable("ILEVA_USUARIO");
    public static readonly string? Password = Environment.GetEnvironmentVariable("ILEVA_SENHA");
    public static readonly string BaseUrl = Environment.GetEnvironmentVariable("ILEVA_BASE_URL") ?? IlevaSdkApiV3Auth.DefaultBaseUrl;
}

/// <summary>Simula outro processo que grava o token no cache depois de algumas leituras.</summary>
public sealed class TokenAppearsAfterReadsStore : ITokenStore
{
    private readonly ITokenStore _inner;
    private readonly int _afterReads;
    private readonly Token _token;
    private int _reads;

    public TokenAppearsAfterReadsStore(ITokenStore inner, int afterReads, Token token)
    {
        _inner = inner;
        _afterReads = afterReads;
        _token = token;
    }

    public async Task<string?> GetAsync(string key, CancellationToken cancellationToken = default)
    {
        if (key.Contains(":token:") && ++_reads > _afterReads)
        {
            return _token.ToJson(Keys.SegredoCheck);
        }
        return await _inner.GetAsync(key, cancellationToken);
    }

    public Task SetAsync(string key, string value, long ttlSeconds, CancellationToken cancellationToken = default) => _inner.SetAsync(key, value, ttlSeconds, cancellationToken);

    public Task DeleteAsync(string key, string? accessToken = null, CancellationToken cancellationToken = default) => _inner.DeleteAsync(key, accessToken, cancellationToken);

    public Task<bool> AcquireLockAsync(string key, string owner, long ttlMilliseconds, CancellationToken cancellationToken = default) => _inner.AcquireLockAsync(key, owner, ttlMilliseconds, cancellationToken);

    public Task ReleaseLockAsync(string key, string owner, CancellationToken cancellationToken = default) => _inner.ReleaseLockAsync(key, owner, cancellationToken);
}
