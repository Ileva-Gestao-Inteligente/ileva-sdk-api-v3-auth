using Ileva.SdkApiV3.Auth.Stores;
using StackExchange.Redis;
using Xunit;

namespace Ileva.SdkApiV3.Auth.Tests;

/// <summary>Testes contra um Redis real; são pulados sem conexão.</summary>
public sealed class RedisTokenStoreTests
{
    private static string NewKey() => $"ileva:auth:test:{Guid.NewGuid():N}";

    private static RedisTokenStore Store() => new(RedisEnv.Database);

    [RedisFact]
    public async Task GravaComTtlELe()
    {
        var key = NewKey();
        await Store().SetAsync(key, "valor", 120);

        Assert.Equal("valor", await Store().GetAsync(key));
        var ttl = (await RedisEnv.Database.KeyTimeToLiveAsync(key))!.Value.TotalSeconds;
        Assert.InRange(ttl, 110, 120);
        await RedisEnv.Database.KeyDeleteAsync(key);
    }

    [RedisFact]
    public async Task ChaveInexistenteDevolveNull()
    {
        Assert.Null(await Store().GetAsync(NewKey()));
    }

    [RedisFact]
    public async Task DeleteSoApagaQuandoOTokenConfere()
    {
        var key = NewKey();
        var store = Store();
        await store.SetAsync(key, new Token("atual", "Bearer", 9999999999).ToJson(), 60);

        await store.DeleteAsync(key, "outro");
        Assert.NotNull(await store.GetAsync(key));

        await store.DeleteAsync(key, "atual");
        Assert.Null(await store.GetAsync(key));
    }

    [RedisFact]
    public async Task DeleteSemTokenApagaSempre()
    {
        var key = NewKey();
        var store = Store();
        await store.SetAsync(key, new Token("atual", "Bearer", 9999999999).ToJson(), 60);

        await store.DeleteAsync(key);

        Assert.Null(await store.GetAsync(key));
    }

    [RedisFact]
    public async Task DeleteApagaValorQueNaoEJson()
    {
        var key = NewKey();
        var store = Store();
        await store.SetAsync(key, "lixo", 60);

        await store.DeleteAsync(key, "qualquer");

        Assert.Null(await store.GetAsync(key));
    }

    [RedisFact]
    public async Task DeleteDeChaveInexistenteNaoFalha()
    {
        await Store().DeleteAsync(NewKey(), "qualquer");
    }

    [RedisFact]
    public async Task LockSoPodeSerObtidoPorUmDono()
    {
        var key = NewKey();
        var store = Store();

        Assert.True(await store.AcquireLockAsync(key, "a", 5000));
        Assert.False(await store.AcquireLockAsync(key, "b", 5000));
        await RedisEnv.Database.KeyDeleteAsync(key);
    }

    [RedisFact]
    public async Task LockExpira()
    {
        var key = NewKey();
        var store = Store();
        await store.AcquireLockAsync(key, "a", 50);

        await Task.Delay(150);

        Assert.True(await store.AcquireLockAsync(key, "b", 5000));
        await RedisEnv.Database.KeyDeleteAsync(key);
    }

    [RedisFact]
    public async Task ReleaseLockSoLiberaParaODono()
    {
        var key = NewKey();
        var store = Store();
        await store.AcquireLockAsync(key, "a", 5000);

        await store.ReleaseLockAsync(key, "b");
        Assert.False(await store.AcquireLockAsync(key, "c", 5000));

        await store.ReleaseLockAsync(key, "a");
        Assert.True(await store.AcquireLockAsync(key, "c", 5000));
        await RedisEnv.Database.KeyDeleteAsync(key);
    }

    [RedisFact]
    public async Task OValorGravadoETextoPuroComoNosOutrosSdks()
    {
        var key = NewKey();
        var json = new Token("tok", "Bearer", 9999999999).ToJson("pbkdf2-sha256$1$AQ==$AQ==");

        await Store().SetAsync(key, json, 60);

        // GET devolve exatamente o JSON: um hash do Redis (como o do IDistributedCache) não serviria.
        Assert.Equal(RedisType.String, await RedisEnv.Database.KeyTypeAsync(key));
        Assert.Equal(json, (string?)await RedisEnv.Database.StringGetAsync(key));
        await RedisEnv.Database.KeyDeleteAsync(key);
    }

    [RedisFact]
    public async Task OSdkCompartilhaOTokenViaRedis()
    {
        var prefix = RedisEnv.NewPrefix();
        var http = new FakeHttp().Token("tok-1");

        IlevaSdkApiV3Auth New(FakeHttp fake) => new(new IlevaAuthOptions
        {
            AppKey = "app-key", Username = "integracao", Password = "segredo",
            Redis = RedisEnv.Database, HttpClient = fake.Client(), KeyPrefix = prefix, BaseUrl = "https://api.teste",
        });

        Assert.Equal("tok-1", await New(http).GetTokenAsync());

        // Outra "aplicação" no mesmo Redis, sem nenhuma resposta enfileirada: não pode chamar a API.
        var other = new FakeHttp();
        Assert.Equal("tok-1", await New(other).GetTokenAsync());
        Assert.Empty(other.Requests);

        await New(other).InvalidateAsync();
        await RedisEnv.Database.KeyDeleteAsync(new RedisKey[] { $"{prefix}:token:{Keys.Hash}", $"{prefix}:lock:{Keys.Hash}" });
    }
}
