using Ileva.SdkApiV3.Auth.Stores;
using Microsoft.Extensions.DependencyInjection;
using StackExchange.Redis;
using Xunit;

namespace Ileva.SdkApiV3.Auth.Tests;

public sealed class ServiceCollectionExtensionsTests : IDisposable
{
    public ServiceCollectionExtensionsTests()
    {
        InMemoryTokenStore.Clear();
        IlevaSdkApiV3Auth.ClearVerifiedForTests();
    }

    public void Dispose()
    {
        InMemoryTokenStore.Clear();
        IlevaSdkApiV3Auth.ClearVerifiedForTests();
    }

    private static void Credentials(IlevaAuthOptions options)
    {
        options.AppKey = "app-key";
        options.Username = "integracao";
        options.Password = "segredo";
        options.BaseUrl = "https://api.teste";
    }

    [Fact]
    public async Task RegistraUmSingletonQueGeraToken()
    {
        var http = new FakeHttp().Token("tok-1");
        var services = new ServiceCollection();
        services.AddIlevaAuth(o => { Credentials(o); o.HttpClient = http.Client(); });
        using var provider = services.BuildServiceProvider();

        var auth = provider.GetRequiredService<IlevaSdkApiV3Auth>();

        Assert.Same(auth, provider.GetRequiredService<IlevaSdkApiV3Auth>());
        Assert.Equal("Bearer tok-1", await auth.GetAuthorizationHeaderAsync());
    }

    [Fact]
    public async Task UsaOTokenStoreRegistradoNaAplicacao()
    {
        var http = new FakeHttp().Token("tok-1");
        var store = new InMemoryTokenStore();
        var services = new ServiceCollection();
        services.AddSingleton<ITokenStore>(store);
        services.AddIlevaAuth(o => { Credentials(o); o.HttpClient = http.Client(); });
        using var provider = services.BuildServiceProvider();

        await provider.GetRequiredService<IlevaSdkApiV3Auth>().GetTokenAsync();

        Assert.NotNull(await store.GetAsync(Keys.TokenKey));
    }

    [RedisFact]
    public async Task UsaOConnectionMultiplexerRegistradoNaAplicacao()
    {
        var prefix = RedisEnv.NewPrefix();
        var http = new FakeHttp().Token("tok-1");
        var services = new ServiceCollection();
        services.AddSingleton<IConnectionMultiplexer>(RedisEnv.Connection!);
        services.AddIlevaAuth(o => { Credentials(o); o.HttpClient = http.Client(); o.KeyPrefix = prefix; });
        using var provider = services.BuildServiceProvider();

        await provider.GetRequiredService<IlevaSdkApiV3Auth>().GetTokenAsync();

        Assert.True(await RedisEnv.Database.KeyExistsAsync($"{prefix}:token:{Keys.Hash}"));
        Assert.Null(await new InMemoryTokenStore().GetAsync(Keys.TokenKey));
        await RedisEnv.Database.KeyDeleteAsync(new RedisKey[] { $"{prefix}:token:{Keys.Hash}", $"{prefix}:lock:{Keys.Hash}" });
    }

    [Fact]
    public async Task ConfigureRecebeOServiceProvider()
    {
        var http = new FakeHttp().Token("tok-1");
        var services = new ServiceCollection();
        services.AddSingleton(http.Client());
        services.AddIlevaAuth((provider, o) => { Credentials(o); o.HttpClient = provider.GetRequiredService<HttpClient>(); });
        using var provider = services.BuildServiceProvider();

        await provider.GetRequiredService<IlevaSdkApiV3Auth>().GetTokenAsync();

        Assert.Single(http.Requests);
    }

    [Fact]
    public void CredenciaisInvalidasFalhamAoResolver()
    {
        var services = new ServiceCollection();
        services.AddIlevaAuth(o => o.AppKey = "so-a-app-key");
        using var provider = services.BuildServiceProvider();

        Assert.Throws<ArgumentException>(() => provider.GetRequiredService<IlevaSdkApiV3Auth>());
    }
}
