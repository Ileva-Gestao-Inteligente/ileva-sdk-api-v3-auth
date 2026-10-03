using System.Net;
using Ileva.SdkApiV3.Auth.Stores;
using Xunit;

namespace Ileva.SdkApiV3.Auth.Tests;

/// <summary>
/// Testes contra a API de verdade: gera o token e chama /outros/estados-listar, que só exige estar
/// autenticado. Rodam com ILEVA_APP_KEY, ILEVA_USUARIO, ILEVA_SENHA (e ILEVA_BASE_URL) definidos.
/// Gerar um token invalida o anterior do mesmo usuário: use um usuário de teste.
/// </summary>
public sealed class LiveApiTests : IDisposable
{
    private static readonly HttpClient Http = new();

    public LiveApiTests()
    {
        InMemoryTokenStore.Clear();
        IlevaSdkApiV3Auth.ClearVerifiedForTests();
    }

    public void Dispose()
    {
        InMemoryTokenStore.Clear();
        IlevaSdkApiV3Auth.ClearVerifiedForTests();
    }

    private static IlevaSdkApiV3Auth Auth(Action<IlevaAuthOptions>? configure = null)
    {
        var options = new IlevaAuthOptions
        {
            AppKey = LiveApi.AppKey!,
            Username = LiveApi.Username!,
            Password = LiveApi.Password!,
            BaseUrl = LiveApi.BaseUrl,
        };
        configure?.Invoke(options);
        return new IlevaSdkApiV3Auth(options);
    }

    private static async Task<HttpStatusCode> ListStatesAsync(string authorization)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, $"{LiveApi.BaseUrl.TrimEnd('/')}/outros/estados-listar");
        request.Headers.TryAddWithoutValidation("Authorization", authorization);
        using var response = await Http.SendAsync(request);
        return response.StatusCode;
    }

    [LiveApiFact]
    public async Task OTokenGeradoAutenticaNaApi()
    {
        var auth = Auth();

        var token = await auth.GetTokenDetailsAsync();

        Assert.Equal(HttpStatusCode.OK, await ListStatesAsync(token.AuthorizationHeader()));
        Assert.True(token.ExpiresAt > DateTimeOffset.UtcNow.ToUnixTimeSeconds());
    }

    [LiveApiFact]
    public async Task OSegundoUsoVemDoCache()
    {
        var first = await Auth().GetTokenAsync();

        Assert.Equal(first, await Auth().GetTokenAsync());
    }

    [LiveApiFact]
    public async Task RefreshGeraOutroTokenEOAnteriorDeixaDeValer()
    {
        var auth = Auth();
        var first = await auth.GetTokenAsync();

        var second = await auth.RefreshAsync();

        Assert.NotEqual(first, second);
        Assert.Equal(HttpStatusCode.OK, await ListStatesAsync("Bearer " + second));
        // A API mantém um único token ativo por usuário.
        Assert.Equal(HttpStatusCode.Unauthorized, await ListStatesAsync("Bearer " + first));
    }

    [LiveApiFact]
    public async Task SenhaErradaERecusadaESemAfetarOTokenDeQuemAcertou()
    {
        var auth = Auth();
        var token = await auth.GetTokenAsync();

        await Assert.ThrowsAsync<IlevaAuthenticationException>(() => Auth(o => o.Password = LiveApi.Password + "x").GetTokenAsync());

        Assert.Equal(token, await auth.GetTokenAsync());
        Assert.Equal(HttpStatusCode.OK, await ListStatesAsync("Bearer " + token));
    }

    [RedisFact]
    public async Task ComRedisOTokenFicaNoFormatoDoContrato()
    {
        if (LiveApi.AppKey is null)
        {
            return;
        }
        var prefix = RedisEnv.NewPrefix();
        var auth = Auth(o => { o.Redis = RedisEnv.Database; o.KeyPrefix = prefix; });

        var token = await auth.GetTokenAsync();

        var keys = RedisEnv.Connection!.GetServer(RedisEnv.Host, RedisEnv.Port).Keys(pattern: $"{prefix}:*").ToArray();
        var stored = (string?)await RedisEnv.Database.StringGetAsync(Assert.Single(keys));
        Assert.Equal(token, Token.FromJson(stored!)!.AccessToken);
        Assert.NotNull(Token.PasswordCheckFromJson(stored!));
        await RedisEnv.Database.KeyDeleteAsync(keys);
    }
}
