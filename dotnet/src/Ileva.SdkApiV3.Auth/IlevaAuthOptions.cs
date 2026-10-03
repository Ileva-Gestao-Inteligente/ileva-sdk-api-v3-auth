using Ileva.SdkApiV3.Auth.Stores;
using StackExchange.Redis;

namespace Ileva.SdkApiV3.Auth;

/// <summary>Configuração do <see cref="IlevaSdkApiV3Auth"/>.</summary>
public sealed class IlevaAuthOptions
{
    /// <summary>Valor de Configurações &gt; Integrações &gt; API Integração no sistema Ileva.</summary>
    public string AppKey { get; set; } = string.Empty;

    /// <summary>Usuário ou e-mail usado para entrar no sistema Ileva; o perfil precisa estar liberado para acesso via API.</summary>
    public string Username { get; set; } = string.Empty;

    public string Password { get; set; } = string.Empty;

    /// <summary>
    /// Banco Redis da aplicação (StackExchange.Redis), já conectado. Sem Redis o token fica em
    /// memória, só neste processo.
    /// </summary>
    public IDatabase? Redis { get; set; }

    /// <summary>Store próprio, no lugar de <see cref="Redis"/>.</summary>
    public ITokenStore? Store { get; set; }

    /// <summary>
    /// Cliente HTTP da aplicação (proxy, handlers, testes). Sem ele, o SDK usa um cliente próprio e
    /// compartilhado. O SDK não altera nem descarta o cliente informado.
    /// </summary>
    public HttpClient? HttpClient { get; set; }

    /// <summary>URL da API. Padrão: https://api.ileva.com.br</summary>
    public string BaseUrl { get; set; } = IlevaSdkApiV3Auth.DefaultBaseUrl;

    /// <summary>Chamado a cada geração de token, para usuários com autenticação em dois fatores.</summary>
    public Func<string>? TwoFactorCode { get; set; }

    /// <summary>Versão assíncrona de <see cref="TwoFactorCode"/>. Informe uma das duas, não as duas.</summary>
    public Func<CancellationToken, Task<string>>? TwoFactorCodeAsync { get; set; }

    /// <summary>Quanto antes da expiração o token passa a ser renovado. Padrão: 300 segundos.</summary>
    public TimeSpan RefreshMargin { get; set; } = TimeSpan.FromSeconds(300);

    /// <summary>Timeout da requisição de token. Padrão: 15 segundos.</summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(15);

    /// <summary>Quanto esperar por outro processo que esteja renovando. Padrão: 20 segundos.</summary>
    public TimeSpan LockWait { get; set; } = TimeSpan.FromSeconds(20);

    /// <summary>Prefixo das chaves no Redis. Padrão: "ileva:auth".</summary>
    public string KeyPrefix { get; set; } = "ileva:auth";

    /// <summary>Não expõe a senha nem a app key em logs e no depurador.</summary>
    public override string ToString() => $"IlevaAuthOptions {{ Username = {Username}, BaseUrl = {BaseUrl} }}";
}
