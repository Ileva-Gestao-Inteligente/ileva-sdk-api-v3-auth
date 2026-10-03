namespace Ileva.SdkApiV3.Auth.Stores;

/// <summary>
/// Onde o token fica guardado entre requisições e processos.
///
/// Além do cache, o store oferece um lock: a API mantém um único token ativo por usuário e gerar um
/// novo invalida o anterior. Sem o lock, dois processos que encontram o cache vazio ao mesmo tempo
/// gerariam dois tokens, e o primeiro passaria a receber 401.
/// </summary>
public interface ITokenStore
{
    Task<string?> GetAsync(string key, CancellationToken cancellationToken = default);

    Task SetAsync(string key, string value, long ttlSeconds, CancellationToken cancellationToken = default);

    /// <summary>
    /// Remove o token. Com <paramref name="accessToken"/>, só remove se o token guardado for esse:
    /// assim um processo que recebeu 401 com um token antigo não apaga o token novo que outro processo
    /// acabou de gerar.
    /// </summary>
    Task DeleteAsync(string key, string? accessToken = null, CancellationToken cancellationToken = default);

    /// <summary>Tenta obter o lock sem esperar. <paramref name="owner"/> identifica quem pode liberá-lo.</summary>
    Task<bool> AcquireLockAsync(string key, string owner, long ttlMilliseconds, CancellationToken cancellationToken = default);

    /// <summary>Libera o lock apenas se ele ainda pertence a <paramref name="owner"/> (pode ter expirado e sido obtido por outro).</summary>
    Task ReleaseLockAsync(string key, string owner, CancellationToken cancellationToken = default);
}
