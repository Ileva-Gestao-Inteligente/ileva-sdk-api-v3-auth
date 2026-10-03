namespace Ileva.SdkApiV3.Auth;

/// <summary>Base de todos os erros do SDK: capture esta para tratar qualquer falha de autenticação.</summary>
public class IlevaSdkApiV3AuthException : Exception
{
    public IlevaSdkApiV3AuthException(string message, Exception? innerException = null)
        : base(message, innerException)
    {
    }
}

/// <summary>
/// A API recusou as credenciais (HTTP 401): app key inválida, expirada ou desativada, usuário ou
/// senha errados, usuário sem acesso via API liberado no perfil, troca de senha pendente ou código
/// 2FA ausente/inválido. A mensagem é a devolvida pela API. Tentar de novo sem mudar a configuração
/// não resolve.
/// </summary>
public sealed class IlevaAuthenticationException : IlevaSdkApiV3AuthException
{
    public IlevaAuthenticationException(string message)
        : base(message)
    {
    }

    public int Status => 401;
}

/// <summary>A API respondeu com erro diferente de 401 (400, 429, 5xx) ou com um corpo fora do formato esperado.</summary>
public sealed class IlevaApiException : IlevaSdkApiV3AuthException
{
    public IlevaApiException(string message, int status)
        : base(message)
    {
        Status = status;
    }

    public int Status { get; }
}

/// <summary>Não houve resposta da API: falha de rede, DNS, TLS ou timeout. O erro original fica em <see cref="Exception.InnerException"/>.</summary>
public sealed class IlevaTransportException : IlevaSdkApiV3AuthException
{
    public IlevaTransportException(string message, Exception? innerException = null)
        : base(message, innerException)
    {
    }
}

/// <summary>
/// Outro processo estava renovando o token e ele não apareceu no cache dentro do tempo de espera.
/// Costuma indicar que a API está lenta ou que o processo que renovava morreu no meio.
/// </summary>
public sealed class IlevaLockTimeoutException : IlevaSdkApiV3AuthException
{
    public IlevaLockTimeoutException(string message)
        : base(message)
    {
    }
}
