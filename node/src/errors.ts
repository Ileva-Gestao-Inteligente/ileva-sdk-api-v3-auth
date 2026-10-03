/** Base de todos os erros do SDK: capture este para tratar qualquer falha de autenticação. */
export class IlevaSdkApiV3AuthError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = new.target.name;
  }
}

/**
 * A API recusou as credenciais (HTTP 401): app key inválida, expirada ou desativada, usuário ou
 * senha errados, usuário sem acesso via API liberado no perfil, troca de senha pendente ou código 2FA ausente/inválido.
 * A mensagem é a devolvida pela API. Tentar de novo sem mudar a configuração não resolve.
 */
export class AuthenticationError extends IlevaSdkApiV3AuthError {
  readonly status = 401;
}

/** A API respondeu com erro diferente de 401 (400, 429, 5xx) ou com um corpo fora do formato esperado. */
export class ApiError extends IlevaSdkApiV3AuthError {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
  }
}

/** Não houve resposta da API: falha de rede, DNS, TLS ou timeout. O erro original fica em `cause`. */
export class TransportError extends IlevaSdkApiV3AuthError {}

/**
 * Outro processo estava renovando o token e ele não apareceu no cache dentro do tempo de espera.
 * Costuma indicar que a API está lenta ou que o processo que renovava morreu no meio.
 */
export class LockTimeoutError extends IlevaSdkApiV3AuthError {}
