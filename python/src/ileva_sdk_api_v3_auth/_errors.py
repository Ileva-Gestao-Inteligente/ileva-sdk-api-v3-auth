from __future__ import annotations


class IlevaSdkApiV3AuthError(Exception):
    """Base de todos os erros do SDK: capture esta para tratar qualquer falha de autenticação."""


class AuthenticationError(IlevaSdkApiV3AuthError):
    """A API recusou as credenciais (HTTP 401).

    App key inválida, expirada ou desativada, usuário ou senha errados, usuário sem acesso via API
    liberado no perfil, troca de senha pendente ou código 2FA ausente/inválido. A mensagem é a
    devolvida pela API. Tentar de novo sem mudar a configuração não resolve.
    """

    status = 401


class ApiError(IlevaSdkApiV3AuthError):
    """A API respondeu com erro diferente de 401 (400, 429, 5xx) ou com um corpo fora do formato."""

    def __init__(self, message: str, status: int) -> None:
        super().__init__(message)
        self.status = status


class TransportError(IlevaSdkApiV3AuthError):
    """Não houve resposta da API: falha de rede, DNS, TLS ou timeout.

    O erro original do cliente HTTP não é encadeado (``__cause__``/``__context__``): o de requests e
    httpx carrega a requisição, com o body e a senha. A mensagem traz o tipo e a descrição dele.
    """


class LockTimeoutError(IlevaSdkApiV3AuthError):
    """Outro processo estava renovando o token e ele não apareceu no cache a tempo.

    Costuma indicar que a API está lenta ou que o processo que renovava morreu no meio.
    """
