<?php

declare(strict_types=1);

namespace Ileva\SdkApiV3\Auth\Exception;

/**
 * A API recusou as credenciais (HTTP 401): app key inválida, expirada ou desativada, usuário ou
 * senha errados, usuário sem acesso via API liberado no perfil, troca de senha pendente ou código 2FA ausente/inválido.
 * A mensagem é a devolvida pela API. Tentar de novo sem mudar a configuração não resolve.
 */
final class AuthenticationException extends IlevaSdkApiV3AuthException
{
}
