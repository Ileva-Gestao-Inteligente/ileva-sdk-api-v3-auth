<?php

declare(strict_types=1);

namespace Ileva\SdkApiV3\Auth\Exception;

/**
 * Outro processo estava renovando o token e ele não apareceu no cache dentro do tempo de espera.
 * Costuma indicar que a API está lenta ou que o processo que renovava morreu no meio.
 */
final class LockTimeoutException extends IlevaSdkApiV3AuthException
{
}
