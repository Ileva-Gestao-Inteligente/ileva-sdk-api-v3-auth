<?php

declare(strict_types=1);

namespace Ileva\SdkApiV3\Auth\Exception;

/**
 * A API respondeu com erro diferente de 401 (400, 429, 5xx) ou com um corpo fora do formato
 * esperado. O código da exceção é o status HTTP.
 */
final class ApiException extends IlevaSdkApiV3AuthException
{
}
