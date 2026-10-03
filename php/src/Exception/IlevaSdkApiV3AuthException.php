<?php

declare(strict_types=1);

namespace Ileva\SdkApiV3\Auth\Exception;

use RuntimeException;

/** Base de todas as exceções do SDK: capture esta para tratar qualquer falha de autenticação. */
class IlevaSdkApiV3AuthException extends RuntimeException
{
}
