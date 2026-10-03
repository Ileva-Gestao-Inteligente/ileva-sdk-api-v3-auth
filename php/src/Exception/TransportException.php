<?php

declare(strict_types=1);

namespace Ileva\SdkApiV3\Auth\Exception;

/** Não houve resposta da API: falha de rede, DNS, TLS ou timeout. */
final class TransportException extends IlevaSdkApiV3AuthException
{
}
