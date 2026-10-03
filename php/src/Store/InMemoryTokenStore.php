<?php

declare(strict_types=1);

namespace Ileva\SdkApiV3\Auth\Store;

use Ileva\SdkApiV3\Auth\Token;

/**
 * Store usado quando nenhum Redis é informado: guarda os dados em memória estática, compartilhada
 * por todo o processo — o token sobrevive a uma nova configuração do SDK.
 *
 * Só serve para um processo único e de vida longa (worker, CLI). No PHP-FPM a memória estática
 * não passa de uma requisição para a outra: cada requisição geraria um token novo, invalidando o
 * das outras — nesse caso use Redis.
 */
final class InMemoryTokenStore implements TokenStore
{
    /** @var array<string, array{value: string, expiresAt: float}> */
    private static array $items = [];

    /** Apaga tudo o que está guardado no processo. */
    public static function clear(): void
    {
        self::$items = [];
    }

    public function get(string $key): ?string
    {
        $item = self::$items[$key] ?? null;
        if ($item === null) {
            return null;
        }
        if ($item['expiresAt'] <= microtime(true)) {
            unset(self::$items[$key]);
            return null;
        }
        return $item['value'];
    }

    public function set(string $key, string $value, int $ttlSeconds): void
    {
        self::$items[$key] = ['value' => $value, 'expiresAt' => microtime(true) + $ttlSeconds];
    }

    public function delete(string $key, ?string $accessToken = null): void
    {
        $value = $this->get($key);
        if ($value === null) {
            return;
        }
        $token = Token::fromJson($value);
        if ($accessToken === null || $token === null || $token->accessToken === $accessToken) {
            unset(self::$items[$key]);
        }
    }

    public function acquireLock(string $key, string $owner, int $ttlMilliseconds): bool
    {
        if ($this->get($key) !== null) {
            return false;
        }
        self::$items[$key] = ['value' => $owner, 'expiresAt' => microtime(true) + $ttlMilliseconds / 1000];
        return true;
    }

    public function releaseLock(string $key, string $owner): void
    {
        if ($this->get($key) === $owner) {
            unset(self::$items[$key]);
        }
    }
}
