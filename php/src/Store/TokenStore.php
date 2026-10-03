<?php

declare(strict_types=1);

namespace Ileva\SdkApiV3\Auth\Store;

/**
 * Onde o token fica guardado entre requisições e processos.
 *
 * Além do cache, o store oferece um lock: a API mantém um único token ativo por usuário e gerar
 * um novo invalida o anterior. Sem o lock, dois processos que encontram o cache vazio ao mesmo
 * tempo gerariam dois tokens, e o primeiro passaria a receber 401.
 */
interface TokenStore
{
    public function get(string $key): ?string;

    public function set(string $key, string $value, int $ttlSeconds): void;

    /**
     * Remove o token. Com `$accessToken`, só remove se o token guardado for esse: assim um processo
     * que recebeu 401 com um token antigo não apaga o token novo que outro processo acabou de gerar.
     */
    public function delete(string $key, ?string $accessToken = null): void;

    /** Tenta obter o lock sem esperar. `$owner` identifica quem pode liberá-lo. */
    public function acquireLock(string $key, string $owner, int $ttlMilliseconds): bool;

    /** Libera o lock apenas se ele ainda pertence a `$owner` (pode ter expirado e sido obtido por outro). */
    public function releaseLock(string $key, string $owner): void;
}
