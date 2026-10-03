<?php

declare(strict_types=1);

namespace Ileva\SdkApiV3\Auth\Store;

use InvalidArgumentException;

/**
 * Store em Redis, compartilhado entre processos e servidores.
 *
 * Recebe por injeção a conexão que a aplicação já usa: phpredis (\Redis ou \RedisCluster) ou
 * Predis (\Predis\ClientInterface). Cada operação usa uma única chave, então funciona em cluster.
 */
final class RedisTokenStore implements TokenStore
{
    // Comparar e apagar precisa ser atômico: entre um GET e um DEL feitos pelo cliente, o lock
    // pode expirar e ser obtido por outro processo, e o DEL apagaria o lock alheio.
    private const RELEASE_LOCK_SCRIPT = <<<'LUA'
        if redis.call('GET', KEYS[1]) == ARGV[1] then
            return redis.call('DEL', KEYS[1])
        end
        return 0
        LUA;

    // ARGV[1] vazio apaga incondicionalmente. Valor que não é JSON válido também é apagado.
    private const DELETE_TOKEN_SCRIPT = <<<'LUA'
        local value = redis.call('GET', KEYS[1])
        if not value then
            return 0
        end
        if ARGV[1] == '' then
            return redis.call('DEL', KEYS[1])
        end
        local ok, token = pcall(cjson.decode, value)
        if not ok or type(token) ~= 'table' or token.access_token == ARGV[1] then
            return redis.call('DEL', KEYS[1])
        end
        return 0
        LUA;

    private readonly bool $isPhpRedis;

    public function __construct(private readonly object $redis)
    {
        $this->isPhpRedis = $redis instanceof \Redis || $redis instanceof \RedisCluster;

        if (!$this->isPhpRedis && !$redis instanceof \Predis\ClientInterface) {
            throw new InvalidArgumentException(sprintf(
                'Conexão Redis não suportada (%s). Informe uma instância de \Redis, \RedisCluster ou \Predis\ClientInterface.',
                $redis::class,
            ));
        }

        if ($this->isPhpRedis) {
            $this->assertNoPhpRedisTransformation();
        }
    }

    public function get(string $key): ?string
    {
        $value = $this->redis->get($key);
        // phpredis devolve false para chave inexistente; Predis devolve null.
        return is_string($value) ? $value : null;
    }

    public function set(string $key, string $value, int $ttlSeconds): void
    {
        $ttlSeconds = max(1, $ttlSeconds);
        if ($this->isPhpRedis) {
            $this->redis->set($key, $value, ['EX' => $ttlSeconds]);
        } else {
            $this->redis->set($key, $value, 'EX', $ttlSeconds);
        }
    }

    public function delete(string $key, ?string $accessToken = null): void
    {
        $this->eval(self::DELETE_TOKEN_SCRIPT, $key, $accessToken ?? '');
    }

    public function acquireLock(string $key, string $owner, int $ttlMilliseconds): bool
    {
        $ttlMilliseconds = max(1, $ttlMilliseconds);
        if ($this->isPhpRedis) {
            return $this->redis->set($key, $owner, ['NX', 'PX' => $ttlMilliseconds]) === true;
        }
        // Predis devolve um Status "OK" quando grava e null quando a chave já existe.
        return $this->redis->set($key, $owner, 'PX', $ttlMilliseconds, 'NX') !== null;
    }

    public function releaseLock(string $key, string $owner): void
    {
        $this->eval(self::RELEASE_LOCK_SCRIPT, $key, $owner);
    }

    private function eval(string $script, string $key, string $argument): mixed
    {
        if ($this->isPhpRedis) {
            return $this->redis->eval($script, [$key, $argument], 1);
        }
        return $this->redis->eval($script, 1, $key, $argument);
    }

    /**
     * Com serializer ou compressão ligados no phpredis, o valor gravado deixa de ser o texto puro:
     * os scripts Lua passam a comparar valores diferentes (o lock nunca seria liberado) e os SDKs
     * de outras linguagens não conseguiriam ler o token.
     */
    private function assertNoPhpRedisTransformation(): void
    {
        if ($this->redis->getOption(\Redis::OPT_SERIALIZER) !== \Redis::SERIALIZER_NONE) {
            throw new InvalidArgumentException(
                'A conexão phpredis está com OPT_SERIALIZER ativo. Use uma conexão sem serializer para o RedisTokenStore.'
            );
        }
        if (defined('Redis::OPT_COMPRESSION') && $this->redis->getOption(\Redis::OPT_COMPRESSION) !== \Redis::COMPRESSION_NONE) {
            throw new InvalidArgumentException(
                'A conexão phpredis está com OPT_COMPRESSION ativo. Use uma conexão sem compressão para o RedisTokenStore.'
            );
        }
    }
}
