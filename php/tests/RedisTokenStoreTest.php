<?php

declare(strict_types=1);

namespace Ileva\SdkApiV3\Auth\Tests;

use Ileva\SdkApiV3\Auth\Store\RedisTokenStore;
use Ileva\SdkApiV3\Auth\Token;
use PHPUnit\Framework\Attributes\RequiresPhpExtension;
use PHPUnit\Framework\TestCase;

/** Testes contra um Redis real (ILEVA_TEST_REDIS_HOST); são pulados sem conexão. */
#[RequiresPhpExtension('redis')]
final class RedisTokenStoreTest extends TestCase
{
    private \Redis $redis;
    private RedisTokenStore $store;
    private string $key;

    protected function setUp(): void
    {
        $this->redis = new \Redis();
        try {
            $this->redis->connect(
                getenv('ILEVA_TEST_REDIS_HOST') ?: '127.0.0.1',
                (int) (getenv('ILEVA_TEST_REDIS_PORT') ?: 6379),
                1.0,
            );
        } catch (\RedisException $e) {
            self::markTestSkipped('Redis indisponível: ' . $e->getMessage());
        }
        $this->store = new RedisTokenStore($this->redis);
        $this->key = 'ileva:auth:test:' . bin2hex(random_bytes(6));
    }

    protected function tearDown(): void
    {
        if (isset($this->key)) {
            $this->redis->del($this->key);
        }
    }

    public function testGravaComTtlELe(): void
    {
        $this->store->set($this->key, 'valor', 120);

        self::assertSame('valor', $this->store->get($this->key));
        $ttl = $this->redis->ttl($this->key);
        self::assertGreaterThan(110, $ttl);
        self::assertLessThanOrEqual(120, $ttl);
    }

    public function testChaveInexistenteDevolveNull(): void
    {
        self::assertNull($this->store->get($this->key));
    }

    public function testDeleteSoApagaQuandoOTokenConfere(): void
    {
        $this->store->set($this->key, (new Token('atual', 'Bearer', time() + 60))->toJson(), 60);

        $this->store->delete($this->key, 'outro');
        self::assertNotNull($this->store->get($this->key));

        $this->store->delete($this->key, 'atual');
        self::assertNull($this->store->get($this->key));
    }

    public function testDeleteSemTokenApagaSempre(): void
    {
        $this->store->set($this->key, (new Token('atual', 'Bearer', time() + 60))->toJson(), 60);

        $this->store->delete($this->key);

        self::assertNull($this->store->get($this->key));
    }

    public function testDeleteApagaValorCorrompido(): void
    {
        $this->store->set($this->key, 'nao-e-json', 60);

        $this->store->delete($this->key, 'qualquer');

        self::assertNull($this->store->get($this->key));
    }

    public function testLockEhExclusivoESoODonoLibera(): void
    {
        self::assertTrue($this->store->acquireLock($this->key, 'a', 5000));
        self::assertFalse($this->store->acquireLock($this->key, 'b', 5000));

        $this->store->releaseLock($this->key, 'b');
        self::assertFalse($this->store->acquireLock($this->key, 'b', 5000));

        $this->store->releaseLock($this->key, 'a');
        self::assertTrue($this->store->acquireLock($this->key, 'b', 5000));
    }

    public function testLockExpira(): void
    {
        self::assertTrue($this->store->acquireLock($this->key, 'a', 50));
        usleep(120_000);

        self::assertTrue($this->store->acquireLock($this->key, 'b', 5000));
    }

    public function testRecusaConexaoComSerializer(): void
    {
        $redis = new \Redis();
        $redis->connect(getenv('ILEVA_TEST_REDIS_HOST') ?: '127.0.0.1', (int) (getenv('ILEVA_TEST_REDIS_PORT') ?: 6379), 1.0);
        $redis->setOption(\Redis::OPT_SERIALIZER, \Redis::SERIALIZER_PHP);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('OPT_SERIALIZER');

        new RedisTokenStore($redis);
    }
}
