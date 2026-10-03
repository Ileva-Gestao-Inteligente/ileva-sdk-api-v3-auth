import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { after, before, describe, it } from 'node:test';
import { Redis as IoRedis } from 'ioredis';
import { createClient } from 'redis';
import { RedisTokenStore, Token } from '../src/index.js';

/** Testes contra um Redis real (ILEVA_TEST_REDIS_HOST); são pulados sem conexão. */
const host = process.env.ILEVA_TEST_REDIS_HOST ?? '127.0.0.1';
const port = Number(process.env.ILEVA_TEST_REDIS_PORT ?? 6379);

async function redisAvailable(): Promise<boolean> {
  const probe = new IoRedis({ host, port, lazyConnect: true, connectTimeout: 1000, maxRetriesPerRequest: 0, retryStrategy: () => null });
  try {
    await probe.connect();
    await probe.ping();
    return true;
  } catch {
    return false;
  } finally {
    probe.disconnect();
  }
}

const available = await redisAvailable();
const skip = available ? false : `Redis indisponível em ${host}:${port}`;

const clients = {
  ioredis: async () => {
    const client = new IoRedis({ host, port });
    return { client, close: async () => void client.disconnect() };
  },
  'node-redis': async () => {
    const client = createClient({ socket: { host, port } });
    await client.connect();
    return { client, close: async () => void (await client.quit()) };
  },
};

for (const [name, connect] of Object.entries(clients)) {
  describe(`RedisTokenStore com ${name}`, { skip }, () => {
    let store: RedisTokenStore;
    let close: () => Promise<void>;
    let raw: IoRedis;
    const newKey = () => `ileva:auth:test:${randomBytes(6).toString('hex')}`;

    before(async () => {
      const connection = await connect();
      store = new RedisTokenStore(connection.client);
      close = connection.close;
      raw = new IoRedis({ host, port });
    });

    after(async () => {
      await close();
      raw.disconnect();
    });

    it('grava com TTL e lê', async () => {
      const key = newKey();
      await store.set(key, 'valor', 120);

      assert.equal(await store.get(key), 'valor');
      const ttl = await raw.ttl(key);
      assert.ok(ttl > 110 && ttl <= 120);
      await raw.del(key);
    });

    it('chave inexistente devolve null', async () => {
      assert.equal(await store.get(newKey()), null);
    });

    it('delete só apaga quando o token confere', async () => {
      const key = newKey();
      await store.set(key, new Token('atual', 'Bearer', 9999999999).toJsonString(), 60);

      await store.delete(key, 'outro');
      assert.notEqual(await store.get(key), null);

      await store.delete(key, 'atual');
      assert.equal(await store.get(key), null);
    });

    it('delete sem token apaga sempre', async () => {
      const key = newKey();
      await store.set(key, new Token('atual', 'Bearer', 9999999999).toJsonString(), 60);

      await store.delete(key);

      assert.equal(await store.get(key), null);
    });

    it('delete apaga valor corrompido', async () => {
      const key = newKey();
      await store.set(key, 'nao-e-json', 60);

      await store.delete(key, 'qualquer');

      assert.equal(await store.get(key), null);
    });

    it('lock é exclusivo e só o dono libera', async () => {
      const key = newKey();
      assert.equal(await store.acquireLock(key, 'a', 5000), true);
      assert.equal(await store.acquireLock(key, 'b', 5000), false);

      await store.releaseLock(key, 'b');
      assert.equal(await store.acquireLock(key, 'b', 5000), false);

      await store.releaseLock(key, 'a');
      assert.equal(await store.acquireLock(key, 'b', 5000), true);
      await raw.del(key);
    });

    it('lock expira', async () => {
      const key = newKey();
      assert.equal(await store.acquireLock(key, 'a', 50), true);
      await new Promise((resolve) => setTimeout(resolve, 120));

      assert.equal(await store.acquireLock(key, 'b', 5000), true);
      await raw.del(key);
    });
  });
}
