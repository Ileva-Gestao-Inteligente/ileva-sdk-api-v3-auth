import type { TokenStore } from './token-store.js';

/** Cliente do ioredis (`Redis` ou `Cluster`). */
export interface IoRedisLike {
  call(command: string, ...args: (string | number)[]): Promise<unknown>;
}

/** Cliente do node-redis (`createClient()` do pacote `redis`). */
export interface NodeRedisLike {
  sendCommand(args: string[]): Promise<unknown>;
}

export type RedisClient = IoRedisLike | NodeRedisLike;

// Comparar e apagar precisa ser atômico: entre um GET e um DEL feitos pelo cliente, o lock pode
// expirar e ser obtido por outro processo, e o DEL apagaria o lock alheio.
const RELEASE_LOCK_SCRIPT = `
if redis.call('GET', KEYS[1]) == ARGV[1] then
    return redis.call('DEL', KEYS[1])
end
return 0
`;

// ARGV[1] vazio apaga incondicionalmente. Valor que não é JSON válido também é apagado.
const DELETE_TOKEN_SCRIPT = `
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
`;

/**
 * Store em Redis, compartilhado entre processos, servidores e com o SDK de PHP.
 *
 * Recebe por injeção a conexão que a aplicação já usa: ioredis (`Redis` ou `Cluster`) ou node-redis
 * (`createClient()`), já conectada. Cada operação usa uma única chave, então funciona em cluster.
 */
export class RedisTokenStore implements TokenStore {
  private readonly command: (args: string[]) => Promise<unknown>;

  constructor(client: RedisClient) {
    // Comandos brutos em vez dos métodos de cada biblioteca: `set` e `eval` têm assinaturas
    // diferentes no ioredis e no node-redis, e o comando é o mesmo nos dois.
    if (typeof (client as IoRedisLike).call === 'function') {
      const ioredis = client as IoRedisLike;
      this.command = ([name, ...args]) => ioredis.call(name!, ...args);
    } else if (typeof (client as NodeRedisLike).sendCommand === 'function') {
      const nodeRedis = client as NodeRedisLike;
      this.command = (args) => nodeRedis.sendCommand(args);
    } else {
      throw new TypeError('Conexão Redis não suportada. Informe um cliente do ioredis ou do node-redis (pacote "redis").');
    }
  }

  async get(key: string): Promise<string | null> {
    const value = await this.command(['GET', key]);
    return typeof value === 'string' ? value : null;
  }

  async set(key: string, value: string, ttlSeconds: number): Promise<void> {
    await this.command(['SET', key, value, 'EX', String(Math.max(1, Math.floor(ttlSeconds)))]);
  }

  async delete(key: string, accessToken?: string): Promise<void> {
    await this.command(['EVAL', DELETE_TOKEN_SCRIPT, '1', key, accessToken ?? '']);
  }

  async acquireLock(key: string, owner: string, ttlMilliseconds: number): Promise<boolean> {
    const result = await this.command(['SET', key, owner, 'NX', 'PX', String(Math.max(1, Math.floor(ttlMilliseconds)))]);
    return result === 'OK';
  }

  async releaseLock(key: string, owner: string): Promise<void> {
    await this.command(['EVAL', RELEASE_LOCK_SCRIPT, '1', key, owner]);
  }
}
