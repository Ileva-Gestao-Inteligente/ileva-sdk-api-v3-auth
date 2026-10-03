import { Token } from '../token.js';
import type { TokenStore } from './token-store.js';

// Lista estática do módulo: compartilhada por todas as instâncias do processo.
const items = new Map<string, { value: string; expiresAt: number }>();

/**
 * Store usado quando nenhum Redis é informado: guarda os dados em memória, compartilhada por todas
 * as instâncias do processo.
 *
 * Só serve para um processo único. Com vários processos (cluster, PM2, várias réplicas, funções
 * serverless) cada um geraria o seu token, invalidando o dos outros — nesse caso use Redis.
 */
export class InMemoryTokenStore implements TokenStore {
  /** Apaga tudo o que está guardado no processo. */
  static clear(): void {
    items.clear();
  }

  async get(key: string): Promise<string | null> {
    return this.read(key);
  }

  async set(key: string, value: string, ttlSeconds: number): Promise<void> {
    items.set(key, { value, expiresAt: Date.now() + ttlSeconds * 1000 });
  }

  async delete(key: string, accessToken?: string): Promise<void> {
    const value = this.read(key);
    if (value === null) {
      return;
    }
    const token = Token.fromJsonString(value);
    if (accessToken === undefined || token === null || token.accessToken === accessToken) {
      items.delete(key);
    }
  }

  async acquireLock(key: string, owner: string, ttlMilliseconds: number): Promise<boolean> {
    if (this.read(key) !== null) {
      return false;
    }
    items.set(key, { value: owner, expiresAt: Date.now() + ttlMilliseconds });
    return true;
  }

  async releaseLock(key: string, owner: string): Promise<void> {
    if (this.read(key) === owner) {
      items.delete(key);
    }
  }

  // Síncrono de propósito: ler e gravar sem `await` no meio é o que torna o lock atômico dentro do
  // processo.
  private read(key: string): string | null {
    const item = items.get(key);
    if (item === undefined) {
      return null;
    }
    if (item.expiresAt <= Date.now()) {
      items.delete(key);
      return null;
    }
    return item.value;
  }
}
