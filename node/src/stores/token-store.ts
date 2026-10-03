/**
 * Onde o token fica guardado entre chamadas e processos.
 *
 * Além do cache, o store oferece um lock: a API mantém um único token ativo por usuário e gerar
 * um novo invalida o anterior. Sem o lock, dois processos que encontram o cache vazio ao mesmo
 * tempo gerariam dois tokens, e o primeiro passaria a receber 401.
 */
export interface TokenStore {
  get(key: string): Promise<string | null>;

  set(key: string, value: string, ttlSeconds: number): Promise<void>;

  /**
   * Remove o token. Com `accessToken`, só remove se o token guardado for esse: assim um processo
   * que recebeu 401 com um token antigo não apaga o token novo que outro processo acabou de gerar.
   */
  delete(key: string, accessToken?: string): Promise<void>;

  /** Tenta obter o lock sem esperar. `owner` identifica quem pode liberá-lo. */
  acquireLock(key: string, owner: string, ttlMilliseconds: number): Promise<boolean>;

  /** Libera o lock apenas se ele ainda pertence a `owner` (pode ter expirado e sido obtido por outro). */
  releaseLock(key: string, owner: string): Promise<void>;
}
