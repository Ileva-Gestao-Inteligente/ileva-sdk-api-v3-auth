import { createHash, createHmac, pbkdf2 as pbkdf2Callback, randomBytes, timingSafeEqual } from 'node:crypto';
import { setTimeout as sleep } from 'node:timers/promises';
import { promisify } from 'node:util';
import { ApiError, AuthenticationError, LockTimeoutError, TransportError } from './errors.js';
import { type AxiosLike, axiosPost, fetchPost, type HttpPost } from './http.js';
import { InMemoryTokenStore } from './stores/in-memory-token-store.js';
import { RedisTokenStore, type RedisClient } from './stores/redis-token-store.js';
import type { TokenStore } from './stores/token-store.js';
import { Token } from './token.js';

export interface IlevaSdkApiV3AuthOptions {
  /** Valor de Configurações > Integrações > API Integração no sistema Ileva. */
  appKey: string;
  /** Usuário ou e-mail usado para entrar no sistema Ileva; o perfil precisa estar liberado para acesso via API. */
  username: string;
  password: string;
  /** Conexão Redis da aplicação (ioredis ou node-redis), já conectada. Sem Redis o token fica em memória, só neste processo. */
  redis?: RedisClient;
  /** Store próprio, no lugar de `redis`. */
  store?: TokenStore;
  /**
   * Implementação de fetch (proxy, logs, testes). O padrão é o fetch nativo do Node, usado quando
   * nem `fetch` nem `axios` são informados.
   */
  fetch?: typeof fetch;
  /** Instância do axios da aplicação, no lugar do fetch. */
  axios?: AxiosLike;
  /** URL da API. Padrão: https://api.ileva.com.br */
  baseUrl?: string;
  /** Chamado a cada geração de token, para usuários com autenticação em dois fatores. */
  twoFactorCode?: () => string | Promise<string>;
  /** Segundos antes da expiração em que o token passa a ser renovado. Padrão: 300. */
  refreshMarginSeconds?: number;
  /** Timeout da requisição de token, em milissegundos. Padrão: 15000. */
  timeoutMs?: number;
  /** Quanto esperar, em milissegundos, por outro processo que esteja renovando. Padrão: 20000. */
  lockWaitMs?: number;
  /** Prefixo das chaves no Redis. Padrão: "ileva:auth". */
  keyPrefix?: string;
}

const POLL_INTERVAL_MS = 100;

const pbkdf2 = promisify(pbkdf2Callback);
const PASSWORD_CHECK_ALGORITHM = 'pbkdf2-sha256';
const PASSWORD_CHECK_ITERATIONS = 100_000;
// Um valor adulterado no cache não pode travar o processo com um número absurdo de iterações.
const PASSWORD_CHECK_MAX_ITERATIONS = 1_000_000;

// Chave aleatória do processo para o HMAC da senha usado na memorização das conferências.
const processSecret = randomBytes(32);

/**
 * Obtém o token de acesso da API Ileva e mantém sua validade.
 *
 * O token é guardado no store e reaproveitado enquanto for válido; perto de expirar, é renovado.
 * A API mantém um único token ativo por usuário — gerar um novo invalida o anterior —, então a
 * renovação é feita sob lock: só um processo pede o token e os outros esperam por ele no cache.
 *
 * O token em cache só é devolvido a quem informa a mesma senha que o gerou: junto dele fica um
 * verificador da senha (PBKDF2), e uma senha diferente faz o SDK consultar a API. Assim a
 * aplicação pode usar o SDK no login dos seus usuários sem que o cache aceite qualquer senha.
 *
 * Token obtido com código 2FA nunca é devolvido do cache: o SDK não tem como conferir o código (o
 * segredo fica no sistema Ileva), então cada uso vai à API com o código informado.
 */
export class IlevaSdkApiV3Auth {
  static readonly DEFAULT_BASE_URL = 'https://api.ileva.com.br';

  // Chamadas simultâneas no mesmo processo aguardam a mesma resolução, em vez de disputar o lock
  // e esperar pelo intervalo de consulta ao cache.
  static readonly #pending = new Map<string, Promise<Token>>();

  // Conferências de senha já feitas no processo, por chave do token: o token conferido e o HMAC da
  // senha (nunca a senha). O PBKDF2 é pago uma vez por processo a cada token.
  static readonly #verified = new Map<string, { accessToken: string; passwordDigest: Buffer }>();

  readonly baseUrl: string;
  readonly username: string;

  // Campos privados (#) não aparecem em console.log, util.inspect nem JSON.stringify.
  readonly #appKey: string;
  readonly #password: string;
  readonly #store: TokenStore;
  readonly #post: HttpPost;
  readonly #twoFactorCode: (() => string | Promise<string>) | undefined;
  readonly #refreshMarginSeconds: number;
  readonly #timeoutMs: number;
  readonly #lockWaitMs: number;
  readonly #tokenKey: string;
  readonly #lockKey: string;
  readonly #passwordDigest: Buffer;
  readonly #pendingKey: string;

  /**
   * Instâncias com a mesma app key e o mesmo usuário compartilham o token: sem Redis, pela memória
   * do processo; com Redis, entre processos, servidores e com o SDK de PHP.
   */
  constructor(options: IlevaSdkApiV3AuthOptions) {
    const {
      appKey,
      username,
      password,
      redis,
      store,
      fetch: fetchImpl,
      axios,
      baseUrl = IlevaSdkApiV3Auth.DEFAULT_BASE_URL,
      twoFactorCode,
      refreshMarginSeconds = 300,
      timeoutMs = 15_000,
      lockWaitMs = 20_000,
      keyPrefix = 'ileva:auth',
    } = options;

    if (!appKey || !username || !password) {
      throw new TypeError('app key, usuário e senha são obrigatórios.');
    }
    if (redis !== undefined && store !== undefined) {
      throw new TypeError('Informe redis ou store, não os dois.');
    }
    if (fetchImpl !== undefined && axios !== undefined) {
      throw new TypeError('Informe fetch ou axios, não os dois.');
    }
    if (axios !== undefined && typeof axios.request !== 'function') {
      throw new TypeError('axios deve ser uma instância do axios (axios ou axios.create()).');
    }
    if (refreshMarginSeconds < 0 || timeoutMs <= 0 || lockWaitMs <= 0) {
      throw new TypeError('refreshMarginSeconds não pode ser negativo; timeoutMs e lockWaitMs devem ser positivos.');
    }

    this.baseUrl = baseUrl.replace(/\/+$/, '');
    this.username = username;
    this.#appKey = appKey;
    this.#password = password;
    this.#store = store ?? (redis !== undefined ? new RedisTokenStore(redis) : new InMemoryTokenStore());
    this.#post = axios !== undefined ? axiosPost(axios) : fetchPost(fetchImpl ?? globalThis.fetch);
    this.#twoFactorCode = twoFactorCode;
    this.#refreshMarginSeconds = refreshMarginSeconds;
    this.#timeoutMs = timeoutMs;
    this.#lockWaitMs = lockWaitMs;

    // A chave identifica o token pelo ambiente, pela associação (app key) e pelo usuário — a mesma
    // combinação que a API usa para manter um token ativo. A senha fica fora, para que uma troca de
    // senha não deixe o token antigo órfão no cache. É o mesmo cálculo do SDK de PHP, para que os
    // dois compartilhem o token.
    const hash = createHash('sha256')
      .update(`${asciiLower(this.baseUrl)}\n${appKey}\n${asciiLower(trimKeyChars(username))}`)
      .digest('hex');
    this.#tokenKey = `${keyPrefix}:token:${hash}`;
    this.#lockKey = `${keyPrefix}:lock:${hash}`;
    this.#passwordDigest = createHmac('sha256', processSecret).update(password).digest();
    // Só chamadas com a mesma senha compartilham a requisição em andamento: uma senha errada não
    // pode receber o token que a requisição de quem acertou vai trazer.
    this.#pendingKey = `${this.#tokenKey}:${this.#passwordDigest.toString('hex')}`;
  }

  /** Token de acesso válido, gerado ou renovado se necessário. */
  async getToken(): Promise<string> {
    return (await this.#resolveToken()).accessToken;
  }

  /** Valor pronto para o header Authorization, ex.: "Bearer eyJ...". */
  async getAuthorizationHeader(): Promise<string> {
    return (await this.#resolveToken()).authorizationHeader();
  }

  /** Token com o instante de expiração. */
  async getTokenDetails(): Promise<Token> {
    return this.#resolveToken();
  }

  /**
   * Descarta o token do cache, para que a próxima chamada gere outro. Chame ao receber 401 da API,
   * passando o token que foi recusado: se outro processo já o substituiu, o novo é preservado.
   */
  async invalidate(rejectedToken?: string): Promise<void> {
    await this.#store.delete(this.#tokenKey, rejectedToken);
  }

  /** Gera um token novo mesmo que o atual ainda seja válido. */
  async refresh(): Promise<string> {
    await this.invalidate();
    return this.getToken();
  }

  #resolveToken(): Promise<Token> {
    // Com 2FA, cada chamada vai à API com o próprio código. Compartilhar a requisição em andamento
    // entregaria o token a quem tem a senha certa e um código qualquer.
    if (this.#twoFactorCode !== undefined) {
      return this.#resolveTokenFromStore();
    }
    const pending = IlevaSdkApiV3Auth.#pending.get(this.#pendingKey);
    if (pending !== undefined) {
      return pending;
    }
    const promise = this.#resolveTokenFromStore().finally(() => {
      IlevaSdkApiV3Auth.#pending.delete(this.#pendingKey);
    });
    IlevaSdkApiV3Auth.#pending.set(this.#pendingKey, promise);
    return promise;
  }

  async #resolveTokenFromStore(): Promise<Token> {
    const cached = await this.#readCachedToken();
    if (cached !== null) {
      return cached;
    }

    // Espera o suficiente para outro processo terminar a requisição de token (timeout) e, se ele
    // tiver morrido segurando o lock, para o lock expirar e ser obtido aqui.
    const lockTtlMs = this.#timeoutMs + 5_000;
    const deadline = Date.now() + this.#lockWaitMs;

    do {
      const owner = randomBytes(16).toString('hex');
      if (await this.#store.acquireLock(this.#lockKey, owner, lockTtlMs)) {
        try {
          // Outro processo pode ter renovado entre a leitura acima e a obtenção do lock.
          return (await this.#readCachedToken()) ?? (await this.#requestAndStoreToken());
        } finally {
          await this.#store.releaseLock(this.#lockKey, owner);
        }
      }

      await sleep(POLL_INTERVAL_MS);

      const token = await this.#readCachedToken();
      if (token !== null) {
        return token;
      }
    } while (Date.now() < deadline);

    throw new LockTimeoutError(
      `O token não foi renovado por outro processo em ${Math.round(this.#lockWaitMs / 1000)} segundos.`,
    );
  }

  /**
   * Token do cache, se ainda válido e gerado com a mesma senha informada nesta instância. Com outra
   * senha devolve null, como se o cache estivesse vazio: o SDK consulta a API, que recusa a senha
   * errada — e o token de quem acertou continua no cache.
   */
  async #readCachedToken(): Promise<Token | null> {
    const value = await this.#store.get(this.#tokenKey);
    if (value === null) {
      return null;
    }
    const token = Token.fromJsonString(value);
    if (token === null || !token.isValid(nowSeconds(), this.#refreshMarginSeconds)) {
      return null;
    }
    // Servir do cache pularia o 2FA: quem soubesse só a senha receberia o token. Ele continua
    // gravado para substituir o token anterior do usuário, que a API invalidou ao gerar este.
    if (token.twoFactor) {
      return null;
    }
    if (this.#isVerified(token)) {
      return token;
    }
    const check = Token.passwordCheckFromJsonString(value);
    if (check === null || !(await this.#passwordMatches(check))) {
      return null;
    }
    this.#markVerified(token);
    return token;
  }

  async #requestAndStoreToken(): Promise<Token> {
    const token = await this.#requestToken();
    await this.#store.set(this.#tokenKey, token.toJsonString(await this.#createPasswordCheck()), token.expiresAt - nowSeconds());
    this.#markVerified(token);
    return token;
  }

  async #createPasswordCheck(): Promise<string> {
    const salt = randomBytes(16);
    const hash = await pbkdf2(this.#password, salt, PASSWORD_CHECK_ITERATIONS, 32, 'sha256');
    return [PASSWORD_CHECK_ALGORITHM, PASSWORD_CHECK_ITERATIONS, salt.toString('base64'), hash.toString('base64')].join('$');
  }

  /** Um verificador fora do formato conta como senha diferente. */
  async #passwordMatches(check: string): Promise<boolean> {
    const [algorithm, rawIterations, rawSalt, rawHash, ...rest] = check.split('$');
    if (algorithm !== PASSWORD_CHECK_ALGORITHM || rest.length > 0 || !/^\d+$/.test(rawIterations ?? '')) {
      return false;
    }
    const iterations = Number(rawIterations);
    const salt = decodeBase64(rawSalt);
    const expected = decodeBase64(rawHash);
    if (iterations < 1 || iterations > PASSWORD_CHECK_MAX_ITERATIONS || salt === null || expected === null) {
      return false;
    }
    const actual = await pbkdf2(this.#password, salt, iterations, expected.length, 'sha256');
    return timingSafeEqual(expected, actual);
  }

  #isVerified(token: Token): boolean {
    const entry = IlevaSdkApiV3Auth.#verified.get(this.#tokenKey);
    return (
      entry !== undefined &&
      entry.accessToken === token.accessToken &&
      timingSafeEqual(entry.passwordDigest, this.#passwordDigest)
    );
  }

  #markVerified(token: Token): void {
    IlevaSdkApiV3Auth.#verified.set(this.#tokenKey, { accessToken: token.accessToken, passwordDigest: this.#passwordDigest });
  }

  /** @internal Esquece as conferências de senha memorizadas no processo. Uso dos testes. */
  static _clearVerifiedForTests(): void {
    IlevaSdkApiV3Auth.#verified.clear();
  }

  async #requestToken(): Promise<Token> {
    const url = `${this.baseUrl}/oauth/token`;
    const body: Record<string, string> = { username: this.username, password: this.#password };
    if (this.#twoFactorCode !== undefined) {
      body.two_fa = await this.#twoFactorCode();
    }

    const requestedAt = nowSeconds();
    // Um timer comum em vez de AbortSignal.timeout(): o daquele não mantém o processo vivo, e um
    // script sem mais nada pendente terminaria antes de o timeout disparar.
    const controller = new AbortController();
    const timer = setTimeout(
      () => controller.abort(new Error(`timeout de ${this.#timeoutMs} ms`)),
      this.#timeoutMs,
    );
    let status: number;
    let text: string;
    try {
      ({ status, body: text } = await this.#post(
        url,
        {
          Accept: 'application/json',
          'Content-Type': 'application/json',
          app_key: this.#appKey,
        },
        JSON.stringify(body),
        controller.signal,
      ));
    } catch (error) {
      // No timeout, a mensagem do cancelamento varia entre clientes ("canceled" no axios); a do
      // motivo do abort é a mesma para todos.
      const cause = controller.signal.aborted ? controller.signal.reason : error;
      const reason = cause instanceof Error ? cause.message : String(cause);
      throw new TransportError(`Falha ao conectar em ${url}: ${reason}`, { cause });
    } finally {
      clearTimeout(timer);
    }

    const data = parseJsonObject(text);

    if (status !== 200) {
      const message =
        typeof data?.mensagem === 'string' ? data.mensagem : `A API respondeu HTTP ${status} ao gerar o token.`;
      if (status === 401) {
        throw new AuthenticationError(message);
      }
      throw new ApiError(message, status);
    }

    const expiresIn = Number(data?.expires_in);
    if (typeof data?.access_token !== 'string' || data.expires_in === null || !Number.isFinite(expiresIn)) {
      throw new ApiError('Resposta de token fora do formato esperado.', status);
    }

    const tokenType = typeof data.token_type === 'string' ? data.token_type : 'Bearer';

    // Conta a validade a partir do envio, não da resposta: assim o tempo de rede nunca faz o SDK
    // achar que o token vale mais do que a API considera.
    return new Token(data.access_token, tokenType, requestedAt + Math.trunc(expiresIn), this.#twoFactorCode !== undefined);
  }
}

// Normalização da chave, idêntica nos SDKs de todas as linguagens: minúsculas só em ASCII e trim só
// de " \t\n\r\v\0". toLowerCase() e trim() convertem e removem também caracteres Unicode, o que
// daria chaves diferentes das do PHP e do Python.
function asciiLower(value: string): string {
  return value.replace(/[A-Z]/g, (char) => char.toLowerCase());
}

function trimKeyChars(value: string): string {
  return value.replace(/^[ \t\n\r\v\0]+|[ \t\n\r\v\0]+$/g, '');
}

/** Base64 estrito e não vazio; null para qualquer outra coisa. */
function decodeBase64(value: string | undefined): Buffer | null {
  if (value === undefined || value === '' || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) {
    return null;
  }
  const decoded = Buffer.from(value, 'base64');
  return decoded.length > 0 ? decoded : null;
}

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

function parseJsonObject(text: string): Record<string, unknown> | null {
  try {
    const data: unknown = JSON.parse(text);
    return typeof data === 'object' && data !== null && !Array.isArray(data) ? (data as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}
