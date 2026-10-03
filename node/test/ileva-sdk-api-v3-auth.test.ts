import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { inspect } from 'node:util';
import { afterEach, beforeEach, describe, it } from 'node:test';
import {
  ApiError,
  AuthenticationError,
  IlevaSdkApiV3Auth,
  type IlevaSdkApiV3AuthOptions,
  InMemoryTokenStore,
  LockTimeoutError,
  Token,
  type TokenStore,
  TransportError,
} from '../src/index.js';

interface RecordedRequest {
  url: string;
  headers: Record<string, string>;
  body: Record<string, string>;
}

/** fetch falso: devolve as respostas enfileiradas, na ordem, e registra as requisições. */
class FakeFetch {
  readonly requests: RecordedRequest[] = [];
  private readonly responses: (() => Response | Promise<Response>)[] = [];

  readonly fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    this.requests.push({
      url: String(input),
      headers: init?.headers as Record<string, string>,
      body: JSON.parse(String(init?.body)),
    });
    const next = this.responses.shift();
    if (next === undefined) {
      throw new Error('Requisição de token inesperada.');
    }
    return next();
  }) as typeof fetch;

  token(accessToken: string, expiresIn = 86400): this {
    return this.json(200, { access_token: accessToken, token_type: 'Bearer', expires_in: expiresIn });
  }

  json(status: number, body: unknown): this {
    this.responses.push(() => new Response(typeof body === 'string' ? body : JSON.stringify(body), { status }));
    return this;
  }

  delayedToken(accessToken: string, delayMs: number): this {
    this.responses.push(async () => {
      await new Promise((resolve) => setTimeout(resolve, delayMs));
      return new Response(JSON.stringify({ access_token: accessToken, token_type: 'Bearer', expires_in: 86400 }));
    });
    return this;
  }

  networkError(message: string): this {
    this.responses.push(() => {
      throw new TypeError(message);
    });
    return this;
  }
}

const hash = createHash('sha256').update('https://api.teste\napp-key\nintegracao').digest('hex');
const tokenKey = `ileva:auth:token:${hash}`;
const lockKey = `ileva:auth:lock:${hash}`;
const now = () => Math.floor(Date.now() / 1000);

/**
 * Verificador da senha "segredo" gerado com salt fixo (16 bytes 0x01). O SDK de PHP testa o mesmo
 * valor: os dois precisam aceitar o verificador gravado pelo outro.
 */
const SEGREDO_CHECK = 'pbkdf2-sha256$100000$AQEBAQEBAQEBAQEBAQEBAQ==$MC4obyTDiJ9/piZiz+KFtXeenFNNoJQjr5MSPiDBgxM=';

describe('IlevaSdkApiV3Auth', () => {
  let http: FakeFetch;
  let store: InMemoryTokenStore;

  const auth = (options: Partial<IlevaSdkApiV3AuthOptions> = {}) =>
    new IlevaSdkApiV3Auth({
      appKey: 'app-key',
      username: 'integracao',
      password: 'segredo',
      fetch: http.fetch,
      baseUrl: 'https://api.teste/',
      ...options,
    });

  /** Grava um token no cache como o SDK grava: com o verificador da senha "segredo". */
  const seed = (token: Token, ttl: number, passwordCheck: string | null = SEGREDO_CHECK) =>
    store.set(tokenKey, token.toJsonString(passwordCheck ?? undefined), ttl);

  beforeEach(() => {
    InMemoryTokenStore.clear();
    IlevaSdkApiV3Auth._clearVerifiedForTests();
    http = new FakeFetch();
    store = new InMemoryTokenStore();
  });

  afterEach(() => {
    InMemoryTokenStore.clear();
    IlevaSdkApiV3Auth._clearVerifiedForTests();
  });

  it('gera o token com a app key no header e as credenciais no body', async () => {
    http.token('tok-1');

    assert.equal(await auth().getToken(), 'tok-1');

    assert.equal(http.requests.length, 1);
    const [request] = http.requests;
    assert.equal(request!.url, 'https://api.teste/oauth/token');
    assert.equal(request!.headers.app_key, 'app-key');
    assert.equal(request!.headers['Content-Type'], 'application/json');
    assert.deepEqual(request!.body, { username: 'integracao', password: 'segredo' });
  });

  it('instâncias com as mesmas credenciais compartilham o token da memória estática', async () => {
    http.token('tok-1');
    await auth().getToken();

    const outra = auth();
    assert.equal(await outra.getToken(), 'tok-1');
    assert.equal(await outra.getAuthorizationHeader(), 'Bearer tok-1');
    assert.equal(http.requests.length, 1);
  });

  it('chamadas simultâneas no processo geram um único token', async () => {
    http.delayedToken('tok-1', 50);

    const tokens = await Promise.all(Array.from({ length: 10 }, () => auth().getToken()));

    assert.deepEqual(new Set(tokens), new Set(['tok-1']));
    assert.equal(http.requests.length, 1);
  });

  it('usuários da mesma app key têm tokens independentes', async () => {
    http.token('tok-joao').token('tok-maria');
    const joao = auth({ username: 'joao' });
    const maria = auth({ username: 'maria' });

    assert.equal(await joao.getToken(), 'tok-joao');
    assert.equal(await maria.getToken(), 'tok-maria');
    assert.equal(await auth({ username: 'joao' }).getToken(), 'tok-joao');
    assert.equal(await auth({ username: 'maria' }).getToken(), 'tok-maria');
    assert.equal(http.requests.length, 2);
  });

  it('invalidar um usuário não afeta outro', async () => {
    http.token('tok-joao').token('tok-maria').token('tok-joao-2');
    const joao = auth({ username: 'joao' });
    const maria = auth({ username: 'maria' });
    await joao.getToken();
    await maria.getToken();

    await joao.invalidate();

    assert.equal(await maria.getToken(), 'tok-maria');
    assert.equal(await joao.getToken(), 'tok-joao-2');
    assert.equal(http.requests.length, 3);
  });

  it('o mesmo usuário em app keys diferentes tem tokens independentes', async () => {
    http.token('tok-a').token('tok-b');

    assert.equal(await auth({ appKey: 'associacao-a' }).getToken(), 'tok-a');
    assert.equal(await auth({ appKey: 'associacao-b' }).getToken(), 'tok-b');
    assert.equal(await auth({ appKey: 'associacao-a' }).getToken(), 'tok-a');
    assert.equal(http.requests.length, 2);
  });

  it('a chave do cache ignora a caixa do usuário e a barra final da URL', async () => {
    http.token('tok-1');
    await auth().getToken();

    assert.notEqual(await store.get(tokenKey), null);
    assert.equal(await auth({ username: ' Integracao ', baseUrl: 'https://api.teste' }).getToken(), 'tok-1');
    assert.equal(http.requests.length, 1);
  });

  it('a chave usa minúsculas só em ASCII, como os outros SDKs', async () => {
    // "Ã" não vira "ã": toLowerCase() do JS, lower() do Python e strtolower() do PHP divergem fora
    // do ASCII, e a chave precisa ser igual em todos. Espaço Unicode (\u00a0) também não é removido.
    http.token('tok-1').token('tok-2');
    await auth({ username: ' JOÃO\t' }).getToken();

    const key = `ileva:auth:token:${createHash('sha256').update('https://api.teste\napp-key\njoÃo').digest('hex')}`;
    assert.notEqual(await store.get(key), null);

    await auth({ username: '\u00a0integracao' }).getToken();
    assert.equal(http.requests.length, 2);
  });

  it('grava no cache no formato compartilhado com o SDK de PHP', async () => {
    http.token('tok-1', 3600);
    const before = now();

    await auth().getToken();

    const stored = JSON.parse((await store.get(tokenKey))!);
    assert.equal(stored.access_token, 'tok-1');
    assert.equal(stored.token_type, 'Bearer');
    assert.ok(stored.expires_at >= before + 3600);
    assert.ok(stored.expires_at <= now() + 3600);
    assert.deepEqual(Object.keys(stored), ['access_token', 'token_type', 'expires_at', 'password_check']);
  });

  it('lê o token gravado pelo SDK de PHP', async () => {
    // Mesmo JSON que o Token::toJson() do PHP grava (json_encode com JSON_UNESCAPED_SLASHES).
    await store.set(
      tokenKey,
      `{"access_token":"do-php","token_type":"Bearer","expires_at":${now() + 3600},"password_check":"${SEGREDO_CHECK}"}`,
      3600,
    );

    assert.equal(await auth().getToken(), 'do-php');
    assert.equal(http.requests.length, 0);
  });

  it('renova o token dentro da margem de renovação', async () => {
    await seed(new Token('velho', 'Bearer', now() + 200), 200);
    http.token('novo');

    assert.equal(await auth({ refreshMarginSeconds: 300 }).getToken(), 'novo');
  });

  it('usa o token fora da margem de renovação', async () => {
    await seed(new Token('atual', 'Bearer', now() + 400), 400);

    assert.equal(await auth({ refreshMarginSeconds: 300 }).getToken(), 'atual');
    assert.equal(http.requests.length, 0);
  });

  it('valor corrompido no cache é tratado como vazio', async () => {
    await store.set(tokenKey, 'nao-e-json', 60);
    http.token('tok-1');

    assert.equal(await auth().getToken(), 'tok-1');
  });

  it('invalidate com token recusado preserva o token novo de outro processo', async () => {
    await seed(new Token('novo', 'Bearer', now() + 3600), 3600);
    const instance = auth();

    await instance.invalidate('velho');

    assert.equal(await instance.getToken(), 'novo');
    assert.equal(http.requests.length, 0);
  });

  it('invalidate com o token atual força nova geração', async () => {
    http.token('tok-1').token('tok-2');
    const instance = auth();

    await instance.invalidate(await instance.getToken());

    assert.equal(await instance.getToken(), 'tok-2');
  });

  it('refresh gera token mesmo com token válido', async () => {
    http.token('tok-1').token('tok-2');
    const instance = auth();
    await instance.getToken();

    assert.equal(await instance.refresh(), 'tok-2');
  });

  it('envia o código de dois fatores', async () => {
    http.token('tok-1');

    await auth({ twoFactorCode: async () => '123456' }).getToken();

    assert.equal(http.requests[0]!.body.two_fa, '123456');
  });

  it('erro 401 vira AuthenticationError com a mensagem da API', async () => {
    http.json(401, { status: 401, mensagem: 'Usuário ou senha inválidos' });

    await assert.rejects(auth().getToken(), (error: unknown) => {
      assert.ok(error instanceof AuthenticationError);
      assert.equal(error.message, 'Usuário ou senha inválidos');
      assert.equal(error.status, 401);
      return true;
    });
  });

  it('erro diferente de 401 vira ApiError com o status', async () => {
    http.json(500, 'Internal Server Error');

    await assert.rejects(auth().getToken(), (error: unknown) => {
      assert.ok(error instanceof ApiError);
      assert.equal(error.status, 500);
      return true;
    });
  });

  it('resposta sem access_token vira ApiError', async () => {
    http.json(200, { expires_in: 60 });

    await assert.rejects(auth().getToken(), ApiError);
  });

  it('falha de rede vira TransportError com o erro original em cause', async () => {
    http.networkError('fetch failed');

    await assert.rejects(auth().getToken(), (error: unknown) => {
      assert.ok(error instanceof TransportError);
      assert.match(error.message, /fetch failed/);
      assert.ok(error.cause instanceof TypeError);
      return true;
    });
  });

  it('timeout da requisição vira TransportError', async () => {
    const slowFetch = ((_url: string, init: RequestInit) =>
      new Promise((_resolve, reject) => {
        init.signal!.addEventListener('abort', () => reject(init.signal!.reason));
      })) as unknown as typeof fetch;

    await assert.rejects(auth({ fetch: slowFetch, timeoutMs: 50 }).getToken(), TransportError);
  });

  it('senha errada com token em cache consulta a API e recebe 401', async () => {
    http.token('tok-certo');
    await auth().getToken();
    http.json(401, { status: 401, mensagem: 'Usuário ou senha inválidos' });

    await assert.rejects(auth({ password: 'errada' }).getToken(), AuthenticationError);

    // A senha errada foi à API; o token de quem acertou continua no cache.
    assert.equal(http.requests.length, 2);
    assert.equal(http.requests[1]!.body.password, 'errada');
    assert.equal(await auth().getToken(), 'tok-certo');
    assert.equal(http.requests.length, 2);
  });

  it('senha errada não aproveita a conferência memorizada da senha certa', async () => {
    http.token('tok-certo');
    await auth().getToken();
    assert.equal(await auth().getToken(), 'tok-certo'); // conferência memorizada no processo
    http.json(401, { status: 401, mensagem: 'Usuário ou senha inválidos' });

    await assert.rejects(auth({ password: 'errada' }).getToken(), AuthenticationError);
  });

  it('senha errada simultânea não pega carona na requisição de quem acertou', async () => {
    // A primeira requisição (senha certa) demora; a segunda (senha errada) chega enquanto ela está
    // em andamento e precisa ir à API por conta própria.
    http.delayedToken('tok-certo', 100).json(401, { status: 401, mensagem: 'Usuário ou senha inválidos' });

    const [certo, errado] = await Promise.allSettled([
      auth().getToken(),
      auth({ password: 'errada' }).getToken(),
    ]);

    assert.equal(certo.status === 'fulfilled' && certo.value, 'tok-certo');
    assert.ok(errado.status === 'rejected' && errado.reason instanceof AuthenticationError);
  });

  it('aceita o verificador gravado pelo SDK de PHP', async () => {
    await seed(new Token('do-php', 'Bearer', now() + 3600), 3600, SEGREDO_CHECK);

    assert.equal(await auth().getToken(), 'do-php');
    assert.equal(http.requests.length, 0);
  });

  it('token sem verificador é tratado como cache vazio', async () => {
    await seed(new Token('sem-verificador', 'Bearer', now() + 3600), 3600, null);
    http.token('tok-novo');

    assert.equal(await auth().getToken(), 'tok-novo');
  });

  it('verificador adulterado é tratado como senha diferente', async () => {
    for (const check of [
      'pbkdf2-sha256$99999999$AQEBAQEBAQEBAQEBAQEBAQ==$MC4obyTDiJ9/piZiz+KFtXeenFNNoJQjr5MSPiDBgxM=',
      'md5$1$AQ==$AQ==',
      'pbkdf2-sha256$100000$@@@$AQ==',
      'lixo',
    ]) {
      await seed(new Token('adulterado', 'Bearer', now() + 3600), 3600, check);
      http.token('tok-novo');
      assert.equal(await auth().getToken(), 'tok-novo');
    }
  });

  it('senha nova correta substitui o token gerado com a senha antiga', async () => {
    http.token('tok-senha-antiga').token('tok-senha-nova');
    await auth({ password: 'antiga' }).getToken();

    assert.equal(await auth({ password: 'nova' }).getToken(), 'tok-senha-nova');
    assert.equal(await auth({ password: 'nova' }).getToken(), 'tok-senha-nova');
    assert.equal(http.requests.length, 2);
  });

  it('token obtido com 2FA não é devolvido do cache sem o código', async () => {
    http.token('tok-com-2fa');
    await auth({ twoFactorCode: () => '123456' }).getToken();
    http.json(401, { status: 401, mensagem: 'Informe o código de verificação de autenticação de dois fatores (two_fa)' });

    // Senha certa, sem o código: vai à API, que exige o 2FA.
    await assert.rejects(auth().getToken(), /dois fatores/);
    assert.equal(http.requests.length, 2);
    assert.equal(http.requests[1]!.body.two_fa, undefined);
  });

  it('cada login com 2FA consulta a API', async () => {
    http.token('tok-1').token('tok-2');

    assert.equal(await auth({ twoFactorCode: () => '111111' }).getToken(), 'tok-1');
    assert.equal(await auth({ twoFactorCode: () => '222222' }).getToken(), 'tok-2');

    assert.equal(http.requests.length, 2);
    assert.equal(http.requests[1]!.body.two_fa, '222222');
  });

  it('código 2FA errado simultâneo não pega carona no login de quem acertou', async () => {
    http.delayedToken('tok-vitima', 100).json(401, { status: 401, mensagem: 'Código de autenticação de dois fatores (two_fa) inválido' });

    const [vitima, atacante] = await Promise.allSettled([
      auth({ twoFactorCode: () => '123456' }).getToken(),
      auth({ twoFactorCode: () => '000000' }).getToken(),
    ]);

    assert.equal(vitima.status === 'fulfilled' && vitima.value, 'tok-vitima');
    assert.ok(atacante.status === 'rejected' && atacante.reason instanceof AuthenticationError);
    assert.equal(http.requests.length, 2);
  });

  it('sem código, simultâneo ao login com 2FA, não pega carona', async () => {
    http.delayedToken('tok-vitima', 100).json(401, { status: 401, mensagem: 'Informe o código de verificação de autenticação de dois fatores (two_fa)' });

    const [vitima, atacante] = await Promise.allSettled([
      auth({ twoFactorCode: () => '123456' }).getToken(),
      auth().getToken(),
    ]);

    assert.equal(vitima.status === 'fulfilled' && vitima.value, 'tok-vitima');
    assert.ok(atacante.status === 'rejected' && atacante.reason instanceof AuthenticationError);
  });

  it('token com 2FA fica marcado no cache; sem 2FA, não', async () => {
    http.token('tok-1');
    await auth({ twoFactorCode: () => '123456' }).getToken();
    assert.equal(JSON.parse((await store.get(tokenKey))!).two_factor, true);

    InMemoryTokenStore.clear();
    http.token('tok-2');
    await auth().getToken();
    assert.equal('two_factor' in JSON.parse((await store.get(tokenKey))!), false);
  });

  it('respeita a marca de 2FA gravada pelo SDK de PHP', async () => {
    await store.set(
      tokenKey,
      `{"access_token":"do-php-com-2fa","token_type":"Bearer","expires_at":${now() + 3600},"password_check":"${SEGREDO_CHECK}","two_factor":true}`,
      3600,
    );
    http.token('tok-novo');

    assert.equal(await auth().getToken(), 'tok-novo');
  });

  it('o cache não guarda a senha', async () => {
    http.token('tok-1');
    await auth().getToken();

    const stored = (await store.get(tokenKey))!;
    assert.doesNotMatch(stored, /segredo/);
    assert.match(JSON.parse(stored).password_check, /^pbkdf2-sha256\$100000\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$/);
  });

  it('falha na geração libera o lock', async () => {
    http.json(500, '').token('tok-1');
    const instance = auth({ lockWaitMs: 300 });

    await assert.rejects(instance.getToken(), ApiError);

    // Se o lock tivesse ficado preso, esta chamada esperaria e daria LockTimeoutError.
    assert.equal(await instance.getToken(), 'tok-1');
  });

  it('espera o token gerado por outro processo que segura o lock', async () => {
    await store.acquireLock(lockKey, 'outro-processo', 10_000);
    const slowStore = new TokenAppearsAfterReadsStore(store, 3, new Token('do-outro', 'Bearer', now() + 3600));

    assert.equal(await auth({ store: slowStore }).getToken(), 'do-outro');
    assert.equal(http.requests.length, 0);
  });

  it('lock preso sem token estoura o tempo de espera', async () => {
    await store.acquireLock(lockKey, 'outro-processo', 10_000);

    await assert.rejects(auth({ lockWaitMs: 300 }).getToken(), LockTimeoutError);
  });

  it('não expõe senha nem app key em console.log, inspect ou JSON', () => {
    const instance = auth({ password: 'senha-secreta-123', appKey: 'app-key-secreta' });

    for (const output of [inspect(instance, { showHidden: true, depth: 5 }), JSON.stringify(instance)]) {
      assert.doesNotMatch(output, /senha-secreta-123/);
      assert.doesNotMatch(output, /app-key-secreta/);
    }
    assert.match(inspect(instance), /integracao/);
  });

  it('recusa redis e store juntos', () => {
    assert.throws(() => auth({ redis: { call: async () => null }, store }), TypeError);
  });

  it('recusa conexão Redis não suportada', () => {
    assert.throws(() => auth({ redis: {} as never }), /Conexão Redis não suportada/);
  });

  it('recusa credenciais vazias', () => {
    assert.throws(() => auth({ password: '' }), TypeError);
  });
});

/** Simula outro processo que grava o token no cache depois de algumas leituras. */
class TokenAppearsAfterReadsStore implements TokenStore {
  private reads = 0;

  constructor(
    private readonly inner: TokenStore,
    private readonly afterReads: number,
    private readonly token: Token,
  ) {}

  async get(key: string): Promise<string | null> {
    if (key === tokenKey && ++this.reads === this.afterReads) {
      await this.inner.set(key, this.token.toJsonString(SEGREDO_CHECK), 3600);
    }
    return this.inner.get(key);
  }

  set(key: string, value: string, ttlSeconds: number) {
    return this.inner.set(key, value, ttlSeconds);
  }

  delete(key: string, accessToken?: string) {
    return this.inner.delete(key, accessToken);
  }

  acquireLock(key: string, owner: string, ttlMilliseconds: number) {
    return this.inner.acquireLock(key, owner, ttlMilliseconds);
  }

  releaseLock(key: string, owner: string) {
    return this.inner.releaseLock(key, owner);
  }
}
