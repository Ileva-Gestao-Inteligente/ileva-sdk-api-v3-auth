import assert from 'node:assert/strict';
import { createServer, type IncomingMessage, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { inspect } from 'node:util';
import { after, before, beforeEach, describe, it } from 'node:test';
import axios from 'axios';
import {
  ApiError,
  AuthenticationError,
  IlevaSdkApiV3Auth,
  type IlevaSdkApiV3AuthOptions,
  InMemoryTokenStore,
  TransportError,
} from '../src/index.js';

/** API Ileva falsa em HTTP de verdade, para exercitar o fetch e o axios reais. */
interface Received {
  headers: IncomingMessage['headers'];
  body: Record<string, string>;
}

let server: Server;
let baseUrl: string;
let received: Received[] = [];
let reply: (res: import('node:http').ServerResponse) => void;

const json = (status: number, body: unknown) => (res: import('node:http').ServerResponse) => {
  res.writeHead(status, { 'Content-Type': 'application/json' }).end(JSON.stringify(body));
};

before(async () => {
  server = createServer(async (req, res) => {
    let raw = '';
    for await (const chunk of req) raw += chunk;
    received.push({ headers: req.headers, body: JSON.parse(raw || '{}') });
    reply(res);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(() => {
  server.closeAllConnections();
  server.close();
});

const clients: Record<string, () => Partial<IlevaSdkApiV3AuthOptions>> = {
  'fetch (padrão)': () => ({}),
  axios: () => ({ axios }),
  'axios.create() com JSON e baseURL próprios': () => ({
    axios: axios.create({ baseURL: 'https://outra.api', timeout: 60_000, headers: { 'X-App': 'teste' } }),
  }),
};

for (const [name, client] of Object.entries(clients)) {
  describe(`requisição de token com ${name}`, () => {
    const auth = (options: Partial<IlevaSdkApiV3AuthOptions> = {}) =>
      new IlevaSdkApiV3Auth({
        appKey: 'app-key',
        username: 'integracao',
        password: 'senha-secreta-123',
        baseUrl,
        ...client(),
        ...options,
      });

    beforeEach(() => {
      InMemoryTokenStore.clear();
      IlevaSdkApiV3Auth._clearVerifiedForTests();
      received = [];
    });

    it('envia app key no header e credenciais no body, e lê o token', async () => {
      reply = json(200, { access_token: 'tok-1', token_type: 'Bearer', expires_in: 86400 });

      const token = await auth().getTokenDetails();

      assert.equal(token.accessToken, 'tok-1');
      assert.ok(token.expiresAt > Date.now() / 1000 + 86000);
      assert.equal(received.length, 1);
      assert.equal(received[0]!.headers.app_key, 'app-key');
      assert.match(received[0]!.headers['content-type']!, /application\/json/);
      assert.deepEqual(received[0]!.body, { username: 'integracao', password: 'senha-secreta-123' });
    });

    it('401 vira AuthenticationError com a mensagem da API', async () => {
      reply = json(401, { status: 401, mensagem: 'App key inválida' });

      await assert.rejects(auth().getToken(), (error: unknown) => {
        assert.ok(error instanceof AuthenticationError);
        assert.equal(error.message, 'App key inválida');
        return true;
      });
    });

    it('500 vira ApiError com o status', async () => {
      reply = (res) => res.writeHead(500).end('Internal Server Error');

      await assert.rejects(auth().getToken(), (error: unknown) => {
        assert.ok(error instanceof ApiError);
        assert.equal(error.status, 500);
        return true;
      });
    });

    it('timeout vira TransportError com a mesma mensagem', async () => {
      reply = () => {}; // nunca responde

      await assert.rejects(auth({ timeoutMs: 100 }).getToken(), (error: unknown) => {
        assert.ok(error instanceof TransportError);
        assert.match(error.message, /timeout de 100 ms/);
        return true;
      });
    });

    it('falha de conexão vira TransportError sem expor a senha', async () => {
      // Porta sem ninguém escutando.
      const closed = createServer();
      await new Promise<void>((resolve) => closed.listen(0, '127.0.0.1', resolve));
      const port = (closed.address() as AddressInfo).port;
      await new Promise((resolve) => closed.close(resolve));

      await assert.rejects(auth({ baseUrl: `http://127.0.0.1:${port}` }).getToken(), (error: unknown) => {
        assert.ok(error instanceof TransportError);
        // console.error mostra o erro com toda a cadeia de `cause`.
        const printed = inspect(error, { depth: 10, showHidden: true });
        assert.doesNotMatch(printed, /senha-secreta-123/);
        return true;
      });
    });
  });
}

describe('axios com interceptor que lança em status de erro', () => {
  it('ainda devolve a mensagem da API no erro certo', async () => {
    InMemoryTokenStore.clear();
    const instance = axios.create();
    instance.interceptors.response.use((response) => {
      if (response.status >= 400) {
        throw Object.assign(new Error(`HTTP ${response.status}`), { response });
      }
      return response;
    });
    reply = json(401, { status: 401, mensagem: 'Usuário ou senha inválidos' });

    const auth = new IlevaSdkApiV3Auth({ appKey: 'app-key', username: 'integracao', password: 'x', baseUrl, axios: instance });

    await assert.rejects(auth.getToken(), (error: unknown) => {
      assert.ok(error instanceof AuthenticationError);
      assert.equal(error.message, 'Usuário ou senha inválidos');
      return true;
    });
  });
});

describe('opções de cliente HTTP', () => {
  it('recusa fetch e axios juntos', () => {
    assert.throws(
      () => new IlevaSdkApiV3Auth({ appKey: 'a', username: 'u', password: 'p', fetch, axios }),
      /fetch ou axios/,
    );
  });

  it('recusa axios que não é instância do axios', () => {
    assert.throws(
      () => new IlevaSdkApiV3Auth({ appKey: 'a', username: 'u', password: 'p', axios: {} as never }),
      /instância do axios/,
    );
  });
});
