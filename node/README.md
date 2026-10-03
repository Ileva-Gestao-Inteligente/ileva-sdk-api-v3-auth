# @ileva/sdk-api-v3-auth (Node.js)

Autenticação na API Ileva v3: gera o token de acesso a partir da app key, do usuário e da senha e
mantém sua validade, renovando quando está perto de expirar.

Requer Node.js 20+. Funciona com ESM (`import`) e CommonJS (`require`), com tipos TypeScript
incluídos e sem dependências. As requisições usam o `fetch` nativo, ou o axios da aplicação. Para compartilhar o token entre processos, use Redis com
[ioredis](https://github.com/redis/ioredis) ou [node-redis](https://github.com/redis/node-redis).

## Instalação

```bash
npm install @ileva/sdk-api-v3-auth
```

## Uso

```js
import { Redis } from 'ioredis';
import { IlevaSdkApiV3Auth } from '@ileva/sdk-api-v3-auth';

const auth = new IlevaSdkApiV3Auth({
  appKey: process.env.ILEVA_APP_KEY,
  username: process.env.ILEVA_USUARIO,
  password: process.env.ILEVA_SENHA,
  redis: new Redis(),
});

const response = await fetch('https://api.ileva.com.br/regulagem?inicio_paginacao=0&quantidade_por_pagina=5', {
  headers: { Authorization: await auth.getAuthorizationHeader() }, // "Bearer eyJ..."
});
```

Com CommonJS: `const { IlevaSdkApiV3Auth } = require('@ileva/sdk-api-v3-auth');`

Instâncias criadas com a mesma app key e o mesmo usuário compartilham o token: enquanto ele não
estiver perto de expirar, nenhuma delas gera outro. Chamadas simultâneas no mesmo processo
aguardam uma única requisição de token.

### Redis

O `redis` recebe a conexão que a aplicação já usa, já conectada:

```js
// ioredis (Redis ou Cluster)
import { Redis } from 'ioredis';
const redis = new Redis(process.env.REDIS_URL);

// node-redis
import { createClient } from 'redis';
const redis = await createClient({ url: process.env.REDIS_URL }).connect();

const auth = new IlevaSdkApiV3Auth({ appKey, username, password, redis });
```

### Por que Redis

A API mantém **um único token ativo por usuário**: gerar um token novo invalida o anterior. Se
cada processo (cada réplica, cada worker do cluster ou do PM2, cada função serverless) gerasse o
seu, eles se derrubariam e passariam a receber 401.

Com Redis, o token fica num cache compartilhado e a renovação é feita sob lock: só um processo
pede o token e os demais esperam por ele no cache. Isso vale também com o SDK de PHP: os dois
usam as mesmas chaves e o mesmo formato (veja o [Contrato do cache](../README.md#contrato-do-cache)),
então uma aplicação PHP e uma Node podem compartilhar o mesmo usuário de API.

Sem `redis`, o token fica na memória do processo, compartilhado por todas as instâncias dele. Isso
serve apenas para um processo único.

### Vários usuários

Cada combinação de app key e usuário tem seu próprio token, lock e renovação:

```js
const joao = new IlevaSdkApiV3Auth({ appKey: 'X', username: 'joao', password: '...', redis });
const maria = new IlevaSdkApiV3Auth({ appKey: 'X', username: 'maria', password: '...', redis });

await joao.getToken();  // gera o token do joao
await maria.getToken(); // gera o da maria, sem invalidar o do joao
```

A senha é conferida a cada uso: o token em cache só é devolvido a quem informa a mesma senha que o
gerou. Com outra senha, o SDK consulta a API — que recusa a senha errada, sem afetar o token de quem
acertou, ou gera um token novo se o usuário tiver trocado a senha.

### Login dos usuários da aplicação

A aplicação pode oferecer aos seus usuários o mesmo login do sistema Ileva: usuário (ou e-mail) e
senha. A app key é da aplicação; usuário, senha e, se houver, o código 2FA vêm da tela de login.

> **O perfil do usuário precisa estar liberado para acesso via API.** No sistema Ileva, em
> *Administração > Usuários do sistema*, edite o usuário e, no painel **Permissões**, ligue
> **API de integração** em **Permitir acesso via**. Sem isso, o login é recusado com
> `Usuário não autorizado para acesso via API`, mesmo com usuário e senha corretos. A opção só
> aparece para quem tem permissão de alterar as permissões de usuários.

```js
import { AuthenticationError, IlevaSdkApiV3Auth } from '@ileva/sdk-api-v3-auth';

// Rota de login da aplicação (ex.: Express)
app.post('/login', async (req, res) => {
  const { usuario, senha, codigo2fa } = req.body;
  try {
    const auth = new IlevaSdkApiV3Auth({
      appKey: process.env.ILEVA_APP_KEY,
      username: usuario,
      password: senha,
      redis,
      twoFactorCode: codigo2fa ? () => codigo2fa : undefined,
    });
    const token = await auth.getTokenDetails();

    req.session.ilevaToken = token.accessToken;
    req.session.ilevaTokenExpiraEm = token.expiresAt;
    res.redirect('/');
  } catch (error) {
    if (error instanceof AuthenticationError) {
      // Mensagem da API: senha errada, perfil sem acesso via API, troca de senha pendente, 2FA...
      return res.status(401).render('login', { erro: error.message });
    }
    throw error;
  }
});
```

Guarde na sessão só o token, nunca a senha do usuário. Quando o token expirar (`expiresAt`) ou a API
responder 401, peça o login de novo.

As mensagens de erro vêm da API e podem ser mostradas ao usuário: `Usuário ou senha inválidos`,
`Usuário não autorizado para acesso via API`, `Informe o código de verificação de autenticação de
dois fatores (two_fa)`, entre outras.

Para usuários com 2FA, cada login vai à API e encerra as outras sessões do mesmo usuário (veja
[Autenticação em dois fatores](#autenticação-em-dois-fatores)).

### Quando a API responder 401

Um token pode ser invalidado antes do prazo — por exemplo, se alguém gerar outro token para o mesmo
usuário fora do SDK. Ao receber 401, invalide o token recusado e tente uma vez mais:

```js
let token = await auth.getToken();
let response = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });

if (response.status === 401) {
  await auth.invalidate(token);
  response = await fetch(url, { headers: { Authorization: await auth.getAuthorizationHeader() } });
}
```

Passar o token recusado para `invalidate()` importa: se outro processo já tiver gerado um token
novo, ele é preservado, e não é gerado um terceiro.

### Cliente HTTP: fetch ou axios

A requisição de token usa o `fetch` nativo por padrão. Para usar o axios da aplicação — com os
interceptors, o proxy e o agente que ela já configura —, passe a instância em `axios`:

```js
import axios from 'axios';

const http = axios.create({ proxy: { host: 'proxy.interno', port: 3128 } });
const auth = new IlevaSdkApiV3Auth({ appKey, username, password, redis, axios: http });
```

O SDK não depende do axios: ele usa a instância que você informar. Na requisição de token, aceita
qualquer status HTTP e lê a resposta como texto, então `baseURL`, `transformResponse` e
`validateStatus` da instância não interferem. O tempo limite é o `timeoutMs`, aplicado por
`signal`; se a instância tiver um `timeout` menor, ele também vale. Interceptors continuam valendo.

Também dá para informar outra implementação de `fetch`, por exemplo para usar um proxy com o undici:

```js
import { fetch, ProxyAgent } from 'undici';

const dispatcher = new ProxyAgent(process.env.HTTPS_PROXY);
const auth = new IlevaSdkApiV3Auth({
  appKey, username, password, redis,
  fetch: (url, init) => fetch(url, { ...init, dispatcher }),
});
```

### Autenticação em dois fatores

Se o usuário tiver 2FA, informe uma função que devolva o código no momento da geração do token:

```js
const auth = new IlevaSdkApiV3Auth({
  appKey, username, password, redis,
  twoFactorCode: () => totp.generate(),
});
```

Token obtido com código 2FA **nunca é reaproveitado do cache**: o SDK não tem como conferir o
código (o segredo fica no sistema Ileva), e servir do cache deixaria entrar quem soubesse só a
senha. Por isso, para usuários com 2FA, cada login vai à API e gera um token novo — o que, pela
regra de um token ativo por usuário, **encerra as outras sessões desse usuário**: se ele entrar pelo
celular, a sessão aberta no computador passa a receber 401 e precisa logar de novo.

Informe `twoFactorCode` só quando o usuário digitou um código. Passar a função sempre faz o SDK
tratar todo usuário como 2FA e ir à API em todo login.

Para integrações automáticas, o recomendado é um usuário de API sem 2FA: com 2FA, cada processo
precisaria de um código novo e o token não seria compartilhado.

## Opções

| Opção | Padrão | Descrição |
|---|---|---|
| `appKey` | — | Menu *Configurações > Integrações > API Integração* no sistema Ileva. |
| `username` | — | Usuário ou e-mail usado para entrar no sistema Ileva. O perfil precisa estar liberado para acesso via API. |
| `password` | — | Senha do usuário no sistema Ileva. |
| `redis` | — | Cliente ioredis (`Redis`/`Cluster`) ou node-redis, já conectado. |
| `store` | — | Implementação própria de `TokenStore`, no lugar de `redis`. |
| `fetch` | `globalThis.fetch` | Implementação de `fetch` (proxy, logs, testes). Usada quando `axios` não é informado. |
| `axios` | — | Instância do axios (`axios` ou `axios.create()`), no lugar do `fetch`. |
| `baseUrl` | `https://api.ileva.com.br` | URL da API. |
| `twoFactorCode` | — | `() => string \| Promise<string>` com o código 2FA. |
| `refreshMarginSeconds` | `300` | Segundos antes de expirar em que o token passa a ser renovado. |
| `timeoutMs` | `15000` | Timeout da requisição de token. |
| `lockWaitMs` | `20000` | Quanto esperar por outro processo que esteja renovando. |
| `keyPrefix` | `ileva:auth` | Prefixo das chaves no Redis. |

## Métodos

Todos devolvem `Promise`.

| Método | Descrição |
|---|---|
| `getToken(): Promise<string>` | Token válido, gerado ou renovado se necessário. |
| `getAuthorizationHeader(): Promise<string>` | `"Bearer <token>"`, pronto para o header `Authorization`. |
| `getTokenDetails(): Promise<Token>` | Token com `expiresAt` (segundos Unix). |
| `invalidate(rejectedToken?: string): Promise<void>` | Descarta o token do cache. |
| `refresh(): Promise<string>` | Gera um token novo mesmo que o atual seja válido. |

## Erros

Todos estendem `IlevaSdkApiV3AuthError`.

| Erro | Quando |
|---|---|
| `AuthenticationError` | A API recusou as credenciais (401): app key inválida, expirada ou desativada, usuário ou senha errados, usuário sem acesso via API liberado no perfil, troca de senha pendente, 2FA ausente ou inválido. A mensagem é a da API. |
| `ApiError` | Outro erro HTTP (400, 429, 5xx) ou resposta fora do formato. O status fica em `status`. |
| `TransportError` | Sem resposta: rede, DNS, TLS ou timeout. O erro original fica em `cause` — com axios, só a mensagem e o `code` dele (veja [Segurança](#segurança)). |
| `LockTimeoutError` | Outro processo estava renovando e o token não apareceu no cache dentro de `lockWaitMs`. |

Erros de conexão com o Redis não são capturados pelo SDK e chegam como o erro do cliente Redis.

## Segurança

A senha e a app key ficam em campos privados (`#`) e não aparecem em `console.log`,
`util.inspect` nem `JSON.stringify` da instância.

A senha nunca é gravada no cache. Junto do token fica um verificador (PBKDF2-SHA256, 100 mil
iterações, salt aleatório), usado para conferir a senha informada. A conferência roda fora do event
loop, custa cerca de 50 ms e é memorizada no processo, uma vez por token.

Com axios, o erro de conexão original (`AxiosError`) não é repassado no `cause` do
`TransportError`: ele carrega o `config` da requisição, com o body e a senha, e apareceria em
qualquer `console.error` ou ferramenta de monitoramento. O `cause` leva só a mensagem e o `code`
(`ECONNREFUSED`, `ETIMEDOUT`...).

## Desenvolvimento

```bash
cd node
npm install
npm test          # os testes de Redis rodam contra 127.0.0.1:6379 e são pulados sem conexão
npm run build
```
