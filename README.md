# Ileva SDK API v3 — Autenticação

SDKs para autenticar na [API Ileva v3](https://api.ileva.com.br/): geram o token de acesso a partir
da app key, do usuário e da senha e mantêm sua validade, renovando antes de expirar.

| Linguagem | Pacote | Situação |
|---|---|---|
| PHP 8.1+ | [`ileva/sdk-api-v3-auth`](php/README.md) | Disponível |
| Node.js 20+ | [`@ileva/sdk-api-v3-auth`](node/README.md) | Disponível |
| Python 3.10+ | [`ileva-sdk-api-v3-auth`](python/README.md) | Disponível |
| .NET 8+ | [`Ileva.SdkApiV3.Auth`](dotnet/README.md) | Disponível |

## Login com o usuário do sistema Ileva

Com o SDK, a aplicação final pode oferecer aos seus usuários o mesmo login que eles já usam para
entrar no sistema Ileva: **usuário (ou e-mail) e senha**. O SDK troca essas credenciais pelo token
da API, e as chamadas feitas com esse token respeitam as permissões que o usuário tem no sistema.

> **O perfil do usuário precisa estar liberado para acesso via API.** No sistema Ileva, em
> *Administração > Usuários do sistema*, edite o usuário e, no painel **Permissões**, ligue
> **API de integração** em **Permitir acesso via**. Sem isso, o login é recusado com
> `Usuário não autorizado para acesso via API`, mesmo com usuário e senha corretos. A opção só
> aparece para quem tem permissão de alterar as permissões de usuários.

- **App key:** identifica a associação e é configurada pela aplicação, não digitada pelo usuário.
- **2FA:** se o usuário tiver autenticação em dois fatores, a tela de login pede o código e a
  aplicação o repassa ao SDK. Token obtido com 2FA nunca é reaproveitado do cache: cada login vai à
  API, e por isso encerra as outras sessões desse usuário.
- **Senha conferida sempre:** o token em cache só é devolvido a quem informa a mesma senha que o
  gerou. Uma senha errada vai à API e é recusada, e o token de quem acertou continua valendo.

Exemplos de tela de login em [PHP](php/README.md#login-dos-usuários-da-aplicação),
[Node.js](node/README.md#login-dos-usuários-da-aplicação),
[Python](python/README.md#login-dos-usuários-da-aplicação) e
[.NET](dotnet/README.md#login-dos-usuários-da-aplicação).

## Exemplo (PHP)

```bash
composer require ileva/sdk-api-v3-auth
```

```php
use Ileva\SdkApiV3\Auth\IlevaSdkApiV3Auth;

$auth = new IlevaSdkApiV3Auth(
    appKey: getenv('ILEVA_APP_KEY'),
    username: getenv('ILEVA_USUARIO'),
    password: getenv('ILEVA_SENHA'),
    redis: $redis, // opcional: \Redis, \RedisCluster ou \Predis\ClientInterface
);

$authorization = $auth->getAuthorizationHeader(); // "Bearer eyJ..."
```

Documentação completa em [php/README.md](php/README.md).

## Exemplo (Node.js)

```bash
npm install @ileva/sdk-api-v3-auth
```

```js
import { IlevaSdkApiV3Auth } from '@ileva/sdk-api-v3-auth';

const auth = new IlevaSdkApiV3Auth({
  appKey: process.env.ILEVA_APP_KEY,
  username: process.env.ILEVA_USUARIO,
  password: process.env.ILEVA_SENHA,
  redis, // opcional: cliente ioredis ou node-redis
});

const authorization = await auth.getAuthorizationHeader(); // "Bearer eyJ..."
```

Documentação completa em [node/README.md](node/README.md).

## Exemplo (Python)

```bash
pip install ileva-sdk-api-v3-auth
```

```python
from ileva_sdk_api_v3_auth import IlevaSdkApiV3Auth

auth = IlevaSdkApiV3Auth(
    app_key=os.environ["ILEVA_APP_KEY"],
    username=os.environ["ILEVA_USUARIO"],
    password=os.environ["ILEVA_SENHA"],
    redis=r,  # opcional: redis.Redis ou RedisCluster (redis-py)
)

authorization = auth.get_authorization_header()  # "Bearer eyJ..."
```

Documentação completa em [python/README.md](python/README.md).

## Exemplo (.NET)

```bash
dotnet add package Ileva.SdkApiV3.Auth
```

```csharp
using Ileva.SdkApiV3.Auth;

var auth = new IlevaSdkApiV3Auth(new IlevaAuthOptions
{
    AppKey = Environment.GetEnvironmentVariable("ILEVA_APP_KEY")!,
    Username = Environment.GetEnvironmentVariable("ILEVA_USUARIO")!,
    Password = Environment.GetEnvironmentVariable("ILEVA_SENHA")!,
    Redis = redis.GetDatabase(), // opcional: IDatabase do StackExchange.Redis
});

var authorization = await auth.GetAuthorizationHeaderAsync(); // "Bearer eyJ..."
```

Documentação completa em [dotnet/README.md](dotnet/README.md).

## Por que o token precisa ser compartilhado

A API mantém **um único token ativo por usuário**: gerar um token novo invalida o anterior. Se cada
processo da aplicação gerasse o seu, eles se derrubariam e passariam a receber 401.

Os SDKs guardam o token em cache — Redis, informado por injeção, ou memória do processo — e só
geram outro quando ele está perto de expirar. A renovação é feita sob lock: só um processo pede o
token e os outros esperam por ele no cache. Cada combinação de app key e usuário tem seu próprio
token, então vários usuários da mesma app key não interferem um no outro.

Como os SDKs seguem o mesmo contrato de cache, aplicações em PHP, Node, Python e .NET apontando
para o mesmo Redis também compartilham o token.

## Contrato do cache

Todos os SDKs seguem este contrato, para que serviços em linguagens diferentes compartilhem o mesmo
token no mesmo Redis.

**Chaves**

```
hash  = sha256_hex( lower(baseUrl sem "/" final) + "\n" + appKey + "\n" + lower(trim(username)) )
token = "{keyPrefix}:token:{hash}"
lock  = "{keyPrefix}:lock:{hash}"
```

- `lower`: só as letras ASCII `A`–`Z` viram `a`–`z`. Letras acentuadas e outros caracteres ficam
  como estão — as funções de minúsculas de cada linguagem divergem fora do ASCII.
- `trim`: remove do início e do fim só os caracteres espaço, `\t`, `\n`, `\r`, `\v` (0x0B) e `\0`.
  Espaços Unicode (como o `\u00a0`) não são removidos.
- `sha256_hex` é calculado sobre o texto em UTF-8.

O `keyPrefix` padrão é `ileva:auth`. A senha não faz parte da chave: ela é conferida pelo
`password_check` gravado junto do token.

**Valor do token**: JSON em texto puro (sem serialização própria da linguagem), com TTL até
`expires_at`.

```json
{"access_token":"eyJ...","token_type":"Bearer","expires_at":1790000000,"password_check":"pbkdf2-sha256$100000$<salt>$<hash>"}
```

**Verificador da senha** (`password_check`): `pbkdf2-sha256$<iterações>$<salt>$<hash>`, com PBKDF2
HMAC-SHA256 sobre a senha em UTF-8, salt aleatório de 16 bytes, hash de 32 bytes, os dois em base64
padrão com `=`. Quem grava usa 100000 iterações. Quem lê só devolve o token se a senha informada
produzir o mesmo hash (comparação em tempo constante); caso contrário, age como se o cache estivesse
vazio e consulta a API. Token sem `password_check`, com outro algoritmo, fora do formato ou com mais
de 1000000 iterações conta como senha diferente. Nunca grave a senha no cache.

**Marca de 2FA** (`two_factor`): `true` quando o token foi obtido com código de autenticação em dois
fatores; ausente nos demais. Quem lê **nunca devolve** um token marcado — age como se o cache
estivesse vazio e consulta a API com o código informado, já que só a API consegue conferir o
código. O token marcado continua sendo gravado, para substituir o anterior do usuário (que a API
invalidou ao gerar o novo). No Node, chamadas com código 2FA também não compartilham a requisição
de token em andamento.

`expires_at` é em segundos Unix, calculado como o instante do envio da requisição mais o
`expires_in` devolvido pela API. O token é tratado como vencido `refreshMargin` segundos antes
(padrão: 300).

**Lock**: `SET {lock} <id aleatório> NX PX <(timeout + 5s) em ms>`. É liberado com um script Lua que
só apaga a chave se o valor ainda for o id de quem a obteve:

```lua
if redis.call('GET', KEYS[1]) == ARGV[1] then
    return redis.call('DEL', KEYS[1])
end
return 0
```

Quem não obtém o lock consulta o token a cada 100 ms até ele aparecer, até o limite de `lockWait`
(padrão: 20 s).

**Invalidação**: script Lua que apaga o token só se o `access_token` guardado for o recusado — ou
sempre, sem token informado. Um valor que não é JSON válido também é apagado.

```lua
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
```

## Versionamento

Os SDKs são versionados juntos: uma tag `vX.Y.Z` publica todas as linguagens na mesma versão. As
mudanças ficam no [CHANGELOG](CHANGELOG.md).

## Segurança

Para reportar uma vulnerabilidade, veja [SECURITY.md](SECURITY.md).

## Licença

[MIT](LICENSE)
