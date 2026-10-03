# ileva/sdk-api-v3-auth (PHP)

Autenticação na API Ileva v3: gera o token de acesso a partir da app key, do usuário e da senha e
mantém sua validade, renovando quando está perto de expirar.

Requer PHP 8.1+ e Guzzle 7. Para compartilhar o token entre processos, use Redis com
`ext-redis` (phpredis) ou `predis/predis`.

## Instalação

```bash
composer require ileva/sdk-api-v3-auth
```

## Uso

```php
use GuzzleHttp\Client;
use Ileva\SdkApiV3\Auth\IlevaSdkApiV3Auth;

$redis = new Redis();
$redis->connect('127.0.0.1', 6379);

$auth = new IlevaSdkApiV3Auth(
    appKey: getenv('ILEVA_APP_KEY'),
    username: getenv('ILEVA_USUARIO'),
    password: getenv('ILEVA_SENHA'),
    redis: $redis,
    guzzle: new Client(),
);

$headers = [
    'Authorization' => $auth->getAuthorizationHeader(), // "Bearer eyJ..."
];
```

Instâncias criadas com a mesma app key e o mesmo usuário compartilham o token: enquanto ele não
estiver perto de expirar, nenhuma delas gera outro. Por isso não é preciso guardar a instância —
criar uma nova a cada uso não gera token novo.

### Vários usuários

Cada combinação de app key e usuário tem seu próprio token, lock e renovação. Usuários da mesma
app key não interferem um no outro:

```php
$joao  = new IlevaSdkApiV3Auth(appKey: 'X', username: 'joao',  password: '...', redis: $redis);
$maria = new IlevaSdkApiV3Auth(appKey: 'X', username: 'maria', password: '...', redis: $redis);

$joao->getToken();  // gera o token do joao
$maria->getToken(); // gera o da maria, sem invalidar o do joao
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

```php
use Ileva\SdkApiV3\Auth\Exception\AuthenticationException;
use Ileva\SdkApiV3\Auth\IlevaSdkApiV3Auth;

// Tela de login da aplicação
try {
    $auth = new IlevaSdkApiV3Auth(
        appKey: getenv('ILEVA_APP_KEY'),
        username: $_POST['usuario'],
        password: $_POST['senha'],
        redis: $redis,
        twoFactorCode: isset($_POST['codigo_2fa']) ? fn () => $_POST['codigo_2fa'] : null,
    );
    $token = $auth->getTokenDetails();

    $_SESSION['ileva_token'] = $token->accessToken;
    $_SESSION['ileva_token_expira_em'] = $token->expiresAt;
} catch (AuthenticationException $e) {
    // Mensagem da API: senha errada, perfil sem acesso via API, troca de senha pendente, 2FA...
    $erro = $e->getMessage();
}
```

Guarde na sessão só o token, nunca a senha do usuário. Quando o token expirar (`expiresAt`) ou a API
responder 401, peça o login de novo.

As mensagens de erro vêm da API e podem ser mostradas ao usuário: `Usuário ou senha inválidos`,
`Usuário não autorizado para acesso via API`, `Informe o código de verificação de autenticação de
dois fatores (two_fa)`, entre outras.

Para usuários com 2FA, cada login vai à API e encerra as outras sessões do mesmo usuário (veja
[Autenticação em dois fatores](#autenticação-em-dois-fatores)).

O `guzzle` recebe o cliente Guzzle da aplicação (`GuzzleHttp\ClientInterface`), com os proxies,
middlewares de log e handlers que ela já usa. Sem ele, o SDK cria um `GuzzleHttp\Client` padrão.
As opções `timeout`, `connect_timeout` e `http_errors` são definidas pelo SDK na requisição de token.

O `redis` recebe a conexão que a aplicação já usa: `\Redis`, `\RedisCluster` ou
`\Predis\ClientInterface`. Com Predis:

```php
$auth = new IlevaSdkApiV3Auth(
    appKey: '...',
    username: '...',
    password: '...',
    redis: new Predis\Client('tcp://127.0.0.1:6379'),
);
```

No Laravel, com o driver phpredis, passe a conexão nativa:
`redis: Illuminate\Support\Facades\Redis::connection()->client()`.

### Por que Redis

A API mantém **um único token ativo por usuário**: gerar um token novo invalida o anterior. Se
cada processo (cada requisição no PHP-FPM, cada worker de fila) gerasse o seu, eles se
derrubariam e passariam a receber 401.

Com Redis, o token fica num cache compartilhado e a renovação é feita sob lock: só um processo
pede o token e os demais esperam por ele no cache. Isso vale também entre linguagens — os SDKs de
PHP e Node usam as mesmas chaves e o mesmo formato (veja o [Contrato do cache](../README.md#contrato-do-cache)).

Sem `redis`, os tokens ficam numa lista estática dentro do SDK, compartilhada por todas as
instâncias do processo. Isso serve apenas para um processo único e de vida longa (um
worker, um script CLI). No PHP-FPM a memória não passa de uma requisição para outra, então cada
requisição geraria um token novo — use Redis.

### Quando a API responder 401

Um token pode ser invalidado antes do prazo — por exemplo, se alguém gerar outro token para o mesmo
usuário fora do SDK. Ao receber 401 numa chamada à API, invalide o token recusado e tente uma vez
mais:

```php
$token = $auth->getToken();
$response = $http->get($url, ['Authorization' => "Bearer $token"]);

if ($response->status === 401) {
    $auth->invalidate($token);
    $response = $http->get($url, ['Authorization' => $auth->getAuthorizationHeader()]);
}
```

Passar o token recusado para `invalidate()` importa: se outro processo já tiver gerado um token
novo, ele é preservado, e não é gerado um terceiro.

### Autenticação em dois fatores

Se o usuário tiver 2FA, informe uma função que devolva o código no momento da geração do token:

```php
$auth = new IlevaSdkApiV3Auth(
    appKey: '...',
    username: '...',
    password: '...',
    redis: $redis,
    twoFactorCode: fn () => $totp->now(),
);
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

## Opções do construtor

| Parâmetro | Padrão | Descrição |
|---|---|---|
| `appKey` | — | Menu *Configurações > Integrações > API Integração* no sistema Ileva. |
| `username` | — | Usuário ou e-mail usado para entrar no sistema Ileva. O perfil precisa estar liberado para acesso via API. |
| `password` | — | Senha do usuário no sistema Ileva. |
| `redis` | `null` | Conexão Redis (`\Redis`, `\RedisCluster` ou `\Predis\ClientInterface`). |
| `guzzle` | `new GuzzleHttp\Client()` | Cliente Guzzle da aplicação (`GuzzleHttp\ClientInterface`). |
| `store` | `null` | Implementação própria de `TokenStore`, no lugar de `redis`. |
| `baseUrl` | `https://api.ileva.com.br` | URL da API. |
| `twoFactorCode` | `null` | `Closure(): string` com o código 2FA. |
| `refreshMargin` | `300` | Segundos antes de expirar em que o token passa a ser renovado. |
| `timeout` | `15.0` | Timeout da requisição de token, em segundos. |
| `lockWait` | `20.0` | Quanto esperar, em segundos, por outro processo que esteja renovando. |
| `keyPrefix` | `ileva:auth` | Prefixo das chaves no Redis. |

## Métodos

| Método | Descrição |
|---|---|
| `getToken(): string` | Token válido, gerado ou renovado se necessário. |
| `getAuthorizationHeader(): string` | `"Bearer <token>"`, pronto para o header `Authorization`. |
| `getTokenDetails(): Token` | Token com `expiresAt` (segundos Unix). |
| `invalidate(?string $rejectedToken = null): void` | Descarta o token do cache. |
| `refresh(): string` | Gera um token novo mesmo que o atual seja válido. |

## Exceções

Todas estendem `Ileva\SdkApiV3\Auth\Exception\IlevaSdkApiV3AuthException`.

| Exceção | Quando |
|---|---|
| `AuthenticationException` | A API recusou as credenciais (401): app key inválida, expirada ou desativada, usuário ou senha errados, usuário sem acesso via API liberado no perfil, troca de senha pendente, 2FA ausente ou inválido. A mensagem é a da API. |
| `ApiException` | Outro erro HTTP (400, 429, 5xx) ou resposta fora do formato. O código é o status HTTP. |
| `TransportException` | Sem resposta: rede, DNS, TLS ou timeout. A exceção do Guzzle fica em `getPrevious()`. |
| `LockTimeoutException` | Outro processo estava renovando e o token não apareceu no cache dentro de `lockWait`. |

Erros de conexão com o Redis não são capturados pelo SDK e chegam como a exceção do cliente Redis.

## Segurança

A senha e a app key não aparecem em `var_dump`/`print_r` da instância nem nos argumentos do trace
das exceções do SDK, que ferramentas como o Sentry costumam enviar.

A senha nunca é gravada no cache. Junto do token fica um verificador (PBKDF2-SHA256, 100 mil
iterações, salt aleatório), usado para conferir a senha informada. A conferência custa cerca de
150 ms e é memorizada no processo — no PHP-FPM, o worker a faz uma vez por token.

No PHP 8.1 há uma exceção: se o próprio construtor lançar erro (por exemplo, por uma conexão Redis
inválida), o trace dele pode conter a senha quando `zend.exception_ignore_args` estiver desligado.
No PHP 8.2+ o parâmetro é marcado com `#[\SensitiveParameter]` e fica oculto. Em produção, mantenha
`zend.exception_ignore_args = On`, que já é o padrão do `php.ini-production`.

A conexão phpredis não pode usar `OPT_SERIALIZER` nem `OPT_COMPRESSION`, para que o valor gravado
siga o [contrato do cache](../README.md#contrato-do-cache) compartilhado com os SDKs das outras
linguagens. O `RedisTokenStore` recusa uma conexão configurada assim.

## Testes

Na raiz do repositório:

```bash
composer install
composer test
```

Os testes do `RedisTokenStore` rodam contra o Redis em `ILEVA_TEST_REDIS_HOST`/`ILEVA_TEST_REDIS_PORT`
(padrão `127.0.0.1:6379`) e são pulados se não houver conexão.
