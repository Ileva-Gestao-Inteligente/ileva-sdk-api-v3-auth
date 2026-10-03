# Ileva.SdkApiV3.Auth (.NET)

Autenticação na API Ileva v3: gera o token de acesso a partir da app key, do usuário e da senha e
mantém sua validade, renovando quando está perto de expirar.

Requer .NET 8 ou superior. Para compartilhar o token entre processos, use Redis com
[StackExchange.Redis](https://stackexchange.github.io/StackExchange.Redis/), que o pacote já traz
como dependência: sem Redis, nada é conectado e o token fica em memória.

## Instalação

```bash
dotnet add package Ileva.SdkApiV3.Auth
```

## Uso

```csharp
using Ileva.SdkApiV3.Auth;

var auth = new IlevaSdkApiV3Auth(new IlevaAuthOptions
{
    AppKey = Environment.GetEnvironmentVariable("ILEVA_APP_KEY")!,
    Username = Environment.GetEnvironmentVariable("ILEVA_USUARIO")!,
    Password = Environment.GetEnvironmentVariable("ILEVA_SENHA")!,
    Redis = redis.GetDatabase(), // opcional: IConnectionMultiplexer.GetDatabase()
});

using var request = new HttpRequestMessage(HttpMethod.Get, "https://api.ileva.com.br/regulagem?inicio_paginacao=0&quantidade_por_pagina=5");
request.Headers.TryAddWithoutValidation("Authorization", await auth.GetAuthorizationHeaderAsync()); // "Bearer eyJ..."
var response = await httpClient.SendAsync(request);
```

Instâncias criadas com a mesma app key e o mesmo usuário compartilham o token: enquanto ele não
estiver perto de expirar, nenhuma delas gera outro. Chamadas simultâneas no mesmo processo aguardam
uma única requisição de token. Todos os métodos aceitam um `CancellationToken`.

### Injeção de dependência (ASP.NET)

`AddIlevaAuth` registra o SDK como singleton, para **um** usuário de API:

```csharp
builder.Services.AddSingleton<IConnectionMultiplexer>(ConnectionMultiplexer.Connect(builder.Configuration["Redis"]!)); // opcional

builder.Services.AddIlevaAuth(o =>
{
    o.AppKey = builder.Configuration["Ileva:AppKey"]!;
    o.Username = builder.Configuration["Ileva:Usuario"]!;
    o.Password = builder.Configuration["Ileva:Senha"]!;
});

// Em qualquer classe:
public class MeuServico(IlevaSdkApiV3Auth auth) { /* await auth.GetTokenAsync() */ }
```

O token é guardado, nesta ordem: no `Store` ou `Redis` definidos nas opções; num `ITokenStore`
registrado na aplicação; no `IConnectionMultiplexer` registrado na aplicação, se houver; na memória
do processo. Para dar ao SDK o `HttpClient` da aplicação, use a sobrecarga com o `IServiceProvider`:

```csharp
builder.Services.AddIlevaAuth((provider, o) =>
{
    // ...credenciais
    o.HttpClient = provider.GetRequiredService<IHttpClientFactory>().CreateClient("ileva");
});
```

Para vários usuários (veja [Login dos usuários da aplicação](#login-dos-usuários-da-aplicação)),
crie uma instância por usuário com `new IlevaSdkApiV3Auth(...)`.

### Redis

A opção `Redis` recebe o `IDatabase` do StackExchange.Redis que a aplicação já usa:

```csharp
var redis = await ConnectionMultiplexer.ConnectAsync(Environment.GetEnvironmentVariable("REDIS_URL")!);

var auth = new IlevaSdkApiV3Auth(new IlevaAuthOptions { AppKey = appKey, Username = usuario, Password = senha, Redis = redis.GetDatabase() });
```

O SDK **não** usa o `IDistributedCache` (nem o `AddStackExchangeRedisCache`): ele não tem as
operações atômicas do lock e guarda os valores num formato próprio, que os SDKs de outras linguagens
não leem. O SDK grava o token como texto puro, no formato do
[Contrato do cache](../README.md#contrato-do-cache), e funciona em Redis Cluster.

### Por que Redis

A API mantém **um único token ativo por usuário**: gerar um token novo invalida o anterior. Se cada
processo (cada réplica, cada instância do app) gerasse o seu, eles se derrubariam e passariam a
receber 401.

Com Redis, o token fica num cache compartilhado e a renovação é feita sob lock: só um processo pede
o token e os demais esperam por ele no cache. Isso vale também com os SDKs de PHP, Node e Python:
todos usam as mesmas chaves e o mesmo formato, então aplicações em linguagens diferentes podem
compartilhar o mesmo usuário de API.

Sem `Redis`, o token fica na memória do processo, compartilhado por todas as instâncias dele. Isso
serve apenas para um processo único.

### Vários usuários

Cada combinação de app key e usuário tem seu próprio token, lock e renovação:

```csharp
var joao = new IlevaSdkApiV3Auth(new IlevaAuthOptions { AppKey = "X", Username = "joao", Password = "...", Redis = db });
var maria = new IlevaSdkApiV3Auth(new IlevaAuthOptions { AppKey = "X", Username = "maria", Password = "...", Redis = db });

await joao.GetTokenAsync();  // gera o token do joao
await maria.GetTokenAsync(); // gera o da maria, sem invalidar o do joao
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

```csharp
// Endpoint de login da aplicação (ASP.NET minimal API)
app.MapPost("/login", async (LoginRequest login, IConnectionMultiplexer redis, HttpContext http) =>
{
    var auth = new IlevaSdkApiV3Auth(new IlevaAuthOptions
    {
        AppKey = app.Configuration["Ileva:AppKey"]!,
        Username = login.Usuario,
        Password = login.Senha,
        Redis = redis.GetDatabase(),
        TwoFactorCode = string.IsNullOrEmpty(login.Codigo2fa) ? null : () => login.Codigo2fa,
    });

    try
    {
        var token = await auth.GetTokenDetailsAsync(http.RequestAborted);

        http.Session.SetString("ileva-token", token.AccessToken);
        http.Session.SetString("ileva-token-expira-em", token.ExpiresAt.ToString());
        return Results.Redirect("/");
    }
    catch (IlevaAuthenticationException error)
    {
        // Mensagem da API: senha errada, perfil sem acesso via API, troca de senha pendente, 2FA...
        return Results.Json(new { erro = error.Message }, statusCode: 401);
    }
});

record LoginRequest(string Usuario, string Senha, string? Codigo2fa);
```

Guarde na sessão só o token, nunca a senha do usuário. Quando o token expirar (`ExpiresAt`) ou a API
responder 401, peça o login de novo.

As mensagens de erro vêm da API e podem ser mostradas ao usuário: `Usuário ou senha inválidos`,
`Usuário não autorizado para acesso via API`, `Informe o código de verificação de autenticação de
dois fatores (two_fa)`, entre outras.

Para usuários com 2FA, cada login vai à API e encerra as outras sessões do mesmo usuário (veja
[Autenticação em dois fatores](#autenticação-em-dois-fatores)).

### Quando a API responder 401

Um token pode ser invalidado antes do prazo — por exemplo, se alguém gerar outro token para o mesmo
usuário fora do SDK. Ao receber 401, invalide o token recusado e tente uma vez mais:

```csharp
var token = await auth.GetTokenAsync();
var response = await Send(url, $"Bearer {token}");

if (response.StatusCode == HttpStatusCode.Unauthorized)
{
    await auth.InvalidateAsync(token);
    response = await Send(url, await auth.GetAuthorizationHeaderAsync());
}
```

Passar o token recusado para `InvalidateAsync` importa: se outro processo já tiver gerado um token
novo, ele é preservado, e não é gerado um terceiro.

### Cliente HTTP

A requisição de token usa um `HttpClient` próprio e compartilhado por padrão. Para usar o da
aplicação — com o proxy, os handlers e as políticas de resiliência que ela já configura —, informe
`HttpClient`. O SDK não altera o cliente informado (nem o descarta): o `app_key` vai em cada
requisição, e o timeout é o `Timeout` das opções.

### Autenticação em dois fatores

Se o usuário tiver 2FA, informe uma função que devolva o código no momento da geração do token
(`TwoFactorCode`, ou `TwoFactorCodeAsync` se obter o código for assíncrono):

```csharp
var auth = new IlevaSdkApiV3Auth(new IlevaAuthOptions
{
    AppKey = appKey, Username = usuario, Password = senha, Redis = db,
    TwoFactorCode = () => totp.ComputeTotp(),
});
```

Token obtido com código 2FA **nunca é reaproveitado do cache**: o SDK não tem como conferir o
código (o segredo fica no sistema Ileva), e servir do cache deixaria entrar quem soubesse só a
senha. Por isso, para usuários com 2FA, cada login vai à API e gera um token novo — o que, pela
regra de um token ativo por usuário, **encerra as outras sessões desse usuário**: se ele entrar pelo
celular, a sessão aberta no computador passa a receber 401 e precisa logar de novo.

Informe o código só quando o usuário digitou um. Passar a função sempre faz o SDK tratar todo
usuário como 2FA e ir à API em todo login.

Para integrações automáticas, o recomendado é um usuário de API sem 2FA: com 2FA, cada processo
precisaria de um código novo e o token não seria compartilhado.

## Opções (`IlevaAuthOptions`)

| Opção | Padrão | Descrição |
|---|---|---|
| `AppKey` | — | Menu *Configurações > Integrações > API Integração* no sistema Ileva. |
| `Username` | — | Usuário ou e-mail usado para entrar no sistema Ileva. O perfil precisa estar liberado para acesso via API. |
| `Password` | — | Senha do usuário no sistema Ileva. |
| `Redis` | — | `IDatabase` do StackExchange.Redis, já conectado. |
| `Store` | — | Implementação própria de `ITokenStore`, no lugar de `Redis`. |
| `HttpClient` | cliente próprio | `HttpClient` da aplicação. |
| `BaseUrl` | `https://api.ileva.com.br` | URL da API. |
| `TwoFactorCode` | — | `Func<string>` com o código 2FA. |
| `TwoFactorCodeAsync` | — | `Func<CancellationToken, Task<string>>` com o código 2FA. Informe esta ou a anterior. |
| `RefreshMargin` | `300 s` | Quanto antes de expirar o token passa a ser renovado. |
| `Timeout` | `15 s` | Timeout da requisição de token. |
| `LockWait` | `20 s` | Quanto esperar por outro processo que esteja renovando. |
| `KeyPrefix` | `ileva:auth` | Prefixo das chaves no Redis. |

## Métodos

| Método | Descrição |
|---|---|
| `Task<string> GetTokenAsync(ct)` | Token válido, gerado ou renovado se necessário. |
| `Task<string> GetAuthorizationHeaderAsync(ct)` | `"Bearer <token>"`, pronto para o header `Authorization`. |
| `Task<Token> GetTokenDetailsAsync(ct)` | Token com `ExpiresAt` (segundos Unix). |
| `Task InvalidateAsync(rejectedToken?, ct)` | Descarta o token do cache. |
| `Task<string> RefreshAsync(ct)` | Gera um token novo mesmo que o atual seja válido. |

## Erros

Todos estendem `IlevaSdkApiV3AuthException`.

| Exceção | Quando |
|---|---|
| `IlevaAuthenticationException` | A API recusou as credenciais (401): app key inválida, expirada ou desativada, usuário ou senha errados, usuário sem acesso via API liberado no perfil, troca de senha pendente, 2FA ausente ou inválido. A mensagem é a da API. |
| `IlevaApiException` | Outro erro HTTP (400, 429, 5xx) ou resposta fora do formato. O status fica em `Status`. |
| `IlevaTransportException` | Sem resposta: rede, DNS, TLS ou timeout. O erro original fica em `InnerException`. |
| `IlevaLockTimeoutException` | Outro processo estava renovando e o token não apareceu no cache dentro de `LockWait`. |

Um cancelamento pelo `CancellationToken` do chamador lança `OperationCanceledException`, como de
costume. Erros de conexão com o Redis não são capturados pelo SDK e chegam como o erro do
StackExchange.Redis.

## Segurança

A senha e a app key ficam em campos privados e não aparecem no `ToString()` da instância, das opções
nem do token, nem nas mensagens das exceções do SDK.

A senha nunca é gravada no cache. Junto do token fica um verificador (PBKDF2-SHA256, 100 mil
iterações, salt aleatório), usado para conferir a senha informada. A conferência custa cerca de
50 ms, roda fora da thread do chamador e é memorizada no processo, uma vez por token.

## Desenvolvimento

```bash
cd dotnet
dotnet test    # os testes de Redis rodam contra 127.0.0.1:6379 e são pulados sem conexão
```

Os testes contra a API de verdade (`/outros/estados-listar`) rodam com `ILEVA_APP_KEY`,
`ILEVA_USUARIO`, `ILEVA_SENHA` e, opcionalmente, `ILEVA_BASE_URL` definidos; sem eles são pulados.
Gerar um token invalida o anterior do mesmo usuário: use um usuário de teste.
