# Changelog

Os SDKs são versionados juntos: uma tag `vX.Y.Z` publica todas as linguagens na mesma versão.
O formato segue o [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/) e as versões seguem o
[Versionamento Semântico](https://semver.org/lang/pt-BR/).

## [Não publicado]

### Adicionado

- PHP (`ileva/sdk-api-v3-auth`): geração do token de acesso a partir de app key, usuário e senha,
  com renovação antes de expirar.
- PHP: cache do token em Redis (phpredis ou Predis, por injeção) ou em memória estática no processo.
- PHP: lock de renovação, para que processos concorrentes não invalidem o token uns dos outros.
- PHP: cliente Guzzle por injeção.
- PHP: suporte a autenticação em dois fatores.
- Node 20+ (`@ileva/sdk-api-v3-auth`): mesmas funcionalidades do SDK de PHP, com ESM e CommonJS.
- Node: cache em Redis (ioredis ou node-redis, por injeção) ou em memória no processo.
- Node: requisições com o `fetch` nativo (padrão), outra implementação de `fetch` ou uma instância
  do axios, por injeção.
- Node: chamadas simultâneas no mesmo processo compartilham uma única requisição de token.
- PHP e Node compartilham o mesmo token no mesmo Redis.
- PHP e Node: o token em cache só é devolvido a quem informa a mesma senha que o gerou (verificador
  PBKDF2 gravado junto do token). Permite usar o SDK no login dos usuários da aplicação, com o mesmo
  usuário e senha do sistema Ileva.
- PHP e Node: token obtido com código 2FA nunca é reaproveitado do cache (marca `two_factor`), para
  que quem souber só a senha não entre sem o código.
- Python 3.10+ (`ileva-sdk-api-v3-auth`): mesmas funcionalidades dos SDKs de PHP e Node, sem
  dependências. Requisições com o urllib (padrão), `requests` ou `httpx`, por injeção; cache em
  Redis (redis-py, por injeção) ou em memória no processo, seguro entre threads.
- PHP, Node e Python compartilham o mesmo token no mesmo Redis.
- .NET 8+ (`Ileva.SdkApiV3.Auth`): mesmas funcionalidades dos outros SDKs, com métodos assíncronos e
  `CancellationToken`. Cache em Redis (StackExchange.Redis, `IDatabase` por injeção) ou em memória no
  processo; `HttpClient` por injeção; registro por injeção de dependência (`AddIlevaAuth`).
- PHP, Node, Python e .NET compartilham o mesmo token no mesmo Redis.
- Contrato do cache: a chave usa minúsculas só em ASCII e trim de um conjunto fixo de caracteres,
  para que usuários com acento ou espaços Unicode tenham a mesma chave em todas as linguagens.
