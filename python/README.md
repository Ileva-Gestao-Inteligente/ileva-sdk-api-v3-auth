# ileva-sdk-api-v3-auth (Python)

Autenticação na API Ileva v3: gera o token de acesso a partir da app key, do usuário e da senha e
mantém sua validade, renovando quando está perto de expirar.

Requer Python 3.10+ e não tem dependências: as requisições usam o `urllib` da biblioteca padrão,
ou o `requests`/`httpx` da aplicação. Para compartilhar o token entre processos, use Redis com o
[redis-py](https://github.com/redis/redis-py).

## Instalação

```bash
pip install ileva-sdk-api-v3-auth
pip install "ileva-sdk-api-v3-auth[redis]"   # já instala o redis-py
```

## Uso

```python
import os

import redis
from ileva_sdk_api_v3_auth import IlevaSdkApiV3Auth

auth = IlevaSdkApiV3Auth(
    app_key=os.environ["ILEVA_APP_KEY"],
    username=os.environ["ILEVA_USUARIO"],
    password=os.environ["ILEVA_SENHA"],
    redis=redis.Redis.from_url(os.environ["REDIS_URL"]),
)

headers = {"Authorization": auth.get_authorization_header()}  # "Bearer eyJ..."
```

Instâncias criadas com a mesma app key e o mesmo usuário compartilham o token: enquanto ele não
estiver perto de expirar, nenhuma delas gera outro. Por isso não é preciso guardar a instância —
criar uma nova a cada uso não gera token novo.

### Redis

O `redis` recebe a conexão que a aplicação já usa: `redis.Redis` ou `redis.cluster.RedisCluster`,
com ou sem `decode_responses`.

### Por que Redis

A API mantém **um único token ativo por usuário**: gerar um token novo invalida o anterior. Se
cada processo (cada worker do Gunicorn ou uWSGI, cada worker do Celery, cada réplica) gerasse o
seu, eles se derrubariam e passariam a receber 401.

Com Redis, o token fica num cache compartilhado e a renovação é feita sob lock: só um processo
pede o token e os demais esperam por ele no cache. Isso vale também com os SDKs de PHP e Node: todos
usam as mesmas chaves e o mesmo formato (veja o [Contrato do cache](../README.md#contrato-do-cache)).

Sem `redis`, o token fica na memória do processo, compartilhado por todas as instâncias e threads
dele. Isso serve apenas para um processo único.

### Vários usuários

Cada combinação de app key e usuário tem seu próprio token, lock e renovação:

```python
joao = IlevaSdkApiV3Auth(app_key="X", username="joao", password="...", redis=r)
maria = IlevaSdkApiV3Auth(app_key="X", username="maria", password="...", redis=r)

joao.get_token()   # gera o token do joao
maria.get_token()  # gera o da maria, sem invalidar o do joao
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

```python
from ileva_sdk_api_v3_auth import AuthenticationError, IlevaSdkApiV3Auth

# Rota de login da aplicação (ex.: Flask)
@app.post("/login")
def login():
    codigo = request.form.get("codigo_2fa")
    try:
        auth = IlevaSdkApiV3Auth(
            app_key=os.environ["ILEVA_APP_KEY"],
            username=request.form["usuario"],
            password=request.form["senha"],
            redis=r,
            two_factor_code=(lambda: codigo) if codigo else None,
        )
        token = auth.get_token_details()
    except AuthenticationError as error:
        # Mensagem da API: senha errada, perfil sem acesso via API, troca de senha pendente, 2FA...
        return render_template("login.html", erro=str(error)), 401

    session["ileva_token"] = token.access_token
    session["ileva_token_expira_em"] = token.expires_at
    return redirect("/")
```

Guarde na sessão só o token, nunca a senha do usuário. Quando o token expirar (`expires_at`) ou a
API responder 401, peça o login de novo.

As mensagens de erro vêm da API e podem ser mostradas ao usuário: `Usuário ou senha inválidos`,
`Usuário não autorizado para acesso via API`, `Informe o código de verificação de autenticação de
dois fatores (two_fa)`, entre outras.

Para usuários com 2FA, cada login vai à API e encerra as outras sessões do mesmo usuário (veja
[Autenticação em dois fatores](#autenticação-em-dois-fatores)).

### Quando a API responder 401

Um token pode ser invalidado antes do prazo — por exemplo, se alguém gerar outro token para o mesmo
usuário fora do SDK. Ao receber 401, invalide o token recusado e tente uma vez mais:

```python
token = auth.get_token()
response = session.get(url, headers={"Authorization": f"Bearer {token}"})

if response.status_code == 401:
    auth.invalidate(token)
    response = session.get(url, headers={"Authorization": auth.get_authorization_header()})
```

Passar o token recusado para `invalidate()` importa: se outro processo já tiver gerado um token
novo, ele é preservado, e não é gerado um terceiro.

### Cliente HTTP: urllib, requests ou httpx

A requisição de token usa o `urllib` da biblioteca padrão. Para usar o cliente da aplicação — com
proxy, certificados, retries e hooks que ela já configura —, passe-o em `http_client`:

```python
import requests
auth = IlevaSdkApiV3Auth(app_key, username, password, redis=r, http_client=requests.Session())

import httpx
auth = IlevaSdkApiV3Auth(app_key, username, password, redis=r, http_client=httpx.Client(proxy="http://proxy:3128"))
```

Aceita `requests.Session`, o próprio módulo `requests` e `httpx.Client` (síncrono). O SDK não
depende de nenhum deles: usa o que você informar. O timeout da requisição de token é o
`timeout_seconds`, e respostas de erro (4xx, 5xx) são lidas normalmente, sem depender de
`raise_for_status`.

### Autenticação em dois fatores

Se o usuário tiver 2FA, informe uma função que devolva o código no momento da geração do token:

```python
auth = IlevaSdkApiV3Auth(app_key, username, password, redis=r, two_factor_code=lambda: totp.now())
```

Token obtido com código 2FA **nunca é reaproveitado do cache**: o SDK não tem como conferir o
código (o segredo fica no sistema Ileva), e servir do cache deixaria entrar quem soubesse só a
senha. Por isso, para usuários com 2FA, cada login vai à API e gera um token novo — o que, pela
regra de um token ativo por usuário, **encerra as outras sessões desse usuário**: se ele entrar pelo
celular, a sessão aberta no computador passa a receber 401 e precisa logar de novo.

Informe `two_factor_code` só quando o usuário digitou um código. Passar a função sempre faz o SDK
tratar todo usuário como 2FA e ir à API em todo login.

Para integrações automáticas, o recomendado é um usuário de API sem 2FA: com 2FA, cada processo
precisaria de um código novo e o token não seria compartilhado.

## Opções

Os três primeiros podem ser posicionais; os demais são só nomeados.

| Parâmetro | Padrão | Descrição |
|---|---|---|
| `app_key` | — | Menu *Configurações > Integrações > API Integração* no sistema Ileva. |
| `username` | — | Usuário ou e-mail usado para entrar no sistema Ileva. O perfil precisa estar liberado para acesso via API. |
| `password` | — | Senha do usuário no sistema Ileva. |
| `redis` | `None` | Conexão do redis-py (`redis.Redis` ou `RedisCluster`). |
| `store` | `None` | Implementação própria de `TokenStore`, no lugar de `redis`. |
| `http_client` | urllib | `requests.Session`, módulo `requests` ou `httpx.Client`. |
| `base_url` | `https://api.ileva.com.br` | URL da API. |
| `two_factor_code` | `None` | Função sem argumentos que devolve o código 2FA. |
| `refresh_margin_seconds` | `300` | Segundos antes de expirar em que o token passa a ser renovado. |
| `timeout_seconds` | `15.0` | Timeout da requisição de token. |
| `lock_wait_seconds` | `20.0` | Quanto esperar por outro processo que esteja renovando. |
| `key_prefix` | `ileva:auth` | Prefixo das chaves no Redis. |

## Métodos

| Método | Descrição |
|---|---|
| `get_token() -> str` | Token válido, gerado ou renovado se necessário. |
| `get_authorization_header() -> str` | `"Bearer <token>"`, pronto para o header `Authorization`. |
| `get_token_details() -> Token` | Token com `expires_at` (segundos Unix). |
| `invalidate(rejected_token=None)` | Descarta o token do cache. |
| `refresh() -> str` | Gera um token novo mesmo que o atual seja válido. |

## Erros

Todos estendem `IlevaSdkApiV3AuthError`.

| Erro | Quando |
|---|---|
| `AuthenticationError` | A API recusou as credenciais (401): app key inválida, expirada ou desativada, usuário ou senha errados, usuário sem acesso via API liberado no perfil, troca de senha pendente, 2FA ausente ou inválido. A mensagem é a da API. |
| `ApiError` | Outro erro HTTP (400, 429, 5xx) ou resposta fora do formato. O status fica em `status`. |
| `TransportError` | Sem resposta: rede, DNS, TLS ou timeout. A mensagem traz o tipo e a descrição do erro original (veja [Segurança](#segurança)). |
| `LockTimeoutError` | Outro processo estava renovando e o token não apareceu no cache dentro de `lock_wait_seconds`. |

Configuração inválida (credenciais vazias, `redis` e `store` juntos) lança `ValueError`; cliente
HTTP ou Redis não suportado, `TypeError`. Erros de conexão com o Redis não são capturados pelo SDK.

## Segurança

- A senha e a app key não aparecem em `repr()`, `str()`, `vars()` nem em logs da instância.
- O erro original do cliente HTTP não é encadeado no `TransportError` (`__cause__`/`__context__`):
  o de requests e httpx carrega a requisição, com o body e a senha. E nenhum frame ativo no momento
  do erro guarda a senha em variável local — ferramentas como o Sentry capturam as variáveis locais
  do traceback.
- A senha nunca é gravada no cache. Junto do token fica um verificador (PBKDF2-SHA256, 100 mil
  iterações, salt aleatório), usado para conferir a senha informada. A conferência é memorizada no
  processo, uma vez por token.

## Desenvolvimento

```bash
cd python
python -m venv .venv
.venv/bin/pip install -e ".[test]"     # no Windows: .venv\Scripts\pip
.venv/bin/pytest                        # os testes de Redis rodam contra 127.0.0.1:6379 e são pulados sem conexão
```
