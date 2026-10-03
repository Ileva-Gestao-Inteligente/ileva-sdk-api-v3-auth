from __future__ import annotations

import hashlib
import json
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest

from ileva_sdk_api_v3_auth import (
    ApiError,
    AuthenticationError,
    IlevaSdkApiV3Auth,
    InMemoryTokenStore,
    LockTimeoutError,
    Token,
    TransportError,
)

#: Verificador da senha "segredo" gerado com salt fixo (16 bytes 0x01). Os SDKs de PHP e Node testam
#: o mesmo valor: todos precisam aceitar o verificador gravado pelos outros.
SEGREDO_CHECK = "pbkdf2-sha256$100000$AQEBAQEBAQEBAQEBAQEBAQ==$MC4obyTDiJ9/piZiz+KFtXeenFNNoJQjr5MSPiDBgxM="

HASH = hashlib.sha256(b"https://api.teste\napp-key\nintegracao").hexdigest()
TOKEN_KEY = f"ileva:auth:token:{HASH}"
LOCK_KEY = f"ileva:auth:lock:{HASH}"


def now() -> int:
    return int(time.time())


class FakeApi:
    """API falsa via httpx.MockTransport: devolve as respostas enfileiradas e registra as requisições."""

    def __init__(self) -> None:
        self.requests: list[dict] = []
        self._responses: list = []
        self._lock = threading.Lock()
        self.client = httpx.Client(transport=httpx.MockTransport(self._handle))

    def token(self, access_token: str, expires_in: int = 86400, delay: float = 0) -> FakeApi:
        return self.json(200, {"access_token": access_token, "token_type": "Bearer", "expires_in": expires_in}, delay)

    def json(self, status: int, body, delay: float = 0) -> FakeApi:
        content = body if isinstance(body, str) else json.dumps(body)
        self._responses.append((status, content, delay))
        return self

    def _handle(self, request: httpx.Request) -> httpx.Response:
        with self._lock:
            self.requests.append({"url": str(request.url), "headers": request.headers, "body": json.loads(request.content)})
            if not self._responses:
                raise AssertionError("Requisição de token inesperada.")
            status, content, delay = self._responses.pop(0)
        if delay:
            time.sleep(delay)
        return httpx.Response(status, content=content)


@pytest.fixture
def api() -> FakeApi:
    return FakeApi()


@pytest.fixture
def store() -> InMemoryTokenStore:
    return InMemoryTokenStore()


@pytest.fixture
def auth(api):
    def make(**options) -> IlevaSdkApiV3Auth:
        params = {
            "app_key": "app-key",
            "username": "integracao",
            "password": "segredo",
            "http_client": api.client,
            "base_url": "https://api.teste/",
            **options,
        }
        return IlevaSdkApiV3Auth(**params)

    return make


def seed(store, token: Token, ttl: int, password_check: str | None = SEGREDO_CHECK) -> None:
    """Grava um token no cache como o SDK grava: com o verificador da senha "segredo"."""
    store.set(TOKEN_KEY, token.to_json(password_check), ttl)


def test_gera_token_com_app_key_no_header_e_credenciais_no_body(api, auth):
    api.token("tok-1")

    assert auth().get_token() == "tok-1"

    assert len(api.requests) == 1
    request = api.requests[0]
    assert request["url"] == "https://api.teste/oauth/token"
    assert request["headers"]["app_key"] == "app-key"
    assert request["headers"]["content-type"] == "application/json"
    assert request["body"] == {"username": "integracao", "password": "segredo"}


def test_instancias_com_as_mesmas_credenciais_compartilham_o_token(api, auth):
    api.token("tok-1")
    auth().get_token()

    outra = auth()
    assert outra.get_token() == "tok-1"
    assert outra.get_authorization_header() == "Bearer tok-1"
    assert len(api.requests) == 1


def test_threads_simultaneas_geram_um_unico_token(api, auth):
    api.token("tok-1", delay=0.2)

    with ThreadPoolExecutor(max_workers=10) as pool:
        tokens = list(pool.map(lambda _: auth().get_token(), range(10)))

    assert set(tokens) == {"tok-1"}
    assert len(api.requests) == 1


def test_usuarios_da_mesma_app_key_tem_tokens_independentes(api, auth):
    api.token("tok-joao").token("tok-maria")

    assert auth(username="joao").get_token() == "tok-joao"
    assert auth(username="maria").get_token() == "tok-maria"
    assert auth(username="joao").get_token() == "tok-joao"
    assert auth(username="maria").get_token() == "tok-maria"
    assert len(api.requests) == 2


def test_invalidar_um_usuario_nao_afeta_outro(api, auth):
    api.token("tok-joao").token("tok-maria").token("tok-joao-2")
    joao, maria = auth(username="joao"), auth(username="maria")
    joao.get_token()
    maria.get_token()

    joao.invalidate()

    assert maria.get_token() == "tok-maria"
    assert joao.get_token() == "tok-joao-2"
    assert len(api.requests) == 3


def test_mesmo_usuario_em_app_keys_diferentes_tem_tokens_independentes(api, auth):
    api.token("tok-a").token("tok-b")

    assert auth(app_key="associacao-a").get_token() == "tok-a"
    assert auth(app_key="associacao-b").get_token() == "tok-b"
    assert auth(app_key="associacao-a").get_token() == "tok-a"
    assert len(api.requests) == 2


def test_chave_ignora_caixa_ascii_do_usuario_e_barra_final_da_url(api, auth, store):
    api.token("tok-1")
    auth().get_token()

    assert store.get(TOKEN_KEY) is not None
    assert auth(username=" Integracao\t", base_url="https://api.teste").get_token() == "tok-1"
    assert len(api.requests) == 1


def test_chave_usa_minusculas_so_em_ascii_como_os_outros_sdks(api, auth, store):
    # "Ã" não vira "ã": lower() do Python, toLowerCase() do JS e strtolower() do PHP divergem fora
    # do ASCII, e a chave precisa ser igual em todos.
    api.token("tok-1")
    auth(username=" JOÃO ").get_token()

    key = "ileva:auth:token:" + hashlib.sha256("https://api.teste\napp-key\njoÃo".encode()).hexdigest()
    assert store.get(key) is not None


def test_grava_no_cache_no_formato_compartilhado_com_os_outros_sdks(api, auth, store):
    api.token("tok-1", expires_in=3600)
    before = now()

    auth().get_token()

    stored = json.loads(store.get(TOKEN_KEY))
    assert stored["access_token"] == "tok-1"
    assert stored["token_type"] == "Bearer"
    assert before + 3600 <= stored["expires_at"] <= now() + 3600
    assert list(stored) == ["access_token", "token_type", "expires_at", "password_check"]


def test_le_o_token_gravado_pelo_sdk_de_php(api, auth, store):
    # Mesmo JSON que o Token::toJson() do PHP grava.
    store.set(
        TOKEN_KEY,
        f'{{"access_token":"do-php","token_type":"Bearer","expires_at":{now() + 3600},"password_check":"{SEGREDO_CHECK}"}}',
        3600,
    )

    assert auth().get_token() == "do-php"
    assert api.requests == []


def test_renova_dentro_da_margem_de_renovacao(api, auth, store):
    seed(store, Token("velho", "Bearer", now() + 200), 200)
    api.token("novo")

    assert auth(refresh_margin_seconds=300).get_token() == "novo"


def test_usa_token_fora_da_margem_de_renovacao(api, auth, store):
    seed(store, Token("atual", "Bearer", now() + 400), 400)

    assert auth(refresh_margin_seconds=300).get_token() == "atual"
    assert api.requests == []


def test_valor_corrompido_no_cache_e_tratado_como_vazio(api, auth, store):
    store.set(TOKEN_KEY, "nao-e-json", 60)
    api.token("tok-1")

    assert auth().get_token() == "tok-1"


def test_invalidate_com_token_recusado_preserva_o_token_novo_de_outro_processo(api, auth, store):
    seed(store, Token("novo", "Bearer", now() + 3600), 3600)
    instance = auth()

    instance.invalidate("velho")

    assert instance.get_token() == "novo"
    assert api.requests == []


def test_invalidate_com_o_token_atual_forca_nova_geracao(api, auth):
    api.token("tok-1").token("tok-2")
    instance = auth()

    instance.invalidate(instance.get_token())

    assert instance.get_token() == "tok-2"


def test_refresh_gera_token_mesmo_com_token_valido(api, auth):
    api.token("tok-1").token("tok-2")
    instance = auth()
    instance.get_token()

    assert instance.refresh() == "tok-2"


# ---------------------------------------------------------------------------- senha

def test_senha_errada_com_token_em_cache_consulta_a_api_e_recebe_401(api, auth):
    api.token("tok-certo")
    auth().get_token()
    api.json(401, {"status": 401, "mensagem": "Usuário ou senha inválidos"})

    with pytest.raises(AuthenticationError, match="Usuário ou senha inválidos"):
        auth(password="errada").get_token()

    # A senha errada foi à API; o token de quem acertou continua no cache.
    assert len(api.requests) == 2
    assert api.requests[1]["body"]["password"] == "errada"
    assert auth().get_token() == "tok-certo"
    assert len(api.requests) == 2


def test_senha_errada_nao_aproveita_a_conferencia_memorizada_da_senha_certa(api, auth):
    api.token("tok-certo")
    auth().get_token()
    assert auth().get_token() == "tok-certo"  # conferência memorizada no processo
    api.json(401, {"status": 401, "mensagem": "Usuário ou senha inválidos"})

    with pytest.raises(AuthenticationError):
        auth(password="errada").get_token()


def test_senha_errada_em_thread_simultanea_nao_recebe_o_token_de_quem_acertou(api, auth):
    api.token("tok-certo", delay=0.2).json(401, {"status": 401, "mensagem": "Usuário ou senha inválidos"})

    with ThreadPoolExecutor(max_workers=2) as pool:
        certo = pool.submit(auth().get_token)
        time.sleep(0.05)  # a requisição da senha certa já está em andamento
        errado = pool.submit(auth(password="errada").get_token)

        assert certo.result() == "tok-certo"
        with pytest.raises(AuthenticationError):
            errado.result()


def test_aceita_o_verificador_gravado_pelos_outros_sdks(api, auth, store):
    seed(store, Token("de-outro-sdk", "Bearer", now() + 3600), 3600, SEGREDO_CHECK)

    assert auth().get_token() == "de-outro-sdk"
    assert api.requests == []


def test_token_sem_verificador_e_tratado_como_cache_vazio(api, auth, store):
    seed(store, Token("sem-verificador", "Bearer", now() + 3600), 3600, None)
    api.token("tok-novo")

    assert auth().get_token() == "tok-novo"


@pytest.mark.parametrize("check", [
    "pbkdf2-sha256$99999999$AQEBAQEBAQEBAQEBAQEBAQ==$MC4obyTDiJ9/piZiz+KFtXeenFNNoJQjr5MSPiDBgxM=",
    "md5$1$AQ==$AQ==",
    "pbkdf2-sha256$100000$@@@$AQ==",
    "pbkdf2-sha256$²$AQ==$AQ==",
    "lixo",
])
def test_verificador_adulterado_e_tratado_como_senha_diferente(api, auth, store, check):
    seed(store, Token("adulterado", "Bearer", now() + 3600), 3600, check)
    api.token("tok-novo")

    assert auth().get_token() == "tok-novo"


def test_senha_nova_correta_substitui_o_token_gerado_com_a_senha_antiga(api, auth):
    api.token("tok-senha-antiga").token("tok-senha-nova")
    auth(password="antiga").get_token()

    assert auth(password="nova").get_token() == "tok-senha-nova"
    assert auth(password="nova").get_token() == "tok-senha-nova"
    assert len(api.requests) == 2


def test_o_cache_nao_guarda_a_senha(api, auth, store):
    api.token("tok-1")
    auth().get_token()

    stored = store.get(TOKEN_KEY)
    assert "segredo" not in stored
    assert re.fullmatch(r"pbkdf2-sha256\$100000\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+", json.loads(stored)["password_check"])


# ---------------------------------------------------------------------------- 2FA

def test_envia_o_codigo_de_dois_fatores(api, auth):
    api.token("tok-1")

    auth(two_factor_code=lambda: "123456").get_token()

    assert api.requests[0]["body"]["two_fa"] == "123456"


def test_token_obtido_com_2fa_nao_e_devolvido_do_cache_sem_o_codigo(api, auth):
    api.token("tok-com-2fa")
    auth(two_factor_code=lambda: "123456").get_token()
    api.json(401, {"status": 401, "mensagem": "Informe o código de verificação de autenticação de dois fatores (two_fa)"})

    # Senha certa, sem o código: vai à API, que exige o 2FA.
    with pytest.raises(AuthenticationError, match="dois fatores"):
        auth().get_token()
    assert len(api.requests) == 2
    assert "two_fa" not in api.requests[1]["body"]


def test_cada_login_com_2fa_consulta_a_api(api, auth):
    api.token("tok-1").token("tok-2")

    assert auth(two_factor_code=lambda: "111111").get_token() == "tok-1"
    assert auth(two_factor_code=lambda: "222222").get_token() == "tok-2"
    assert len(api.requests) == 2
    assert api.requests[1]["body"]["two_fa"] == "222222"


def test_codigo_2fa_errado_em_thread_simultanea_nao_recebe_o_token_da_vitima(api, auth):
    api.token("tok-vitima", delay=0.2).json(401, {"status": 401, "mensagem": "Código de autenticação de dois fatores (two_fa) inválido"})

    with ThreadPoolExecutor(max_workers=2) as pool:
        vitima = pool.submit(auth(two_factor_code=lambda: "123456").get_token)
        time.sleep(0.05)
        atacante = pool.submit(auth(two_factor_code=lambda: "000000").get_token)

        assert vitima.result() == "tok-vitima"
        with pytest.raises(AuthenticationError):
            atacante.result()


def test_token_com_2fa_fica_marcado_no_cache_e_sem_2fa_nao(api, auth, store):
    api.token("tok-1")
    auth(two_factor_code=lambda: "123456").get_token()
    assert json.loads(store.get(TOKEN_KEY))["two_factor"] is True

    InMemoryTokenStore.clear()
    api.token("tok-2")
    auth().get_token()
    assert "two_factor" not in json.loads(store.get(TOKEN_KEY))


def test_respeita_a_marca_de_2fa_gravada_pelos_outros_sdks(api, auth, store):
    store.set(
        TOKEN_KEY,
        f'{{"access_token":"com-2fa","token_type":"Bearer","expires_at":{now() + 3600},"password_check":"{SEGREDO_CHECK}","two_factor":true}}',
        3600,
    )
    api.token("tok-novo")

    assert auth().get_token() == "tok-novo"


# ---------------------------------------------------------------------------- erros e lock

def test_erro_401_vira_authentication_error_com_a_mensagem_da_api(api, auth):
    api.json(401, {"status": 401, "mensagem": "Usuário ou senha inválidos"})

    with pytest.raises(AuthenticationError, match="Usuário ou senha inválidos") as caught:
        auth().get_token()
    assert caught.value.status == 401


def test_erro_diferente_de_401_vira_api_error_com_o_status(api, auth):
    api.json(500, "Internal Server Error")

    with pytest.raises(ApiError) as caught:
        auth().get_token()
    assert caught.value.status == 500


def test_resposta_sem_access_token_vira_api_error(api, auth):
    api.json(200, {"expires_in": 60})

    with pytest.raises(ApiError):
        auth().get_token()


def test_falha_na_geracao_libera_o_lock(api, auth):
    api.json(500, "").token("tok-1")
    instance = auth(lock_wait_seconds=0.3)

    with pytest.raises(ApiError):
        instance.get_token()

    # Se o lock tivesse ficado preso, esta chamada esperaria e daria LockTimeoutError.
    assert instance.get_token() == "tok-1"


def test_espera_o_token_gerado_por_outro_processo_que_segura_o_lock(api, auth, store):
    store.acquire_lock(LOCK_KEY, "outro-processo", 10_000)

    def outro_processo():
        time.sleep(0.25)
        seed(store, Token("do-outro", "Bearer", now() + 3600), 3600)

    threading.Thread(target=outro_processo).start()

    assert auth().get_token() == "do-outro"
    assert api.requests == []


def test_lock_preso_sem_token_estoura_o_tempo_de_espera(api, auth, store):
    store.acquire_lock(LOCK_KEY, "outro-processo", 10_000)

    with pytest.raises(LockTimeoutError):
        auth(lock_wait_seconds=0.3).get_token()


# ---------------------------------------------------------------------------- configuração e segurança

def test_nao_expoe_senha_nem_app_key_em_repr_str_ou_vars(auth):
    instance = auth(password="senha-secreta-123", app_key="app-key-secreta")

    for output in (repr(instance), str(instance), repr(vars(instance))):
        assert "senha-secreta-123" not in output
        assert "app-key-secreta" not in output
    assert "integracao" in repr(instance)


def test_recusa_redis_e_store_juntos(auth, store):
    with pytest.raises(ValueError):
        auth(redis=object(), store=store)


def test_recusa_conexao_redis_nao_suportada(auth):
    with pytest.raises(TypeError, match="Conexão Redis não suportada"):
        auth(redis=object())


def test_recusa_http_client_nao_suportado(auth):
    with pytest.raises(TypeError, match="http_client"):
        auth(http_client=object())


def test_recusa_httpx_async_client(auth):
    with pytest.raises(TypeError, match="AsyncClient"):
        auth(http_client=httpx.AsyncClient())


def test_recusa_credenciais_vazias(auth):
    with pytest.raises(ValueError):
        auth(password="")


def test_falha_de_transporte_nao_encadeia_o_erro_original(auth):
    def falha(request):
        raise httpx.ConnectError("Connection refused", request=request)

    instance = auth(http_client=httpx.Client(transport=httpx.MockTransport(falha)))

    with pytest.raises(TransportError, match="ConnectError: Connection refused") as caught:
        instance.get_token()
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
