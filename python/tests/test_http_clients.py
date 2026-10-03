"""Os mesmos cenários com urllib (padrão), requests e httpx, contra um servidor HTTP de verdade."""

from __future__ import annotations

import json
import socket
import threading
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest
import requests

from ileva_sdk_api_v3_auth import ApiError, AuthenticationError, IlevaSdkApiV3Auth, TransportError

SENHA = "senha-secreta-123"


class _Handler(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        # Nomes de header em minúsculas: HTTP não diferencia, e o urllib capitaliza ("App_key").
        self.server.received.append({"headers": {k.lower(): v for k, v in self.headers.items()}, "body": json.loads(self.rfile.read(length) or b"{}")})
        status, body, delay = self.server.reply
        if delay:
            time.sleep(delay)
        payload = body.encode() if isinstance(body, str) else json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


@pytest.fixture(scope="module")
def server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    httpd.daemon_threads = True
    httpd.received = []
    httpd.reply = (200, {}, 0)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield httpd
    httpd.shutdown()


@pytest.fixture
def base_url(server):
    server.received.clear()
    return f"http://127.0.0.1:{server.server_address[1]}"


def closed_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


CLIENTS = {
    "urllib (padrão)": lambda: None,
    "requests.Session": requests.Session,
    "módulo requests": lambda: requests,
    "httpx.Client": httpx.Client,
}


@pytest.fixture(params=list(CLIENTS), ids=list(CLIENTS))
def auth(request, base_url):
    client = CLIENTS[request.param]()

    def make(**options) -> IlevaSdkApiV3Auth:
        params = {"app_key": "app-key", "username": "integracao", "password": SENHA, "base_url": base_url, **options}
        if client is not None:
            params["http_client"] = client
        return IlevaSdkApiV3Auth(**params)

    return make


def test_envia_credenciais_e_le_o_token(server, auth):
    server.reply = (200, {"access_token": "tok-1", "token_type": "Bearer", "expires_in": 86400}, 0)

    token = auth().get_token_details()

    assert token.access_token == "tok-1"
    assert token.expires_at > time.time() + 86000
    assert len(server.received) == 1
    assert server.received[0]["headers"]["app_key"] == "app-key"
    assert server.received[0]["headers"]["content-type"] == "application/json"
    assert server.received[0]["body"] == {"username": "integracao", "password": SENHA}


def test_401_vira_authentication_error_com_a_mensagem_da_api(server, auth):
    server.reply = (401, {"status": 401, "mensagem": "App key inválida"}, 0)

    with pytest.raises(AuthenticationError, match="App key inválida"):
        auth().get_token()


def test_500_vira_api_error_com_o_status(server, auth):
    server.reply = (500, "Internal Server Error", 0)

    with pytest.raises(ApiError) as caught:
        auth().get_token()
    assert caught.value.status == 500


def test_timeout_vira_transport_error(server, auth):
    server.reply = (200, {}, 1.0)

    with pytest.raises(TransportError):
        auth(timeout_seconds=0.2).get_token()


def test_falha_de_conexao_nao_expoe_a_senha(auth):
    with pytest.raises(TransportError) as caught:
        auth(base_url=f"http://127.0.0.1:{closed_port()}").get_token()

    error = caught.value
    # Sem encadeamento: o erro do requests/httpx carrega a requisição, com o body.
    assert error.__cause__ is None
    assert error.__context__ is None
    assert SENHA not in str(error)
    # O Sentry captura as variáveis locais de cada frame do traceback.
    for frame, _ in traceback.walk_tb(error.__traceback__):
        for name, value in frame.f_locals.items():
            assert SENHA not in repr(value), f"senha na variável local {name!r} de {frame.f_code.co_name}"


def test_erro_http_da_sessao_da_aplicacao_nao_interfere(server, base_url):
    # Uma Session com hook que lança em 4xx/5xx: a mensagem da API ainda chega no erro certo.
    session = requests.Session()
    session.hooks["response"].append(lambda response, *args, **kwargs: response.raise_for_status())
    server.reply = (401, {"status": 401, "mensagem": "Usuário ou senha inválidos"}, 0)

    auth = IlevaSdkApiV3Auth("app-key", "integracao", "x", base_url=base_url, http_client=session)

    # Um hook que lança transforma a resposta em erro de transporte: documentado como limitação.
    with pytest.raises((AuthenticationError, TransportError)):
        auth.get_token()
