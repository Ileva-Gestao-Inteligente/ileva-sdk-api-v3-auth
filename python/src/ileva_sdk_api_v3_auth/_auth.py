from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import threading
import time
from typing import Any, Callable, Optional

from ._errors import ApiError, AuthenticationError, LockTimeoutError, TransportError
from ._http import HttpPost, HttpResponse, client_post, urllib_post
from ._token import Token
from .stores import InMemoryTokenStore, RedisTokenStore, TokenStore

DEFAULT_BASE_URL = "https://api.ileva.com.br"

_POLL_INTERVAL_SECONDS = 0.1

_PASSWORD_CHECK_ALGORITHM = "pbkdf2-sha256"
_PASSWORD_CHECK_ITERATIONS = 100_000
# Um valor adulterado no cache não pode travar o processo com um número absurdo de iterações.
_PASSWORD_CHECK_MAX_ITERATIONS = 1_000_000
_BASE64 = re.compile(r"[A-Za-z0-9+/]+={0,2}")

# Normalização da chave do cache, idêntica nos SDKs de todas as linguagens: minúsculas só em ASCII
# e trim só destes caracteres. As funções nativas de cada linguagem divergem em acentos e espaços
# Unicode, e a chave precisa ser a mesma para o token ser compartilhado.
_ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")
_TRIM_CHARS = " \t\n\r\x0b\x00"

# Conferências de senha já feitas no processo, por chave do token: o token conferido e o HMAC da
# senha com uma chave aleatória do processo (nunca a senha). O PBKDF2 é pago uma vez por token.
_process_secret = secrets.token_bytes(32)
_verified: dict[str, tuple[str, bytes]] = {}
_verified_lock = threading.Lock()


class _Secret:
    """Guarda um valor sensível sem expô-lo em repr, logs, vars() ou variáveis locais capturadas
    por ferramentas de erro como o Sentry."""

    __slots__ = ("_value",)

    def __init__(self, value: Any) -> None:
        self._value = value

    def reveal(self) -> Any:
        return self._value

    def __repr__(self) -> str:
        return "***"

    __str__ = __repr__


class IlevaSdkApiV3Auth:
    """Obtém o token de acesso da API Ileva e mantém sua validade.

    O token é guardado no store e reaproveitado enquanto for válido; perto de expirar, é renovado.
    A API mantém um único token ativo por usuário — gerar um novo invalida o anterior —, então a
    renovação é feita sob lock: só um processo pede o token e os outros esperam por ele no cache.

    O token em cache só é devolvido a quem informa a mesma senha que o gerou: junto dele fica um
    verificador da senha (PBKDF2), e uma senha diferente faz o SDK consultar a API. Token obtido com
    código 2FA nunca é devolvido do cache: o SDK não tem como conferir o código.

    Instâncias com a mesma app key e o mesmo usuário compartilham o token: sem Redis, pela memória
    do processo; com Redis, entre processos, servidores e com os SDKs de PHP e Node.
    """

    DEFAULT_BASE_URL = DEFAULT_BASE_URL

    def __init__(
        self,
        app_key: str,
        username: str,
        password: str,
        *,
        redis: Any = None,
        store: Optional[TokenStore] = None,
        http_client: Any = None,
        base_url: str = DEFAULT_BASE_URL,
        two_factor_code: Optional[Callable[[], str]] = None,
        refresh_margin_seconds: int = 300,
        timeout_seconds: float = 15.0,
        lock_wait_seconds: float = 20.0,
        key_prefix: str = "ileva:auth",
    ) -> None:
        """
        :param app_key: Valor de Configurações > Integrações > API Integração no sistema Ileva.
        :param username: Usuário ou e-mail usado para entrar no sistema Ileva; o perfil precisa estar
            liberado para acesso via API.
        :param password: Senha do usuário no sistema Ileva.
        :param redis: Conexão do redis-py (``redis.Redis`` ou ``RedisCluster``). Sem Redis o token
            fica em memória, só neste processo.
        :param store: Store próprio, no lugar de ``redis``.
        :param http_client: ``requests.Session`` (ou o módulo ``requests``) ou ``httpx.Client``. O
            padrão é o urllib da biblioteca padrão.
        :param two_factor_code: Chamado a cada geração de token, para usuários com 2FA.
        :param refresh_margin_seconds: Segundos antes da expiração em que o token passa a ser renovado.
        :param timeout_seconds: Timeout da requisição de token.
        :param lock_wait_seconds: Quanto esperar por outro processo que esteja renovando.
        :param key_prefix: Prefixo das chaves no Redis.
        """
        if not app_key or not username or not password:
            raise ValueError("app key, usuário e senha são obrigatórios.")
        if redis is not None and store is not None:
            raise ValueError("Informe redis ou store, não os dois.")
        if refresh_margin_seconds < 0 or timeout_seconds <= 0 or lock_wait_seconds <= 0:
            raise ValueError(
                "refresh_margin_seconds não pode ser negativo; timeout_seconds e lock_wait_seconds devem ser positivos."
            )

        self.base_url = base_url.rstrip("/")
        self.username = username
        self._app_key = _Secret(app_key)
        self._password = _Secret(password)
        self._store: TokenStore = store if store is not None else (
            RedisTokenStore(redis) if redis is not None else InMemoryTokenStore()
        )
        self._http: HttpPost = client_post(http_client) if http_client is not None else urllib_post
        self._two_factor_code = two_factor_code
        self._refresh_margin = refresh_margin_seconds
        self._timeout = timeout_seconds
        self._lock_wait = lock_wait_seconds

        # A chave identifica o token pelo ambiente, pela associação (app key) e pelo usuário — a
        # mesma combinação que a API usa para manter um token ativo. A senha fica fora: ela é
        # conferida pelo verificador gravado junto do token. É o mesmo cálculo dos outros SDKs.
        material = "\n".join([
            self.base_url.translate(_ASCII_LOWER),
            app_key,
            username.strip(_TRIM_CHARS).translate(_ASCII_LOWER),
        ])
        digest = hashlib.sha256(material.encode("utf-8")).hexdigest()
        self._token_key = f"{key_prefix}:token:{digest}"
        self._lock_key = f"{key_prefix}:lock:{digest}"
        self._password_digest = _Secret(hmac.new(_process_secret, password.encode("utf-8"), hashlib.sha256).digest())

    def __repr__(self) -> str:
        return f"IlevaSdkApiV3Auth(base_url={self.base_url!r}, username={self.username!r}, app_key=***, password=***)"

    def get_token(self) -> str:
        """Token de acesso válido, gerado ou renovado se necessário."""
        return self._resolve_token().access_token

    def get_authorization_header(self) -> str:
        """Valor pronto para o header Authorization, ex.: ``"Bearer eyJ..."``."""
        return self._resolve_token().authorization_header()

    def get_token_details(self) -> Token:
        """Token com o instante de expiração."""
        return self._resolve_token()

    def invalidate(self, rejected_token: Optional[str] = None) -> None:
        """Descarta o token do cache, para que a próxima chamada gere outro.

        Chame ao receber 401 da API, passando o token que foi recusado: se outro processo já o
        substituiu, o novo é preservado.
        """
        self._store.delete(self._token_key, rejected_token)

    def refresh(self) -> str:
        """Gera um token novo mesmo que o atual ainda seja válido."""
        self.invalidate()
        return self.get_token()

    def _resolve_token(self) -> Token:
        cached = self._read_cached_token()
        if cached is not None:
            return cached

        # Espera o suficiente para outro processo terminar a requisição de token (timeout) e, se
        # ele tiver morrido segurando o lock, para o lock expirar e ser obtido aqui.
        lock_ttl_ms = int((self._timeout + 5) * 1000)
        deadline = time.monotonic() + self._lock_wait

        while True:
            owner = secrets.token_hex(16)
            if self._store.acquire_lock(self._lock_key, owner, lock_ttl_ms):
                try:
                    # Outro processo pode ter renovado entre a leitura acima e a obtenção do lock.
                    return self._read_cached_token() or self._request_and_store_token()
                finally:
                    self._store.release_lock(self._lock_key, owner)

            time.sleep(_POLL_INTERVAL_SECONDS)

            cached = self._read_cached_token()
            if cached is not None:
                return cached
            if time.monotonic() >= deadline:
                raise LockTimeoutError(
                    f"O token não foi renovado por outro processo em {self._lock_wait:.0f} segundos."
                )

    def _read_cached_token(self) -> Optional[Token]:
        """Token do cache, se ainda válido, sem 2FA e gerado com a mesma senha desta instância.

        Com outra senha devolve None, como se o cache estivesse vazio: o SDK consulta a API, que
        recusa a senha errada — e o token de quem acertou continua no cache.
        """
        value = self._store.get(self._token_key)
        if value is None:
            return None
        token = Token.from_json(value)
        if token is None or not token.is_valid(int(time.time()), self._refresh_margin):
            return None
        # Servir do cache pularia o 2FA: quem soubesse só a senha receberia o token. Ele continua
        # gravado para substituir o token anterior do usuário, que a API invalidou ao gerar este.
        if token.two_factor:
            return None
        if self._is_verified(token):
            return token
        check = Token.password_check_from_json(value)
        if check is None or not self._password_matches(check):
            return None
        self._mark_verified(token)
        return token

    def _request_and_store_token(self) -> Token:
        token = self._request_token()
        self._store.set(self._token_key, token.to_json(self._create_password_check()), token.expires_at - int(time.time()))
        self._mark_verified(token)
        return token

    def _request_token(self) -> Token:
        url = f"{self.base_url}/oauth/token"
        two_factor = self._two_factor_code() if self._two_factor_code is not None else None
        requested_at = int(time.time())
        response = self._post(url, two_factor)
        data = _parse_object(response.body)

        if response.status != 200:
            message = data.get("mensagem") if data is not None else None
            if not isinstance(message, str):
                message = f"A API respondeu HTTP {response.status} ao gerar o token."
            if response.status == 401:
                raise AuthenticationError(message)
            raise ApiError(message, response.status)

        access_token = data.get("access_token") if data is not None else None
        expires_in = data.get("expires_in") if data is not None else None
        try:
            expires_in = int(float(expires_in))  # type: ignore[arg-type]
        except (TypeError, ValueError):
            expires_in = None
        if not isinstance(access_token, str) or expires_in is None:
            raise ApiError("Resposta de token fora do formato esperado.", response.status)

        token_type = data.get("token_type") if data is not None else None
        # Conta a validade a partir do envio, não da resposta: assim o tempo de rede nunca faz o
        # SDK achar que o token vale mais do que a API considera.
        return Token(
            access_token,
            token_type if isinstance(token_type, str) else "Bearer",
            requested_at + expires_in,
            self._two_factor_code is not None,
        )

    def _post(self, url: str, two_factor: Optional[str]) -> HttpResponse:
        # Nenhuma variável local deste frame guarda a senha ou a app key: headers e body são
        # montados dentro da chamada. E o erro do cliente HTTP não é encadeado — o de requests e
        # httpx carrega a requisição, com o body — então o raise fica fora do except.
        failure: Optional[str] = None
        try:
            return self._http(url, self._headers(), self._credentials_json(two_factor), self._timeout)
        except Exception as error:  # qualquer falha do cliente HTTP escolhido
            failure = f"{type(error).__name__}: {error}"
        raise TransportError(f"Falha ao conectar em {url}: {failure}")

    def _headers(self) -> dict[str, str]:
        return {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "app_key": self._app_key.reveal(),
        }

    def _credentials_json(self, two_factor: Optional[str]) -> bytes:
        body = {"username": self.username, "password": self._password.reveal()}
        if two_factor is not None:
            body["two_fa"] = two_factor
        return json.dumps(body).encode("utf-8")

    # A senha nunca é passada como argumento nem fica em variável local nos métodos abaixo.

    def _create_password_check(self) -> str:
        salt = secrets.token_bytes(16)
        digest = hashlib.pbkdf2_hmac("sha256", self._password.reveal().encode("utf-8"), salt, _PASSWORD_CHECK_ITERATIONS, 32)
        return "$".join([
            _PASSWORD_CHECK_ALGORITHM,
            str(_PASSWORD_CHECK_ITERATIONS),
            base64.b64encode(salt).decode("ascii"),
            base64.b64encode(digest).decode("ascii"),
        ])

    def _password_matches(self, check: str) -> bool:
        """Um verificador fora do formato conta como senha diferente."""
        parts = check.split("$")
        if len(parts) != 4 or parts[0] != _PASSWORD_CHECK_ALGORITHM or not parts[1].isascii() or not parts[1].isdigit():
            return False
        iterations = int(parts[1])
        salt = _decode_base64(parts[2])
        expected = _decode_base64(parts[3])
        if not 1 <= iterations <= _PASSWORD_CHECK_MAX_ITERATIONS or salt is None or expected is None:
            return False
        actual = hashlib.pbkdf2_hmac("sha256", self._password.reveal().encode("utf-8"), salt, iterations, len(expected))
        return hmac.compare_digest(expected, actual)

    def _is_verified(self, token: Token) -> bool:
        with _verified_lock:
            entry = _verified.get(self._token_key)
        return (
            entry is not None
            and entry[0] == token.access_token
            and hmac.compare_digest(entry[1], self._password_digest.reveal())
        )

    def _mark_verified(self, token: Token) -> None:
        with _verified_lock:
            _verified[self._token_key] = (token.access_token, self._password_digest.reveal())


def _clear_verified_for_tests() -> None:
    """Esquece as conferências de senha memorizadas no processo. Uso dos testes."""
    with _verified_lock:
        _verified.clear()


def _decode_base64(value: str) -> Optional[bytes]:
    """Base64 estrito e não vazio; None para qualquer outra coisa."""
    if not _BASE64.fullmatch(value):
        return None
    try:
        decoded = base64.b64decode(value, validate=True)
    except ValueError:
        return None
    return decoded or None


def _parse_object(text: str) -> Optional[dict[str, Any]]:
    try:
        data = json.loads(text)
    except ValueError:
        return None
    return data if isinstance(data, dict) else None
