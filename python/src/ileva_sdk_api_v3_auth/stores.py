"""Onde o token fica guardado entre chamadas e processos."""

from __future__ import annotations

import threading
import time
from typing import Any, Optional, Protocol, runtime_checkable

from ._token import Token


@runtime_checkable
class TokenStore(Protocol):
    """Cache do token, com lock de renovação.

    A API mantém um único token ativo por usuário e gerar um novo invalida o anterior. Sem o lock,
    dois processos que encontram o cache vazio ao mesmo tempo gerariam dois tokens, e o primeiro
    passaria a receber 401.
    """

    def get(self, key: str) -> Optional[str]: ...

    def set(self, key: str, value: str, ttl_seconds: int) -> None: ...

    def delete(self, key: str, access_token: Optional[str] = None) -> None:
        """Remove o token. Com ``access_token``, só remove se o token guardado for esse: assim um
        processo que recebeu 401 com um token antigo não apaga o token novo de outro processo."""
        ...

    def acquire_lock(self, key: str, owner: str, ttl_milliseconds: int) -> bool:
        """Tenta obter o lock sem esperar. ``owner`` identifica quem pode liberá-lo."""
        ...

    def release_lock(self, key: str, owner: str) -> None:
        """Libera o lock só se ele ainda pertence a ``owner`` (pode ter expirado e sido obtido por outro)."""
        ...


# Lista do módulo: compartilhada por todas as instâncias e threads do processo.
_items: dict[str, tuple[str, float]] = {}
_items_lock = threading.Lock()


class InMemoryTokenStore:
    """Store usado quando nenhum Redis é informado: memória compartilhada por todo o processo.

    Só serve para um processo único. Com vários processos (workers do Gunicorn/uWSGI, Celery,
    várias réplicas) cada um geraria o seu token, invalidando o dos outros — nesse caso use Redis.
    """

    @staticmethod
    def clear() -> None:
        """Apaga tudo o que está guardado no processo."""
        with _items_lock:
            _items.clear()

    def get(self, key: str) -> Optional[str]:
        with _items_lock:
            return self._read(key)

    def set(self, key: str, value: str, ttl_seconds: int) -> None:
        with _items_lock:
            _items[key] = (value, time.monotonic() + ttl_seconds)

    def delete(self, key: str, access_token: Optional[str] = None) -> None:
        with _items_lock:
            value = self._read(key)
            if value is None:
                return
            token = Token.from_json(value)
            if access_token is None or token is None or token.access_token == access_token:
                del _items[key]

    def acquire_lock(self, key: str, owner: str, ttl_milliseconds: int) -> bool:
        with _items_lock:
            if self._read(key) is not None:
                return False
            _items[key] = (owner, time.monotonic() + ttl_milliseconds / 1000)
            return True

    def release_lock(self, key: str, owner: str) -> None:
        with _items_lock:
            if self._read(key) == owner:
                del _items[key]

    @staticmethod
    def _read(key: str) -> Optional[str]:
        item = _items.get(key)
        if item is None:
            return None
        value, expires_at = item
        if expires_at <= time.monotonic():
            del _items[key]
            return None
        return value


# Comparar e apagar precisa ser atômico: entre um GET e um DEL feitos pelo cliente, o lock pode
# expirar e ser obtido por outro processo, e o DEL apagaria o lock alheio.
_RELEASE_LOCK_SCRIPT = """
if redis.call('GET', KEYS[1]) == ARGV[1] then
    return redis.call('DEL', KEYS[1])
end
return 0
"""

# ARGV[1] vazio apaga incondicionalmente. Valor que não é JSON válido também é apagado.
_DELETE_TOKEN_SCRIPT = """
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
"""


class RedisTokenStore:
    """Store em Redis, compartilhado entre processos, servidores e com os SDKs de PHP e Node.

    Recebe por injeção a conexão que a aplicação já usa: ``redis.Redis`` ou
    ``redis.cluster.RedisCluster`` (redis-py), com ou sem ``decode_responses``. Cada operação usa
    uma única chave, então funciona em cluster.
    """

    def __init__(self, client: Any) -> None:
        if not all(callable(getattr(client, name, None)) for name in ("get", "set", "eval")):
            raise TypeError("Conexão Redis não suportada. Informe um cliente do redis-py (redis.Redis ou RedisCluster).")
        self._client = client

    def get(self, key: str) -> Optional[str]:
        value = self._client.get(key)
        if isinstance(value, bytes):
            return value.decode("utf-8")
        return value if isinstance(value, str) else None

    def set(self, key: str, value: str, ttl_seconds: int) -> None:
        self._client.set(key, value, ex=max(1, int(ttl_seconds)))

    def delete(self, key: str, access_token: Optional[str] = None) -> None:
        self._client.eval(_DELETE_TOKEN_SCRIPT, 1, key, access_token or "")

    def acquire_lock(self, key: str, owner: str, ttl_milliseconds: int) -> bool:
        return bool(self._client.set(key, owner, px=max(1, int(ttl_milliseconds)), nx=True))

    def release_lock(self, key: str, owner: str) -> None:
        self._client.eval(_RELEASE_LOCK_SCRIPT, 1, key, owner)
