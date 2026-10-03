"""Autenticação na API Ileva v3: gera o token de acesso e mantém sua validade."""

from ._auth import IlevaSdkApiV3Auth
from ._errors import (
    ApiError,
    AuthenticationError,
    IlevaSdkApiV3AuthError,
    LockTimeoutError,
    TransportError,
)
from ._token import Token
from .stores import InMemoryTokenStore, RedisTokenStore, TokenStore

__version__ = "0.0.0.dev0"

__all__ = [
    "IlevaSdkApiV3Auth",
    "Token",
    "TokenStore",
    "InMemoryTokenStore",
    "RedisTokenStore",
    "IlevaSdkApiV3AuthError",
    "AuthenticationError",
    "ApiError",
    "TransportError",
    "LockTimeoutError",
]
