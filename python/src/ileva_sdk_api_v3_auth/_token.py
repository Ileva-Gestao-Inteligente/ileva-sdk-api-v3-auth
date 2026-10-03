from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Optional


@dataclass(frozen=True)
class Token:
    """Token de acesso da API Ileva.

    O formato serializado (``to_json``) é o contrato gravado no cache: os SDKs de PHP, Node e Python
    leem e gravam o mesmo JSON, para que serviços em linguagens diferentes compartilhem o mesmo token.
    """

    access_token: str
    token_type: str
    #: Instante de expiração, em segundos Unix.
    expires_at: int
    #: Obtido com código de autenticação em dois fatores: nunca é devolvido do cache.
    two_factor: bool = False

    def is_valid(self, now: int, refresh_margin: int = 0) -> bool:
        """Válido até ``refresh_margin`` segundos antes de expirar, para que uma requisição iniciada
        perto do fim da validade não chegue à API com ele já vencido."""
        return now < self.expires_at - refresh_margin

    def authorization_header(self) -> str:
        return f"{self.token_type} {self.access_token}"

    def to_json(self, password_check: Optional[str] = None) -> str:
        """``password_check`` é o verificador da senha que gerou o token (veja o contrato do cache).
        O SDK sempre grava com ele."""
        data: dict[str, Any] = {
            "access_token": self.access_token,
            "token_type": self.token_type,
            "expires_at": self.expires_at,
        }
        if password_check is not None:
            data["password_check"] = password_check
        if self.two_factor:
            data["two_factor"] = True
        return json.dumps(data, separators=(",", ":"), ensure_ascii=False)

    @classmethod
    def from_json(cls, value: str) -> Optional[Token]:
        """Devolve None para um valor corrompido ou em outro formato, tratado como cache vazio."""
        data = _parse_object(value)
        if data is None:
            return None
        access_token = data.get("access_token")
        expires_at = data.get("expires_at")
        # bool é subclasse de int em Python; true/false no JSON não é um instante válido.
        if not isinstance(access_token, str) or not isinstance(expires_at, int) or isinstance(expires_at, bool):
            return None
        token_type = data.get("token_type")
        return cls(
            access_token,
            token_type if isinstance(token_type, str) else "Bearer",
            expires_at,
            data.get("two_factor") is True,
        )

    @staticmethod
    def password_check_from_json(value: str) -> Optional[str]:
        """Verificador da senha gravado junto do token, ou None se não houver."""
        data = _parse_object(value)
        check = data.get("password_check") if data is not None else None
        return check if isinstance(check, str) else None


def _parse_object(value: str) -> Optional[dict[str, Any]]:
    try:
        data = json.loads(value)
    except ValueError:
        return None
    return data if isinstance(data, dict) else None
