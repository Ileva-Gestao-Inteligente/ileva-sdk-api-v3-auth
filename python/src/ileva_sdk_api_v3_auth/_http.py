"""Requisição de token com o cliente HTTP escolhido: urllib (padrão), requests ou httpx."""

from __future__ import annotations

import urllib.error
import urllib.request
from typing import Any, Callable, NamedTuple


class HttpResponse(NamedTuple):
    status: int
    body: str


#: (url, headers, body, timeout em segundos) -> resposta com qualquer status HTTP. Lança exceção só
#: quando não há resposta (rede, DNS, TLS, timeout).
HttpPost = Callable[[str, "dict[str, str]", bytes, float], HttpResponse]


def urllib_post(url: str, headers: dict[str, str], body: bytes, timeout: float) -> HttpResponse:
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return HttpResponse(response.status, response.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as error:
        # O urllib trata status >= 400 como exceção; aqui ele é só uma resposta.
        with error:
            return HttpResponse(error.code, error.read().decode("utf-8", "replace"))


def client_post(client: Any) -> HttpPost:
    """Adapta um ``requests.Session`` (ou o módulo ``requests``) ou um ``httpx.Client``."""
    library = _library_of(client)

    if library == "httpx":
        if not callable(getattr(client, "post", None)) or type(client).__name__ == "AsyncClient":
            raise TypeError("Informe um httpx.Client síncrono; httpx.AsyncClient não é suportado.")

        def httpx_post(url: str, headers: dict[str, str], body: bytes, timeout: float) -> HttpResponse:
            response = client.post(url, headers=headers, content=body, timeout=timeout)
            return HttpResponse(response.status_code, response.text)

        return httpx_post

    if library == "requests":

        def requests_post(url: str, headers: dict[str, str], body: bytes, timeout: float) -> HttpResponse:
            response = client.post(url, headers=headers, data=body, timeout=timeout)
            return HttpResponse(response.status_code, response.text)

        return requests_post

    raise TypeError("http_client deve ser um requests.Session, o módulo requests ou um httpx.Client.")


def _library_of(client: Any) -> str:
    # O próprio módulo `requests` também tem .post; uma instância informa o módulo pela classe.
    module = getattr(client, "__name__", None) if type(client).__name__ == "module" else type(client).__module__
    return str(module or "").split(".")[0]
