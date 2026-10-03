import pytest

from ileva_sdk_api_v3_auth import InMemoryTokenStore
from ileva_sdk_api_v3_auth._auth import _clear_verified_for_tests


@pytest.fixture(autouse=True)
def _processo_limpo():
    """Cada teste começa sem token em memória e sem conferências de senha memorizadas."""
    InMemoryTokenStore.clear()
    _clear_verified_for_tests()
    yield
    InMemoryTokenStore.clear()
    _clear_verified_for_tests()
