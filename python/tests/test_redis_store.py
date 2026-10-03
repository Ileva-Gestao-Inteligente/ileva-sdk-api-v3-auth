"""Testes contra um Redis real (ILEVA_TEST_REDIS_HOST); são pulados sem conexão."""

from __future__ import annotations

import os
import secrets
import time

import pytest
import redis

from ileva_sdk_api_v3_auth import RedisTokenStore, Token

HOST = os.environ.get("ILEVA_TEST_REDIS_HOST", "127.0.0.1")
PORT = int(os.environ.get("ILEVA_TEST_REDIS_PORT", "6379"))


def _available() -> bool:
    try:
        return bool(redis.Redis(host=HOST, port=PORT, socket_connect_timeout=1).ping())
    except redis.RedisError:
        return False


pytestmark = pytest.mark.skipif(not _available(), reason=f"Redis indisponível em {HOST}:{PORT}")


@pytest.fixture(params=[False, True], ids=["bytes", "decode_responses"])
def client(request):
    connection = redis.Redis(host=HOST, port=PORT, decode_responses=request.param)
    yield connection
    connection.close()


@pytest.fixture
def store(client):
    return RedisTokenStore(client)


@pytest.fixture
def key(client):
    name = f"ileva:auth:test:{secrets.token_hex(6)}"
    yield name
    client.delete(name)


def test_grava_com_ttl_e_le(store, client, key):
    store.set(key, "valor", 120)

    assert store.get(key) == "valor"
    assert 110 < client.ttl(key) <= 120


def test_chave_inexistente_devolve_none(store, key):
    assert store.get(key) is None


def test_delete_so_apaga_quando_o_token_confere(store, key):
    store.set(key, Token("atual", "Bearer", 9999999999).to_json(), 60)

    store.delete(key, "outro")
    assert store.get(key) is not None

    store.delete(key, "atual")
    assert store.get(key) is None


def test_delete_sem_token_apaga_sempre(store, key):
    store.set(key, Token("atual", "Bearer", 9999999999).to_json(), 60)

    store.delete(key)

    assert store.get(key) is None


def test_delete_apaga_valor_corrompido(store, key):
    store.set(key, "nao-e-json", 60)

    store.delete(key, "qualquer")

    assert store.get(key) is None


def test_lock_e_exclusivo_e_so_o_dono_libera(store, key):
    assert store.acquire_lock(key, "a", 5000) is True
    assert store.acquire_lock(key, "b", 5000) is False

    store.release_lock(key, "b")
    assert store.acquire_lock(key, "b", 5000) is False

    store.release_lock(key, "a")
    assert store.acquire_lock(key, "b", 5000) is True


def test_lock_expira(store, key):
    assert store.acquire_lock(key, "a", 50) is True
    time.sleep(0.12)

    assert store.acquire_lock(key, "b", 5000) is True
