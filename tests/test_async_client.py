"""Tests for the async client — mirrors test_client.py."""

from __future__ import annotations

import pytest

from tzam import AUTH_INVALID_CREDENTIALS, AsyncTzamClient, AuthInvalidCredentials, Config


@pytest.fixture
def client() -> AsyncTzamClient:
    return AsyncTzamClient(Config(url="https://idp.test", client_id="cid"))


async def test_async_login_success(httpx_mock, client):
    httpx_mock.add_response(
        url="https://idp.test/auth/login",
        method="POST",
        json={"accessToken": "at", "refreshToken": "rt", "user": {"id": "u1", "email": "a@b", "name": "A"}},
    )
    result = await client.login("a@b", "pw")
    assert result.access_token == "at"
    await client.aclose()


async def test_async_validate_token_returns_none_on_401(httpx_mock, client):
    httpx_mock.add_response(
        url="https://idp.test/auth/validate",
        method="POST",
        status_code=401,
    )
    assert await client.validate_token("bad") is None
    await client.aclose()


async def test_async_login_invalid_credentials(httpx_mock, client):
    httpx_mock.add_response(
        url="https://idp.test/auth/login",
        method="POST",
        status_code=401,
        json={"code": AUTH_INVALID_CREDENTIALS, "message": "nope"},
    )
    with pytest.raises(AuthInvalidCredentials):
        await client.login("a@b", "pw")
    await client.aclose()


async def test_async_get_auth_methods_parses_response(httpx_mock, client):
    httpx_mock.add_response(
        url="https://idp.test/auth/app-config?client_id=cid",
        method="GET",
        json={
            "clientId": "cid",
            "active": True,
            "methods": {
                "password": False,
                "magicLink": True,
                "otp": False,
                "oauth": {"github": True, "google": False},
            },
        },
    )
    cfg = await client.get_auth_methods()
    assert cfg.active is True
    assert cfg.methods.magic_link is True
    assert cfg.methods.oauth.github is True
    assert cfg.methods.password is False
    await client.aclose()
