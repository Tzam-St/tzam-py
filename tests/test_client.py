"""Tests for the sync client. Uses pytest-httpx to mock outbound calls."""

from __future__ import annotations

import pytest

from tzam import (
    AUTH_INVALID_CREDENTIALS,
    AUTH_TOKEN_EXPIRED,
    AuthInvalidCredentials,
    Config,
    TzamClient,
    TzamError,
)


@pytest.fixture
def client() -> TzamClient:
    return TzamClient(Config(url="https://idp.test", client_id="cid", client_secret="sec"))


def test_login_success(httpx_mock, client):
    httpx_mock.add_response(
        url="https://idp.test/auth/login",
        method="POST",
        json={
            "accessToken": "at",
            "refreshToken": "rt",
            "user": {"id": "u1", "email": "a@b", "name": "Alice"},
        },
    )
    result = client.login("a@b", "pw")
    assert result.access_token == "at"
    assert result.refresh_token == "rt"
    assert result.user.id == "u1"
    assert result.user.email == "a@b"


def test_login_invalid_credentials_raises_specific(httpx_mock, client):
    httpx_mock.add_response(
        url="https://idp.test/auth/login",
        method="POST",
        status_code=401,
        json={"code": AUTH_INVALID_CREDENTIALS, "message": "wrong password"},
    )
    with pytest.raises(AuthInvalidCredentials) as exc_info:
        client.login("a@b", "pw")
    assert exc_info.value.status == 401
    assert exc_info.value.code == AUTH_INVALID_CREDENTIALS
    assert "wrong password" in exc_info.value.message


def test_login_unknown_code_falls_back_to_generic(httpx_mock, client):
    httpx_mock.add_response(
        url="https://idp.test/auth/login",
        method="POST",
        status_code=500,
        json={"message": "db down"},
    )
    with pytest.raises(TzamError) as exc_info:
        client.login("a@b", "pw")
    assert exc_info.value.status == 500
    assert exc_info.value.code == ""
    # More specific classes must NOT match.
    assert not isinstance(exc_info.value, AuthInvalidCredentials)


def test_validate_token_returns_none_on_401(httpx_mock, client):
    httpx_mock.add_response(
        url="https://idp.test/auth/validate",
        method="POST",
        status_code=401,
        json={"code": AUTH_TOKEN_EXPIRED},
    )
    assert client.validate_token("bad") is None


def test_validate_token_success(httpx_mock, client):
    httpx_mock.add_response(
        url="https://idp.test/auth/validate",
        method="POST",
        json={"userId": "u1", "email": "a@b"},
    )
    payload = client.validate_token("good")
    assert payload is not None
    assert payload.user_id == "u1"
    assert payload.email == "a@b"


def test_refresh_token_forwards_cookie(httpx_mock, client):
    httpx_mock.add_response(
        url="https://idp.test/auth/refresh",
        method="POST",
        json={"accessToken": "fresh"},
    )
    at = client.refresh_token("rt-value")
    assert at == "fresh"
    req = httpx_mock.get_request()
    assert req is not None and req.headers.get("cookie") == "refresh_token=rt-value"


def test_logout_accepts_204(httpx_mock, client):
    httpx_mock.add_response(
        url="https://idp.test/auth/logout",
        method="POST",
        status_code=204,
    )
    client.logout("at", "rt")  # should not raise


def test_magic_link_verify_url_encodes_token(client):
    assert client.magic_link_verify_url("ab cd") == "https://idp.test/auth/magic-link/verify?token=ab%20cd"


def test_empty_url_raises():
    with pytest.raises(ValueError):
        TzamClient(Config(url=""))
