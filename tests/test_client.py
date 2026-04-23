"""Tests for the sync client. Uses pytest-httpx to mock outbound calls."""

from __future__ import annotations

import pytest

from tzam import (
    AUTH_INVALID_CREDENTIALS,
    AUTH_TOKEN_EXPIRED,
    AppInactiveError,
    AuthInvalidCredentials,
    Config,
    PasswordMethodDisabledError,
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


# get_auth_methods is the client-side half of the silent-by-design
# forgot-password flow. /auth/forgot-password returns 204 even when
# the password method is disabled for the app (to avoid enumeration);
# callers must consult /auth/app-config to decide what UI to render.
def test_get_auth_methods_queries_app_config_with_client_id(httpx_mock, client):
    httpx_mock.add_response(
        url="https://idp.test/auth/app-config?client_id=cid",
        method="GET",
        json={
            "clientId": "cid",
            "active": True,
            "methods": {
                "password": True,
                "magicLink": False,
                "otp": False,
                "oauth": {"github": False, "google": True},
            },
        },
    )
    cfg = client.get_auth_methods()
    assert cfg.client_id == "cid"
    assert cfg.active is True
    assert cfg.methods.password is True
    assert cfg.methods.magic_link is False
    assert cfg.methods.oauth.google is True
    assert cfg.methods.oauth.github is False


def test_get_auth_methods_reports_inactive_app(httpx_mock, client):
    httpx_mock.add_response(
        url="https://idp.test/auth/app-config?client_id=cid",
        method="GET",
        json={
            "clientId": "cid",
            "active": False,
            "methods": {
                "password": False,
                "magicLink": False,
                "otp": False,
                "oauth": {"github": False, "google": False},
            },
        },
    )
    cfg = client.get_auth_methods()
    assert cfg.active is False
    assert cfg.methods.password is False


def test_get_auth_methods_raises_on_server_error(httpx_mock, client):
    httpx_mock.add_response(
        url="https://idp.test/auth/app-config?client_id=cid",
        method="GET",
        status_code=500,
        json={"message": "Upstream unavailable"},
    )
    with pytest.raises(TzamError):
        client.get_auth_methods()


# forgot_password probes /auth/app-config first so the SDK can surface
# a typed error instead of the silent 204 the IdP returns when the flow
# would be dropped (app inactive or email/password disabled).
def _app_config_payload(*, active: bool = True, password: bool = True) -> dict:
    return {
        "clientId": "cid",
        "active": active,
        "methods": {
            "password": password,
            "magicLink": False,
            "otp": False,
            "oauth": {"github": False, "google": False},
        },
    }


def test_forgot_password_probes_app_config_and_posts_when_enabled(httpx_mock, client):
    httpx_mock.add_response(
        url="https://idp.test/auth/app-config?client_id=cid",
        method="GET",
        json=_app_config_payload(),
    )
    httpx_mock.add_response(
        url="https://idp.test/auth/forgot-password",
        method="POST",
        status_code=204,
    )
    client.forgot_password("user@example.com")


def test_forgot_password_raises_password_disabled(httpx_mock, client):
    httpx_mock.add_response(
        url="https://idp.test/auth/app-config?client_id=cid",
        method="GET",
        json=_app_config_payload(password=False),
    )
    with pytest.raises(PasswordMethodDisabledError):
        client.forgot_password("user@example.com")
    # /auth/forgot-password must NOT be reached — pytest-httpx asserts that
    # no unmatched requests were made at teardown.


def test_forgot_password_raises_app_inactive(httpx_mock, client):
    httpx_mock.add_response(
        url="https://idp.test/auth/app-config?client_id=cid",
        method="GET",
        json=_app_config_payload(active=False),
    )
    with pytest.raises(AppInactiveError):
        client.forgot_password("user@example.com")
