"""Tests for the async client — mirrors test_client.py."""

from __future__ import annotations

import pytest

from tzam import (
    AUTH_INVALID_CREDENTIALS,
    AppInactiveError,
    AsyncTzamClient,
    AuthInvalidCredentials,
    Config,
    MagicLinkMethodDisabledError,
    OtpMethodDisabledError,
    PasswordMethodDisabledError,
)


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


def _async_app_config(
    *,
    active: bool = True,
    password: bool = True,
    magic_link: bool = True,
    otp: bool = True,
) -> dict:
    return {
        "clientId": "cid",
        "active": active,
        "methods": {
            "password": password,
            "magicLink": magic_link,
            "otp": otp,
            "oauth": {"github": False, "google": False},
        },
    }


async def test_async_forgot_password_probes_then_posts(httpx_mock, client):
    httpx_mock.add_response(
        url="https://idp.test/auth/app-config?client_id=cid",
        method="GET",
        json=_async_app_config(),
    )
    httpx_mock.add_response(
        url="https://idp.test/auth/forgot-password",
        method="POST",
        status_code=204,
    )
    await client.forgot_password("user@example.com")
    await client.aclose()


async def test_async_forgot_password_raises_password_disabled(httpx_mock, client):
    httpx_mock.add_response(
        url="https://idp.test/auth/app-config?client_id=cid",
        method="GET",
        json=_async_app_config(password=False),
    )
    with pytest.raises(PasswordMethodDisabledError):
        await client.forgot_password("user@example.com")
    await client.aclose()


async def test_async_forgot_password_raises_app_inactive(httpx_mock, client):
    httpx_mock.add_response(
        url="https://idp.test/auth/app-config?client_id=cid",
        method="GET",
        json=_async_app_config(active=False),
    )
    with pytest.raises(AppInactiveError):
        await client.forgot_password("user@example.com")
    await client.aclose()


async def test_async_request_magic_link_probes_then_posts(httpx_mock, client):
    httpx_mock.add_response(
        url="https://idp.test/auth/app-config?client_id=cid",
        method="GET",
        json=_async_app_config(),
    )
    httpx_mock.add_response(
        url="https://idp.test/auth/magic-link",
        method="POST",
        status_code=204,
    )
    await client.request_magic_link("user@example.com", "/after")
    await client.aclose()


async def test_async_request_magic_link_raises_when_disabled(httpx_mock, client):
    httpx_mock.add_response(
        url="https://idp.test/auth/app-config?client_id=cid",
        method="GET",
        json=_async_app_config(magic_link=False),
    )
    with pytest.raises(MagicLinkMethodDisabledError):
        await client.request_magic_link("user@example.com")
    await client.aclose()


async def test_async_request_otp_probes_then_posts(httpx_mock, client):
    httpx_mock.add_response(
        url="https://idp.test/auth/app-config?client_id=cid",
        method="GET",
        json=_async_app_config(),
    )
    httpx_mock.add_response(
        url="https://idp.test/auth/otp",
        method="POST",
        status_code=204,
    )
    await client.request_otp("user@example.com")
    await client.aclose()


async def test_async_request_otp_raises_when_disabled(httpx_mock, client):
    httpx_mock.add_response(
        url="https://idp.test/auth/app-config?client_id=cid",
        method="GET",
        json=_async_app_config(otp=False),
    )
    with pytest.raises(OtpMethodDisabledError):
        await client.request_otp("user@example.com")
    await client.aclose()
