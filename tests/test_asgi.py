"""Tests for the ASGI middleware.

We drive the middleware directly with a fake ASGI app and capture the
send() events to assert redirects, status codes, and cookie headers.
"""

from __future__ import annotations

from typing import Any

import pytest

from tzam import Config
from tzam.asgi import TzamASGIMiddleware


async def _fake_app(scope: dict, receive, send) -> None:
    """Echoes the injected X-User-ID header back to the client."""
    user_id = ""
    for name, value in scope.get("headers", []):
        if name == b"x-user-id":
            user_id = value.decode()
    body = f"hi {user_id}".encode()
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": body})


def _scope(path: str, cookies: dict[str, str] | None = None) -> dict:
    headers: list[tuple[bytes, bytes]] = []
    if cookies:
        raw = "; ".join(f"{k}={v}" for k, v in cookies.items())
        headers.append((b"cookie", raw.encode("latin-1")))
    return {"type": "http.http", "method": "GET", "path": path, "headers": headers, "query_string": b""}


class _RecordingSend:
    def __init__(self) -> None:
        self.messages: list[dict[str, Any]] = []

    async def __call__(self, message: dict) -> None:
        self.messages.append(message)


async def _recv() -> dict:
    return {"type": "http.request"}


@pytest.fixture
def middleware():
    return TzamASGIMiddleware(
        _fake_app,
        config=Config(url="https://idp.test"),
        public_routes=["/", "/health"],
        login_url="/signin",
    )


async def test_public_route_passes_through(middleware, httpx_mock):
    scope = {**_scope("/health"), "type": "http"}
    send = _RecordingSend()
    await middleware(scope, _recv, send)
    assert send.messages[0]["status"] == 200


async def test_no_cookies_redirects_to_login(middleware, httpx_mock):
    scope = {**_scope("/dashboard"), "type": "http"}
    send = _RecordingSend()
    await middleware(scope, _recv, send)
    assert send.messages[0]["status"] == 303
    # Location header includes the original path.
    headers = dict((k.decode(), v.decode()) for k, v in send.messages[0]["headers"])
    assert headers.get("location") == "/signin?redirect=%2Fdashboard"


async def test_valid_session_injects_user_and_passes_through(middleware, httpx_mock):
    httpx_mock.add_response(
        url="https://idp.test/auth/validate",
        method="POST",
        json={"userId": "u1", "email": "a@b"},
    )
    scope = {**_scope("/dashboard", {"session": "good"}), "type": "http"}
    send = _RecordingSend()
    await middleware(scope, _recv, send)
    assert send.messages[0]["status"] == 200
    body = send.messages[1]["body"].decode()
    assert body == "hi u1"


async def test_expired_session_triggers_refresh_and_sets_cookie(middleware, httpx_mock):
    # First validate → 401, refresh → fresh, second validate → OK
    httpx_mock.add_response(
        url="https://idp.test/auth/validate",
        method="POST",
        status_code=401,
    )
    httpx_mock.add_response(
        url="https://idp.test/auth/refresh",
        method="POST",
        json={"accessToken": "fresh"},
    )
    httpx_mock.add_response(
        url="https://idp.test/auth/validate",
        method="POST",
        json={"userId": "u1", "email": "a@b"},
    )

    scope = {**_scope("/dashboard", {"session": "stale", "refresh_token": "rt1"}), "type": "http"}
    send = _RecordingSend()
    await middleware(scope, _recv, send)

    start = send.messages[0]
    assert start["status"] == 200
    cookie_headers = [v.decode() for k, v in start["headers"] if k == b"set-cookie"]
    assert any("session=fresh" in c and "HttpOnly" in c for c in cookie_headers)
