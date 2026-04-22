"""ASGI middleware — validates the session cookie, auto-refreshes on 401,
injects request.scope['tzam_user'] and `X-User-*` headers.

Compatible with FastAPI, Starlette, Litestar, and any ASGI app.

Example
-------
    from fastapi import FastAPI, Request
    from tzam import Config
    from tzam.asgi import TzamASGIMiddleware

    app = FastAPI()
    app.add_middleware(
        TzamASGIMiddleware,
        config=Config(url="https://tzam.online", client_id="...", client_secret="..."),
        public_routes=["/", "/auth/login", "/api/auth"],
        login_url="/auth/login",
    )

    @app.get("/dashboard")
    async def dashboard(request: Request):
        user = request.scope["tzam_user"]  # TokenPayload
        return {"email": user.email}
"""

from __future__ import annotations

from http.cookies import SimpleCookie
from typing import Awaitable, Callable, Sequence
from urllib.parse import quote

from ._client import AsyncTzamClient
from ._types import Config, TokenPayload

ASGIApp = Callable[[dict, Callable, Callable], Awaitable[None]]

SESSION_COOKIE = "session"
REFRESH_COOKIE = "refresh_token"
HEADER_USER_ID = b"x-user-id"
HEADER_USER_EMAIL = b"x-user-email"


class TzamASGIMiddleware:
    """ASGI middleware that gates every non-public request on a valid session."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        config: Config,
        public_routes: Sequence[str] = ("/", "/auth/login", "/auth/register", "/api/auth"),
        login_url: str = "/auth/login",
        secure: bool = True,
        cookie_path: str = "/",
    ):
        self.app = app
        self.client = AsyncTzamClient(config)
        self.public_routes = tuple(public_routes)
        self.login_url = login_url
        self.secure = secure
        self.cookie_path = cookie_path

    async def __call__(self, scope: dict, receive: Callable, send: Callable) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path: str = scope["path"]
        if self._is_public(path):
            await self.app(scope, receive, send)
            return

        cookies = _parse_cookies(scope)
        session_cookie = cookies.get(SESSION_COOKIE, "")
        refresh_cookie = cookies.get(REFRESH_COOKIE, "")

        # Happy path.
        payload = None
        if session_cookie:
            payload = await self.client.validate_token(session_cookie)

        # Refresh path.
        refreshed_access = ""
        if payload is None and refresh_cookie:
            try:
                refreshed_access = await self.client.refresh_token(refresh_cookie)
            except Exception:
                refreshed_access = ""
            if refreshed_access:
                payload = await self.client.validate_token(refreshed_access)

        if payload is None:
            await self._redirect_to_login(scope, send)
            return

        # Inject user metadata into scope + headers before dispatching.
        scope["tzam_user"] = payload
        _inject_user_headers(scope, payload)

        if refreshed_access:
            # Wrap send to set the new session cookie on the first response.
            send = _wrap_send_with_cookie(
                send,
                name=SESSION_COOKIE,
                value=refreshed_access,
                path=self.cookie_path,
                secure=self.secure,
                max_age=15 * 60,
            )

        await self.app(scope, receive, send)

    def _is_public(self, path: str) -> bool:
        for route in self.public_routes:
            if route == "/":
                if path == "/":
                    return True
                continue
            if path.startswith(route):
                return True
        return False

    async def _redirect_to_login(self, scope: dict, send: Callable) -> None:
        query = scope.get("query_string", b"")
        raw_path = scope["path"] + (b"?" + query).decode() if query else scope["path"]
        location = f"{self.login_url}?redirect={quote(raw_path, safe='')}"

        headers = [(b"location", location.encode())]
        for name in (SESSION_COOKIE, REFRESH_COOKIE):
            headers.append((b"set-cookie", _build_cookie(
                name, "", path=self.cookie_path, secure=self.secure, max_age=0,
            ).encode()))

        await send({"type": "http.response.start", "status": 303, "headers": headers})
        await send({"type": "http.response.body", "body": b""})


def _parse_cookies(scope: dict) -> dict[str, str]:
    raw = ""
    for name, value in scope.get("headers", []):
        if name == b"cookie":
            raw = value.decode("latin-1")
            break
    if not raw:
        return {}
    jar: SimpleCookie = SimpleCookie()
    jar.load(raw)
    return {k: morsel.value for k, morsel in jar.items()}


def _inject_user_headers(scope: dict, payload: TokenPayload) -> None:
    headers = [
        (k, v) for k, v in scope.get("headers", [])
        if k not in (HEADER_USER_ID, HEADER_USER_EMAIL)
    ]
    headers.append((HEADER_USER_ID, payload.user_id.encode()))
    headers.append((HEADER_USER_EMAIL, payload.email.encode()))
    scope["headers"] = headers


def _build_cookie(
    name: str,
    value: str,
    *,
    path: str = "/",
    secure: bool = True,
    http_only: bool = True,
    max_age: int | None = None,
    same_site: str = "Lax",
) -> str:
    parts = [f"{name}={value}", f"Path={path}", f"SameSite={same_site}"]
    if http_only:
        parts.append("HttpOnly")
    if secure:
        parts.append("Secure")
    if max_age is not None:
        parts.append(f"Max-Age={max_age}")
    return "; ".join(parts)


def _wrap_send_with_cookie(
    send: Callable,
    *,
    name: str,
    value: str,
    path: str,
    secure: bool,
    max_age: int,
) -> Callable:
    cookie = _build_cookie(name, value, path=path, secure=secure, max_age=max_age).encode()
    applied = False

    async def wrapped(message: dict) -> None:
        nonlocal applied
        if not applied and message["type"] == "http.response.start":
            headers = list(message.get("headers", []))
            headers.append((b"set-cookie", cookie))
            message = {**message, "headers": headers}
            applied = True
        await send(message)

    return wrapped
