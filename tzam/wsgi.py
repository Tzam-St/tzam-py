"""WSGI middleware — same contract as the ASGI one, for Flask and plain WSGI apps.

Example
-------
    from flask import Flask, request
    from tzam import Config
    from tzam.wsgi import TzamWSGIMiddleware

    app = Flask(__name__)
    app.wsgi_app = TzamWSGIMiddleware(
        app.wsgi_app,
        config=Config(url="https://tzam.online", client_id="...", client_secret="..."),
        public_routes=["/", "/auth/login"],
        login_url="/auth/login",
    )

    @app.route("/dashboard")
    def dashboard():
        user_id = request.headers.get("X-User-ID")
        email = request.headers.get("X-User-Email")
        return f"hi {email} ({user_id})"
"""

from __future__ import annotations

from http.cookies import SimpleCookie
from typing import Callable, Iterable, Sequence
from urllib.parse import quote

from ._client import TzamClient
from ._types import Config

SESSION_COOKIE = "session"
REFRESH_COOKIE = "refresh_token"

WSGIApp = Callable[[dict, Callable], Iterable[bytes]]


class TzamWSGIMiddleware:
    """Gate every non-public request on a valid session. Sync (WSGI)."""

    def __init__(
        self,
        app: WSGIApp,
        *,
        config: Config,
        public_routes: Sequence[str] = ("/", "/auth/login", "/auth/register", "/api/auth"),
        login_url: str = "/auth/login",
        secure: bool = True,
        cookie_path: str = "/",
    ):
        self.app = app
        self.client = TzamClient(config)
        self.public_routes = tuple(public_routes)
        self.login_url = login_url
        self.secure = secure
        self.cookie_path = cookie_path

    def __call__(self, environ: dict, start_response: Callable) -> Iterable[bytes]:
        path: str = environ.get("PATH_INFO", "/")
        if self._is_public(path):
            return self.app(environ, start_response)

        cookies = _parse_cookies(environ.get("HTTP_COOKIE", ""))
        session_cookie = cookies.get(SESSION_COOKIE, "")
        refresh_cookie = cookies.get(REFRESH_COOKIE, "")

        payload = None
        if session_cookie:
            payload = self.client.validate_token(session_cookie)

        refreshed_access = ""
        if payload is None and refresh_cookie:
            try:
                refreshed_access = self.client.refresh_token(refresh_cookie)
            except Exception:
                refreshed_access = ""
            if refreshed_access:
                payload = self.client.validate_token(refreshed_access)

        if payload is None:
            return self._redirect_to_login(environ, start_response)

        environ["tzam.user"] = payload
        environ["HTTP_X_USER_ID"] = payload.user_id
        environ["HTTP_X_USER_EMAIL"] = payload.email

        if not refreshed_access:
            return self.app(environ, start_response)

        # Patch start_response to append the refreshed cookie header.
        def start(status: str, headers: list[tuple[str, str]], exc_info=None) -> Callable:  # type: ignore[override]
            headers = list(headers)
            headers.append((
                "Set-Cookie",
                _build_cookie(SESSION_COOKIE, refreshed_access, path=self.cookie_path,
                              secure=self.secure, max_age=15 * 60),
            ))
            return start_response(status, headers, exc_info)

        return self.app(environ, start)

    def _is_public(self, path: str) -> bool:
        for route in self.public_routes:
            if route == "/":
                if path == "/":
                    return True
                continue
            if path.startswith(route):
                return True
        return False

    def _redirect_to_login(self, environ: dict, start_response: Callable) -> Iterable[bytes]:
        path = environ.get("PATH_INFO", "/")
        qs = environ.get("QUERY_STRING", "")
        full_path = path + ("?" + qs if qs else "")
        location = f"{self.login_url}?redirect={quote(full_path, safe='')}"

        headers = [
            ("Location", location),
            ("Set-Cookie", _build_cookie(SESSION_COOKIE, "", path=self.cookie_path,
                                          secure=self.secure, max_age=0)),
            ("Set-Cookie", _build_cookie(REFRESH_COOKIE, "", path=self.cookie_path,
                                          secure=self.secure, max_age=0)),
        ]
        start_response("303 See Other", headers)
        return [b""]


def _parse_cookies(raw: str) -> dict[str, str]:
    if not raw:
        return {}
    jar: SimpleCookie = SimpleCookie()
    jar.load(raw)
    return {k: morsel.value for k, morsel in jar.items()}


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
