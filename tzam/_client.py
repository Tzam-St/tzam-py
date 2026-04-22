"""Sync and async HTTP clients for the Tzam IdP.

Both clients share method signatures so switching between them is
mechanical. Each method returns parsed dataclasses, never raw JSON.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

import httpx

from ._errors import raise_api_error
from ._types import Config, LoginResult, TokenPayload, User


def _parse_login_result(data: dict[str, Any]) -> LoginResult:
    u = data.get("user") or {}
    return LoginResult(
        access_token=str(data.get("accessToken", "")),
        refresh_token=str(data.get("refreshToken", "")),
        user=User(id=str(u.get("id", "")), email=str(u.get("email", "")), name=str(u.get("name", ""))),
    )


def _raise_for_status(response: httpx.Response) -> None:
    if response.status_code < 400:
        return
    payload: dict[str, Any] | None
    try:
        payload = response.json()
        if not isinstance(payload, dict):
            payload = None
    except ValueError:
        payload = None
    raise_api_error(response.status_code, payload, response.text)


class TzamClient:
    """Synchronous client. Thread-safe — build once and share."""

    def __init__(self, config: Config):
        if not config.url:
            raise ValueError("tzam: Config.url is required")
        self._cfg = Config(
            url=config.url.rstrip("/"),
            client_id=config.client_id,
            client_secret=config.client_secret,
            timeout=config.timeout,
        )
        self._http = httpx.Client(timeout=self._cfg.timeout)

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> TzamClient:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    # ── Authentication ────────────────────────────────────────────

    def login(self, email: str, password: str) -> LoginResult:
        body = {
            "email": email,
            "password": password,
            "client_id": self._cfg.client_id,
            "client_secret": self._cfg.client_secret,
        }
        return _parse_login_result(self._post("/auth/login", json=body))

    def register(self, name: str, email: str, password: str) -> LoginResult:
        body = {
            "name": name,
            "email": email,
            "password": password,
            "clientId": self._cfg.client_id,
            "clientSecret": self._cfg.client_secret,
        }
        return _parse_login_result(self._post("/auth/register/app", json=body))

    def validate_token(self, token: str) -> TokenPayload | None:
        """Confirm an access token. Returns None on 401 (expired/revoked).

        Silent failure is intentional so middleware can attempt a refresh
        without treating every stale token as an exception.
        """
        try:
            data = self._post(
                "/auth/validate",
                json={"token": token},
                headers={"Authorization": f"Bearer {token}"},
            )
        except Exception as exc:
            if getattr(exc, "status", 0) == 401:
                return None
            raise
        return TokenPayload(user_id=str(data.get("userId", "")), email=str(data.get("email", "")))

    def refresh_token(self, refresh_token: str) -> str:
        """Swap refresh for a new access token. Raises on failure."""
        data = self._post(
            "/auth/refresh",
            headers={"Cookie": f"refresh_token={refresh_token}"},
        )
        return str(data.get("accessToken", ""))

    def logout(self, access_token: str, refresh_token: str) -> None:
        """Revoke the session. Best-effort — raises only on transport errors."""
        self._post(
            "/auth/logout",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Cookie": f"refresh_token={refresh_token}",
            },
        )

    # ── Magic link / OTP ──────────────────────────────────────────

    def request_magic_link(self, email: str, redirect: str | None = None) -> None:
        self._post("/auth/magic-link", json={
            "email": email,
            "redirect": redirect,
            "client_id": self._cfg.client_id,
        })

    def request_otp(self, email: str) -> None:
        self._post("/auth/otp", json={"email": email, "client_id": self._cfg.client_id})

    def verify_otp(self, email: str, code: str) -> LoginResult:
        return _parse_login_result(self._post("/auth/otp/verify", json={"email": email, "code": code}))

    def magic_link_verify_url(self, token: str) -> str:
        return f"{self._cfg.url}/auth/magic-link/verify?token={quote(token, safe='')}"

    # ── internals ────────────────────────────────────────────────

    def _post(
        self,
        path: str,
        *,
        json: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        response = self._http.post(self._cfg.url + path, json=json, headers=headers)
        _raise_for_status(response)
        if response.status_code == 204 or not response.content:
            return {}
        try:
            data = response.json()
        except ValueError as exc:
            raise RuntimeError(f"tzam: invalid JSON from {path}") from exc
        return data if isinstance(data, dict) else {}


class AsyncTzamClient:
    """Async variant with identical method surface."""

    def __init__(self, config: Config):
        if not config.url:
            raise ValueError("tzam: Config.url is required")
        self._cfg = Config(
            url=config.url.rstrip("/"),
            client_id=config.client_id,
            client_secret=config.client_secret,
            timeout=config.timeout,
        )
        self._http = httpx.AsyncClient(timeout=self._cfg.timeout)

    async def aclose(self) -> None:
        await self._http.aclose()

    async def __aenter__(self) -> AsyncTzamClient:
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.aclose()

    async def login(self, email: str, password: str) -> LoginResult:
        body = {
            "email": email,
            "password": password,
            "client_id": self._cfg.client_id,
            "client_secret": self._cfg.client_secret,
        }
        return _parse_login_result(await self._post("/auth/login", json=body))

    async def register(self, name: str, email: str, password: str) -> LoginResult:
        body = {
            "name": name,
            "email": email,
            "password": password,
            "clientId": self._cfg.client_id,
            "clientSecret": self._cfg.client_secret,
        }
        return _parse_login_result(await self._post("/auth/register/app", json=body))

    async def validate_token(self, token: str) -> TokenPayload | None:
        try:
            data = await self._post(
                "/auth/validate",
                json={"token": token},
                headers={"Authorization": f"Bearer {token}"},
            )
        except Exception as exc:
            if getattr(exc, "status", 0) == 401:
                return None
            raise
        return TokenPayload(user_id=str(data.get("userId", "")), email=str(data.get("email", "")))

    async def refresh_token(self, refresh_token: str) -> str:
        data = await self._post(
            "/auth/refresh",
            headers={"Cookie": f"refresh_token={refresh_token}"},
        )
        return str(data.get("accessToken", ""))

    async def logout(self, access_token: str, refresh_token: str) -> None:
        await self._post(
            "/auth/logout",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Cookie": f"refresh_token={refresh_token}",
            },
        )

    async def request_magic_link(self, email: str, redirect: str | None = None) -> None:
        await self._post("/auth/magic-link", json={
            "email": email,
            "redirect": redirect,
            "client_id": self._cfg.client_id,
        })

    async def request_otp(self, email: str) -> None:
        await self._post("/auth/otp", json={"email": email, "client_id": self._cfg.client_id})

    async def verify_otp(self, email: str, code: str) -> LoginResult:
        return _parse_login_result(await self._post("/auth/otp/verify", json={"email": email, "code": code}))

    def magic_link_verify_url(self, token: str) -> str:
        return f"{self._cfg.url}/auth/magic-link/verify?token={quote(token, safe='')}"

    async def _post(
        self,
        path: str,
        *,
        json: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        response = await self._http.post(self._cfg.url + path, json=json, headers=headers)
        _raise_for_status(response)
        if response.status_code == 204 or not response.content:
            return {}
        try:
            data = response.json()
        except ValueError as exc:
            raise RuntimeError(f"tzam: invalid JSON from {path}") from exc
        return data if isinstance(data, dict) else {}
