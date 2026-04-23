"""Typed data structures returned by the Tzam API.

We use dataclasses instead of pydantic to keep the SDK free of heavy deps.
JSON <-> dataclass conversion is handled explicitly in _client.py.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal


@dataclass(frozen=True, slots=True)
class Config:
    """Connection details for the Tzam IdP."""

    url: str
    """Base URL of the IdP, e.g. 'https://tzam.online'. Trailing slash is stripped."""

    client_id: str = ""
    """Application.clientId registered in the admin panel."""

    client_secret: str = ""
    """Application.clientSecret. Required for password/OAuth flows."""

    timeout: float = 10.0
    """HTTP timeout in seconds."""


@dataclass(frozen=True, slots=True)
class User:
    """Subset of user data returned by login/register/OAuth callback."""

    id: str
    email: str
    name: str


@dataclass(frozen=True, slots=True)
class LoginResult:
    """Returned by login, register, and verify_otp."""

    access_token: str
    refresh_token: str
    user: User


@dataclass(frozen=True, slots=True)
class TokenPayload:
    """Subset of JWT claims confirmed by /auth/validate.

    Intentionally narrow — richer claims live inside the JWT itself and
    should be verified with PyJWT + JWKS if needed.
    """

    user_id: str
    email: str


SameSite = Literal["strict", "lax", "none"]


@dataclass(frozen=True, slots=True)
class OAuthMethods:
    """Which third-party OAuth providers are currently enabled for the app."""

    github: bool = False
    google: bool = False


@dataclass(frozen=True, slots=True)
class AppMethods:
    """Which auth entry points are active for the app."""

    password: bool = False
    magic_link: bool = False
    otp: bool = False
    oauth: OAuthMethods = field(default_factory=OAuthMethods)


@dataclass(frozen=True, slots=True)
class AppConfig:
    """Returned by ``get_auth_methods``.

    Lets the client decide what auth UI to render without relying on
    ``forgot_password`` / magic-link status codes — those endpoints are
    silent by design so they can't be probed to enumerate which methods
    the app exposes.
    """

    client_id: str
    active: bool
    methods: AppMethods
