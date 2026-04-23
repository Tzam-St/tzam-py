"""Tzam Python SDK — official client for the Tzam Identity Provider.

Public API (stable):

    from tzam import TzamClient, AsyncTzamClient, Config
    from tzam import TzamError, AuthInvalidCredentials, AuthTokenExpired
    from tzam.asgi import TzamASGIMiddleware
    from tzam.wsgi import TzamWSGIMiddleware

See https://tzam.online/docs/sdks/python for usage.
"""

from ._client import AsyncTzamClient, TzamClient
from ._errors import (
    APP_REDIRECT_INVALID,
    AUTH_ACCOUNT_INACTIVE,
    AUTH_EMAIL_EXISTS,
    AUTH_INVALID_CREDENTIALS,
    AUTH_REFRESH_FAILED,
    AUTH_SESSION_REVOKED,
    AUTH_TOKEN_EXPIRED,
    AUTH_TOKEN_INVALID,
    AUTH_USER_NOT_REGISTERED,
    AuthAccountInactive,
    AuthEmailExists,
    AuthInvalidCredentials,
    AuthRefreshFailed,
    AuthSessionRevoked,
    AuthTokenExpired,
    AuthTokenInvalid,
    AuthUserNotRegistered,
    TzamError,
)
from ._types import AppConfig, AppMethods, Config, LoginResult, OAuthMethods, TokenPayload, User

__version__ = "0.1.0"

__all__ = [
    # client
    "TzamClient",
    "AsyncTzamClient",
    # types
    "Config",
    "User",
    "LoginResult",
    "TokenPayload",
    "AppConfig",
    "AppMethods",
    "OAuthMethods",
    # errors
    "TzamError",
    "AuthInvalidCredentials",
    "AuthAccountInactive",
    "AuthUserNotRegistered",
    "AuthEmailExists",
    "AuthTokenInvalid",
    "AuthTokenExpired",
    "AuthSessionRevoked",
    "AuthRefreshFailed",
    # error codes
    "AUTH_INVALID_CREDENTIALS",
    "AUTH_ACCOUNT_INACTIVE",
    "AUTH_USER_NOT_REGISTERED",
    "AUTH_EMAIL_EXISTS",
    "AUTH_TOKEN_INVALID",
    "AUTH_TOKEN_EXPIRED",
    "AUTH_SESSION_REVOKED",
    "AUTH_REFRESH_FAILED",
    "APP_REDIRECT_INVALID",
]
