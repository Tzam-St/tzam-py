"""Error codes and exception classes for the Tzam Python SDK.

All SDK-raised errors inherit from TzamError. Specific subclasses exist
for the codes documented in /docs/guides/sessions-and-refresh so callers
can use `except AuthInvalidCredentials` instead of string matching.
"""

from __future__ import annotations

# Error code constants — mirror the Go and Node SDKs byte-for-byte.
AUTH_INVALID_CREDENTIALS = "AUTH_INVALID_CREDENTIALS"
AUTH_ACCOUNT_INACTIVE = "AUTH_ACCOUNT_INACTIVE"
AUTH_USER_NOT_REGISTERED = "AUTH_USER_NOT_REGISTERED"
AUTH_EMAIL_EXISTS = "AUTH_EMAIL_EXISTS"
AUTH_TOKEN_INVALID = "AUTH_TOKEN_INVALID"
AUTH_TOKEN_EXPIRED = "AUTH_TOKEN_EXPIRED"
AUTH_SESSION_REVOKED = "AUTH_SESSION_REVOKED"
AUTH_REFRESH_FAILED = "AUTH_REFRESH_FAILED"

OAUTH_PROVIDER_DISABLED = "OAUTH_PROVIDER_DISABLED"
OAUTH_CODE_INVALID = "OAUTH_CODE_INVALID"
OAUTH_CODE_EXPIRED = "OAUTH_CODE_EXPIRED"

APP_CLIENT_INVALID = "APP_CLIENT_INVALID"
APP_REDIRECT_INVALID = "APP_REDIRECT_INVALID"


class TzamError(Exception):
    """Base class for every exception raised by the SDK.

    Attributes
    ----------
    status:   HTTP status from the IdP response (0 if the error is local).
    code:     Tzam error code, empty string if absent.
    message:  Human-readable message (may be translated by the IdP).
    """

    def __init__(self, message: str = "", *, status: int = 0, code: str = ""):
        self.status = status
        self.code = code
        self.message = message
        super().__init__(self._format())

    def _format(self) -> str:
        if self.code:
            return f"tzam: {self.code} ({self.status}) {self.message}"
        if self.status:
            return f"tzam: HTTP {self.status} {self.message}"
        return f"tzam: {self.message}" if self.message else "tzam: unknown error"


class AuthInvalidCredentials(TzamError):
    """Wrong email or password."""


class AuthAccountInactive(TzamError):
    """Account was disabled by the admin."""


class AuthUserNotRegistered(TzamError):
    """User does not exist (app login requires prior registration)."""


class AuthEmailExists(TzamError):
    """Email already in use during register."""


class AuthTokenInvalid(TzamError):
    """Access token is malformed or has a bad signature."""


class AuthTokenExpired(TzamError):
    """Access or refresh token is past its TTL."""


class AuthSessionRevoked(TzamError):
    """Session was revoked by admin or via logout — do not retry."""


class AuthRefreshFailed(TzamError):
    """Refresh attempt failed for any reason."""


# Map IdP error codes to exception classes. Unlisted codes bubble as
# generic TzamError so the SDK stays forward-compatible with new codes.
_CODE_TO_EXC: dict[str, type[TzamError]] = {
    AUTH_INVALID_CREDENTIALS: AuthInvalidCredentials,
    AUTH_ACCOUNT_INACTIVE: AuthAccountInactive,
    AUTH_USER_NOT_REGISTERED: AuthUserNotRegistered,
    AUTH_EMAIL_EXISTS: AuthEmailExists,
    AUTH_TOKEN_INVALID: AuthTokenInvalid,
    AUTH_TOKEN_EXPIRED: AuthTokenExpired,
    AUTH_SESSION_REVOKED: AuthSessionRevoked,
    AUTH_REFRESH_FAILED: AuthRefreshFailed,
}


def raise_api_error(status: int, payload: dict[str, object] | None, body_text: str = "") -> None:
    """Raise the most specific TzamError subclass for the given response."""
    payload = payload or {}
    code = str(payload.get("code") or "")
    message = str(payload.get("message") or payload.get("error") or body_text).strip()

    exc_cls = _CODE_TO_EXC.get(code, TzamError)
    raise exc_cls(message, status=status, code=code)
