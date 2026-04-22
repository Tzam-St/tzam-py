# Tzam Python SDK

Official Python client for the [Tzam Identity Provider](https://tzam.online).

**Tzam** (צם) — Hebrew for *"to watch and protect"*.

Single dependency (`httpx`). Sync and async clients. ASGI middleware for FastAPI/Starlette, WSGI middleware for Flask. Cookie contract identical to the [`@tzam-st/tzam`](https://www.npmjs.com/package/@tzam-st/tzam) Node SDK and [`github.com/Tzam-St/tzam-go`](https://github.com/Tzam-St/tzam-go) Go SDK — Python, Node and Go services can share a session on the same domain.

## Install

```bash
pip install tzam
# or
uv add tzam
# or
poetry add tzam
```

## Client

### Sync

```python
from tzam import TzamClient, Config

client = TzamClient(Config(
    url="https://tzam.online",
    client_id="your-client-id",
    client_secret="your-client-secret",
))

result = client.login("user@example.com", "password")
print(result.user.email, result.access_token)
```

### Async

```python
from tzam import AsyncTzamClient, Config

async with AsyncTzamClient(Config(url="https://tzam.online", client_id="...", client_secret="...")) as client:
    result = await client.login("user@example.com", "password")
    print(result.user.email)
```

### Methods

| Method | Returns | Description |
|---|---|---|
| `login(email, password)` | `LoginResult` | Password login |
| `register(name, email, password)` | `LoginResult` | App user registration |
| `validate_token(token)` | `TokenPayload \| None` | **Returns `None` on 401** (silent failure for middleware refresh) |
| `refresh_token(rt)` | `str` | New access token |
| `logout(at, rt)` | `None` | Revoke session |
| `request_magic_link(email, redirect=None)` | `None` | Send magic link |
| `request_otp(email)` | `None` | Send OTP code |
| `verify_otp(email, code)` | `LoginResult` | Exchange OTP for tokens |
| `magic_link_verify_url(token)` | `str` | Build verification URL |

### Errors

All failed requests raise a subclass of `tzam.TzamError`. Catch specific ones:

```python
from tzam import AuthInvalidCredentials, AuthAccountInactive, TzamError

try:
    client.login(email, password)
except AuthInvalidCredentials:
    show("wrong email or password")
except AuthAccountInactive:
    show("account disabled, contact admin")
except TzamError as exc:
    log.error("tzam failed: %s (%s) %s", exc.status, exc.code, exc.message)
```

**Specific exceptions:** `AuthInvalidCredentials`, `AuthAccountInactive`, `AuthUserNotRegistered`, `AuthEmailExists`, `AuthTokenInvalid`, `AuthTokenExpired`, `AuthSessionRevoked`, `AuthRefreshFailed`.

## ASGI middleware (FastAPI · Starlette · Litestar)

Validates the `session` cookie on every non-public request. Auto-refreshes with the `refresh_token` cookie. Injects `X-User-ID` / `X-User-Email` headers and `request.scope["tzam_user"]`.

```python
from fastapi import FastAPI, Request
from tzam import Config
from tzam.asgi import TzamASGIMiddleware

app = FastAPI()
app.add_middleware(
    TzamASGIMiddleware,
    config=Config(url="https://tzam.online", client_id="...", client_secret="..."),
    public_routes=["/", "/auth/login", "/api/public"],
    login_url="/auth/login",
)

@app.get("/dashboard")
async def dashboard(request: Request):
    user = request.scope["tzam_user"]  # TokenPayload
    return {"email": user.email, "id": user.user_id}
```

## WSGI middleware (Flask · Django · plain WSGI)

```python
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

@app.get("/dashboard")
def dashboard():
    email = request.headers.get("X-User-Email")
    return f"hi {email}"
```

### Django integration

Wrap the WSGI or ASGI app in your `wsgi.py` / `asgi.py` — Django supports both.

```python
# wsgi.py
import os
from django.core.wsgi import get_wsgi_application
from tzam import Config
from tzam.wsgi import TzamWSGIMiddleware

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "myproject.settings")
application = TzamWSGIMiddleware(
    get_wsgi_application(),
    config=Config(url="https://tzam.online", client_id="...", client_secret="..."),
)
```

## Configuration

```python
@dataclass(frozen=True)
class Config:
    url: str                # e.g. "https://tzam.online"
    client_id: str = ""     # Application.clientId
    client_secret: str = "" # Application.clientSecret
    timeout: float = 10.0   # HTTP timeout in seconds
```

Middleware constructors accept:

```python
TzamASGIMiddleware(
    app,
    config,
    public_routes=["/", "/auth/login", "/auth/register", "/api/auth"],
    login_url="/auth/login",
    secure=True,        # set False for http:// development
    cookie_path="/",
)
```

## Thread-safety

`TzamClient` and `AsyncTzamClient` are safe for concurrent use. Build once at app startup and share.

## Testing

```bash
pip install -e ".[dev]"
pytest
```

Tests use `pytest-httpx` to mock outbound calls — no network access required.

## License

MIT © Tzam-St
