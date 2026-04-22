"""FastAPI example. Run:

    pip install tzam fastapi uvicorn
    export TZAM_URL=https://tzam.online TZAM_CLIENT_ID=... TZAM_CLIENT_SECRET=...
    uvicorn fastapi_app:app --reload
"""

from __future__ import annotations

import os

from fastapi import FastAPI, Request

from tzam import Config
from tzam.asgi import TzamASGIMiddleware

app = FastAPI()

app.add_middleware(
    TzamASGIMiddleware,
    config=Config(
        url=os.environ["TZAM_URL"],
        client_id=os.environ["TZAM_CLIENT_ID"],
        client_secret=os.environ["TZAM_CLIENT_SECRET"],
    ),
    public_routes=["/", "/health", "/auth/login", "/auth/callback"],
    login_url="/auth/login",
    secure=False,  # local http://
)


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/dashboard")
async def dashboard(request: Request):
    user = request.scope["tzam_user"]
    return {"email": user.email, "id": user.user_id}
