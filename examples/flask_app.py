"""Flask example. Run:

    pip install tzam flask
    export TZAM_URL=https://tzam.online TZAM_CLIENT_ID=... TZAM_CLIENT_SECRET=...
    flask --app flask_app run
"""

from __future__ import annotations

import os

from flask import Flask, request

from tzam import Config
from tzam.wsgi import TzamWSGIMiddleware

app = Flask(__name__)
app.wsgi_app = TzamWSGIMiddleware(
    app.wsgi_app,
    config=Config(
        url=os.environ["TZAM_URL"],
        client_id=os.environ["TZAM_CLIENT_ID"],
        client_secret=os.environ["TZAM_CLIENT_SECRET"],
    ),
    public_routes=["/", "/health", "/auth/login"],
    login_url="/auth/login",
    secure=False,
)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/dashboard")
def dashboard():
    email = request.headers.get("X-User-Email")
    user_id = request.headers.get("X-User-ID")
    return f"hi {email} ({user_id})"
