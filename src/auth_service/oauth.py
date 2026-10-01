import base64
import hashlib
import json
import secrets
from typing import Any
from urllib.parse import urlencode

from flask import Blueprint, current_app, redirect, request
from pydantic import EmailStr, TypeAdapter, ValidationError

from auth_service.api import limited, service
from auth_service.errors import Problem
from auth_service.security import digest

oauth_bp = Blueprint("oauth", __name__)


def configured() -> Any:
    settings = current_app.extensions["settings"]
    if not settings.github_client_id:
        raise Problem(503, "oauth_unconfigured", "GitHub OAuth is not configured")
    return settings


@oauth_bp.get("/start")
@limited
def start() -> Any:
    settings = configured()
    state, binding, verifier = (secrets.token_urlsafe(32) for _ in range(3))
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=")
    current_app.extensions["redis"].setex(
        f"oauth:{digest(state)}",
        300,
        json.dumps({"binding": digest(binding), "verifier": verifier}),
    )
    callback = settings.public_url.rstrip("/") + "/api/v1/auth/oauth/github/callback"
    response = redirect(
        "https://github.com/login/oauth/authorize?"
        + urlencode(
            {
                "client_id": settings.github_client_id,
                "redirect_uri": callback,
                "state": state,
                "scope": "read:user user:email",
                "code_challenge": challenge.decode(),
                "code_challenge_method": "S256",
            }
        )
    )
    response.set_cookie(
        "oauth_binding",
        binding,
        max_age=300,
        httponly=True,
        secure=settings.public_url.startswith("https:"),
        samesite="Lax",
        path="/api/v1/auth/oauth/github",
    )
    return response


@oauth_bp.get("/callback")
@limited
def callback() -> Any:
    settings = configured()
    state, code = request.args.get("state", ""), request.args.get("code", "")
    binding = request.cookies.get("oauth_binding", "")
    if not state or not code or len(state) > 100 or len(code) > 1024 or not binding:
        raise Problem(400, "oauth_state_invalid", "Invalid OAuth callback")
    raw = current_app.extensions["redis"].getdel(f"oauth:{digest(state)}")
    if not raw:
        raise Problem(400, "oauth_state_invalid", "Invalid or expired OAuth state")
    attempt = json.loads(raw)
    if not secrets.compare_digest(attempt["binding"], digest(binding)):
        raise Problem(400, "oauth_state_invalid", "Invalid OAuth browser binding")
    callback_url = settings.public_url.rstrip("/") + "/api/v1/auth/oauth/github/callback"
    # No database query/transaction precedes these external requests.
    profile, email = current_app.extensions["github"].identity(
        code,
        attempt["verifier"],
        settings.github_client_id,
        settings.github_client_secret,
        callback_url,
    )
    try:
        email = str(TypeAdapter(EmailStr).validate_python(email)).casefold()
    except ValidationError as exc:
        raise Problem(502, "oauth_email_invalid", "Invalid GitHub email") from exc
    response = current_app.make_response(
        service().oauth_login(str(profile.id), profile.login, profile.name or profile.login, email)
    )
    response.delete_cookie("oauth_binding", path="/api/v1/auth/oauth/github")
    return response
