from collections.abc import Callable
from contextlib import ExitStack
from functools import wraps
from typing import Any

import jwt
from flask import Blueprint, current_app, g, request
from pydantic import BaseModel
from sqlalchemy import select

from auth_service.errors import Problem, unauthorized
from auth_service.models import AuthSession, SecurityEvent, User, now
from auth_service.schemas import (
    AdminPatch,
    EmailInput,
    Login,
    PasswordChange,
    Register,
    Reset,
    TokenInput,
    UserPatch,
)
from auth_service.security import decode_token, digest
from auth_service.services import AuthService, ProfileService

bp = Blueprint("api", __name__)


def parse[T: BaseModel](schema: type[T]) -> T:
    return schema.model_validate(request.get_json())


def service() -> AuthService:
    return AuthService(
        g.db, current_app.extensions["settings"], current_app.extensions["mail"], g.request_id
    )


def limited(fn: Callable[..., Any]) -> Callable[..., Any]:
    @wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        limiter = current_app.extensions["auth_limiter"]
        settings = current_app.extensions["settings"]
        with ExitStack() as stack:
            stack.enter_context(limiter.limit(settings.auth_limit))
            body = request.get_json(silent=True)
            if isinstance(body, dict) and isinstance(body.get("email"), str):
                account = digest(body["email"].strip().casefold())
                stack.enter_context(
                    limiter.limit(settings.account_limit, key_func=lambda: account, scope="account")
                )
            return fn(*args, **kwargs)

    return wrapper


def protected(admin: bool = False) -> Callable[..., Any]:
    def decorate(fn: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            header = request.headers.get("Authorization", "")
            if not header.startswith("Bearer "):
                raise unauthorized()
            try:
                claims = decode_token(current_app.extensions["settings"], header[7:], "access")
            except jwt.InvalidTokenError as exc:
                raise unauthorized() from exc
            user = g.db.get(User, claims["sub"])
            session = g.db.get(AuthSession, claims["sid"])
            if (
                not user
                or user.disabled
                or not user.verified
                or not session
                or session.revoked
                or session.user_id != user.id
                or session.expires_at <= now()
            ):
                raise unauthorized()
            if admin and user.role != "admin":
                raise Problem(403, "forbidden", "Administrator access required")
            g.user, g.auth_session = user, session
            return fn(*args, **kwargs)

        return wrapper

    return decorate


def user_json(user: User) -> dict[str, Any]:
    return {
        "id": user.id,
        "email": user.email,
        "display_name": user.display_name,
        "role": user.role,
        "verified": user.verified,
        "disabled": user.disabled,
    }


@bp.post("/auth/register")
@limited
def register() -> tuple[dict[str, str], int]:
    data = parse(Register)
    service().register(str(data.email), data.password, data.display_name)
    return {"message": "If eligible, a verification message has been sent"}, 202


@bp.post("/auth/login")
@limited
def login() -> dict[str, Any]:
    data = parse(Login)
    return service().login(str(data.email), data.password)


@bp.post("/auth/refresh")
@limited
def refresh() -> dict[str, Any]:
    raw = parse(TokenInput).token
    try:
        claims = decode_token(current_app.extensions["settings"], raw, "refresh")
    except jwt.InvalidTokenError as exc:
        raise unauthorized() from exc
    return service().refresh(claims, raw)


@bp.post("/auth/logout")
@protected()
def logout() -> tuple[str, int]:
    service().logout(g.auth_session.id, g.user.id)
    return "", 204


@bp.post("/auth/logout-all")
@protected()
def logout_all() -> tuple[str, int]:
    service().logout(g.auth_session.id, g.user.id, all_sessions=True)
    return "", 204


@bp.post("/auth/password/change")
@limited
@protected()
def change_password() -> tuple[str, int]:
    data = parse(PasswordChange)
    user_id = g.user.id
    g.db.rollback()
    service().change_password(user_id, data.current_password, data.new_password)
    return "", 204


@bp.post("/auth/password/forgot")
@limited
def forgot() -> tuple[dict[str, str], int]:
    service().request_action(str(parse(EmailInput).email), "reset")
    return {"message": "If eligible, a recovery message has been sent"}, 202


@bp.post("/auth/password/reset")
@limited
def reset() -> tuple[str, int]:
    data = parse(Reset)
    service().consume_action(data.token, "reset", data.password)
    return "", 204


@bp.post("/auth/email-verification/request")
@limited
def verification_request() -> tuple[dict[str, str], int]:
    service().request_action(str(parse(EmailInput).email), "verify")
    return {"message": "If eligible, a verification message has been sent"}, 202


@bp.post("/auth/email-verification/confirm")
@limited
def verification_confirm() -> tuple[str, int]:
    service().consume_action(parse(TokenInput).token, "verify")
    return "", 204


@bp.get("/users/me")
@protected()
def me() -> dict[str, Any]:
    return user_json(g.user)


@bp.patch("/users/me")
@protected()
def patch_me() -> dict[str, Any]:
    return user_json(service().update_name(g.user, parse(UserPatch).display_name))


@bp.get("/users/me/external-profile")
@protected()
def external_profile() -> dict[str, Any]:
    return (
        ProfileService(g.db, current_app.extensions["github"])
        .current_profile(g.user.id)
        .model_dump()
    )


@bp.get("/admin/users")
@protected(admin=True)
def admin_users() -> dict[str, Any]:
    try:
        page = int(request.args.get("page", "1"))
        if not 1 <= page <= 10000:
            raise ValueError
    except ValueError as exc:
        raise Problem(422, "validation_error", "Invalid page") from exc
    users = g.db.scalars(
        select(User).order_by(User.created_at, User.id).offset((page - 1) * 50).limit(50)
    )
    return {"items": [user_json(user) for user in users], "page": page}


@bp.get("/admin/users/<user_id>")
@protected(admin=True)
def admin_user(user_id: str) -> dict[str, Any]:
    user = g.db.get(User, user_id)
    if not user:
        raise Problem(404, "not_found", "User not found")
    return user_json(user)


@bp.patch("/admin/users/<user_id>")
@protected(admin=True)
def admin_patch(user_id: str) -> dict[str, Any]:
    data = parse(AdminPatch)
    return user_json(service().admin_update(g.user.id, user_id, data.role, data.disabled))


@bp.get("/admin/security-events")
@protected(admin=True)
def security_events() -> dict[str, Any]:
    events = g.db.scalars(
        select(SecurityEvent).order_by(SecurityEvent.created_at.desc(), SecurityEvent.id).limit(100)
    )
    return {
        "items": [
            {
                "id": event.id,
                "kind": event.kind,
                "user_id": event.user_id,
                "target_id": event.target_id,
                "request_id": event.request_id,
                "created_at": event.created_at.isoformat(),
            }
            for event in events
        ]
    }
