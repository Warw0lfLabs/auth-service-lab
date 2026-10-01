import secrets
from datetime import timedelta
from typing import Any

from sqlalchemy import select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from auth_service.config import Settings
from auth_service.email import DevelopmentEmail
from auth_service.errors import Problem, unauthorized
from auth_service.github import GitHubClient, Profile
from auth_service.models import (
    ActionToken,
    AuthSession,
    OAuthIdentity,
    RefreshToken,
    SecurityEvent,
    User,
    identifier,
    now,
)
from auth_service.security import digest, encode_token, hasher, verify_password


class AuthService:
    def __init__(
        self, db: Session, settings: Settings, mail: DevelopmentEmail, request_id: str
    ) -> None:
        self.db = db
        self.settings = settings
        self.mail = mail
        self.request_id = request_id

    def audit(self, kind: str, user_id: str | None = None, target_id: str | None = None) -> None:
        self.db.add(
            SecurityEvent(
                kind=kind, user_id=user_id, target_id=target_id, request_id=self.request_id
            )
        )

    def action(self, user: User, purpose: str) -> str:
        self.db.execute(
            update(ActionToken)
            .where(ActionToken.user_id == user.id, ActionToken.purpose == purpose)
            .values(consumed=True)
        )
        raw = secrets.token_urlsafe(32)
        self.db.add(
            ActionToken(
                user_id=user.id,
                purpose=purpose,
                digest=digest(raw),
                expires_at=now() + timedelta(minutes=30),
            )
        )
        return raw

    def register(self, email: str, password: str, display_name: str) -> None:
        # Generic duplicate responses avoid exposing account existence.
        if self.db.scalar(select(User).where(User.email == email)):
            return
        user = User(email=email, password_hash=hasher.hash(password), display_name=display_name)
        self.db.add(user)
        try:
            self.db.flush()
        except IntegrityError:
            self.db.rollback()
            if self.db.scalar(select(User.id).where(User.email == email)):
                return
            raise
        raw = self.action(user, "verify")
        self.audit("registered", user.id)
        self.db.commit()
        self.mail.send(email, "verify", raw)

    def issue(self, user: User, session: AuthSession) -> dict[str, Any]:
        remaining = int((session.expires_at - now()).total_seconds())
        seconds = min(self.settings.refresh_seconds, remaining)
        jti = identifier()
        refresh = encode_token(self.settings, user.id, session.id, jti, "refresh", seconds)
        self.db.add(
            RefreshToken(
                id=jti,
                session_id=session.id,
                digest=digest(refresh),
                expires_at=now() + timedelta(seconds=seconds),
            )
        )
        access = encode_token(
            self.settings,
            user.id,
            session.id,
            identifier(),
            "access",
            min(self.settings.access_seconds, remaining),
        )
        return {
            "access_token": access,
            "refresh_token": refresh,
            "token_type": "Bearer",
            "expires_in": min(self.settings.access_seconds, remaining),
        }

    def new_session(self, user: User) -> dict[str, Any]:
        if user.disabled or not user.verified:
            raise unauthorized()
        session = AuthSession(
            user_id=user.id, expires_at=now() + timedelta(seconds=self.settings.session_seconds)
        )
        self.db.add(session)
        self.db.flush()
        result = self.issue(user, session)
        self.audit("login", user.id)
        self.db.commit()
        return result

    def login(self, email: str, password: str) -> dict[str, Any]:
        user = self.db.scalar(select(User).where(User.email == email).with_for_update())
        valid = verify_password(user.password_hash if user else None, password)
        if not valid or not user or user.disabled or not user.verified:
            self.audit("login_failed", user.id if user else None)
            self.db.commit()
            raise unauthorized()
        if user.password_hash and hasher.check_needs_rehash(user.password_hash):
            user.password_hash = hasher.hash(password)
        return self.new_session(user)

    def refresh(self, claims: dict[str, Any], raw: str) -> dict[str, Any]:
        # All flows lock user before session; password changes cannot race rotation.
        user = self.db.scalar(select(User).where(User.id == claims["sub"]).with_for_update())
        session = self.db.scalar(
            select(AuthSession)
            .where(AuthSession.id == claims["sid"], AuthSession.user_id == claims["sub"])
            .with_for_update()
        )
        token = self.db.get(RefreshToken, claims["jti"])
        if (
            not user
            or user.disabled
            or not user.verified
            or not session
            or session.revoked
            or session.expires_at <= now()
            or not token
            or token.session_id != session.id
            or token.expires_at <= now()
            or not secrets.compare_digest(token.digest, digest(raw))
        ):
            raise unauthorized()
        if token.consumed:
            session.revoked = True
            self.audit("refresh_reuse", user.id)
            # Commit revocation before returning an error; request rollback must not undo it.
            self.db.commit()
            raise unauthorized()
        token.consumed = True
        result = self.issue(user, session)
        self.audit("refreshed", user.id)
        self.db.commit()
        return result

    def revoke_all(self, user_id: str) -> None:
        self.db.execute(
            update(AuthSession).where(AuthSession.user_id == user_id).values(revoked=True)
        )

    def request_action(self, email: str, purpose: str) -> None:
        user = self.db.scalar(select(User).where(User.email == email).with_for_update())
        if not user or user.disabled or (purpose == "verify" and user.verified):
            return
        if purpose == "reset" and not user.password_hash:
            return
        raw = self.action(user, purpose)
        self.audit(f"{purpose}_requested", user.id)
        self.db.commit()
        self.mail.send(email, purpose, raw)

    def consume_action(self, raw: str, purpose: str, password: str | None = None) -> None:
        candidate = self.db.scalar(select(ActionToken).where(ActionToken.digest == digest(raw)))
        if not candidate:
            raise Problem(400, "invalid_action_token", "Invalid or expired token")
        user_id = candidate.user_id
        self.db.rollback()
        user = self.db.scalar(select(User).where(User.id == user_id).with_for_update())
        token = self.db.scalar(
            select(ActionToken).where(ActionToken.digest == digest(raw)).with_for_update()
        )
        if not user or user.disabled or not token or token.consumed or token.expires_at <= now():
            raise Problem(400, "invalid_action_token", "Invalid or expired token")
        token.consumed = True
        if purpose != token.purpose:
            raise Problem(400, "invalid_action_token", "Invalid or expired token")
        if purpose == "verify":
            user.verified = True
        else:
            assert password is not None
            user.password_hash = hasher.hash(password)
            self.revoke_all(user.id)
            self.db.execute(
                update(ActionToken)
                .where(ActionToken.user_id == user.id, ActionToken.purpose == "reset")
                .values(consumed=True)
            )
        self.audit(f"{purpose}_completed", user.id)
        self.db.commit()

    def change_password(self, user_id: str, current: str, new: str) -> None:
        user = self.db.scalar(select(User).where(User.id == user_id).with_for_update())
        if not user or user.disabled or not verify_password(user.password_hash, current):
            raise unauthorized()
        user.password_hash = hasher.hash(new)
        self.revoke_all(user.id)
        self.db.execute(
            update(ActionToken)
            .where(ActionToken.user_id == user.id, ActionToken.purpose == "reset")
            .values(consumed=True)
        )
        self.audit("password_changed", user.id)
        self.db.commit()

    def logout(self, session_id: str, user_id: str, all_sessions: bool = False) -> None:
        self.db.scalar(select(User).where(User.id == user_id).with_for_update())
        if all_sessions:
            self.revoke_all(user_id)
        else:
            self.db.execute(
                update(AuthSession)
                .where(AuthSession.id == session_id, AuthSession.user_id == user_id)
                .values(revoked=True)
            )
        self.audit("logout_all" if all_sessions else "logout", user_id)
        self.db.commit()

    def admin_update(
        self, actor_id: str, user_id: str, role: str | None, disabled: bool | None
    ) -> User:
        self.db.rollback()
        # Serialize mutations so two administrators cannot remove each other concurrently.
        self.db.execute(text("SELECT pg_advisory_xact_lock(19012026)"))
        actor = self.db.get(User, actor_id)
        if not actor or actor.disabled or actor.role != "admin":
            raise Problem(403, "forbidden", "Administrator access required")
        user = self.db.scalar(select(User).where(User.id == user_id).with_for_update())
        if not user:
            raise Problem(404, "not_found", "User not found")
        if user.role == "admin" and not user.disabled and (role == "user" or disabled):
            others = self.db.scalar(
                select(User.id).where(
                    User.role == "admin", User.disabled.is_(False), User.id != user.id
                )
            )
            if not others:
                raise Problem(409, "last_admin", "Cannot remove the last active administrator")
        if role is not None:
            user.role = role
        if disabled is not None:
            user.disabled = disabled
            if disabled:
                self.revoke_all(user.id)
        self.audit("admin_user_updated", actor_id, user.id)
        self.db.commit()
        return user

    def oauth_login(self, subject: str, handle: str, name: str, email: str) -> dict[str, Any]:
        identity = self.db.scalar(
            select(OAuthIdentity).where(
                OAuthIdentity.provider == "github", OAuthIdentity.subject == subject
            )
        )
        if identity:
            user = self.db.scalar(select(User).where(User.id == identity.user_id).with_for_update())
            identity.handle = handle
        else:
            if self.db.scalar(select(User).where(User.email == email)):
                raise Problem(
                    409, "oauth_account_conflict", "Email already belongs to a local account"
                )
            user = User(email=email, verified=True, display_name=name[:100])
            self.db.add(user)
            self.db.flush()
            self.db.add(OAuthIdentity(user_id=user.id, subject=subject, handle=handle))
        if not user:
            raise unauthorized()
        return self.new_session(user)

    def update_name(self, user: User, name: str) -> User:
        user.display_name = name
        self.audit("profile_updated", user.id)
        self.db.commit()
        return user


class ProfileService:
    def __init__(self, db: Session, github: "GitHubClient") -> None:
        self.db = db
        self.github = github

    def current_profile(self, user_id: str) -> "Profile":
        identity = self.db.scalar(select(OAuthIdentity).where(OAuthIdentity.user_id == user_id))
        if not identity:
            raise Problem(404, "profile_not_connected", "No GitHub identity connected")
        handle = identity.handle
        # Release the read transaction before touching the network.
        self.db.rollback()
        return self.github.profile(handle)
