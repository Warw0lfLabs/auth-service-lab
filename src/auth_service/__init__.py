import logging
import uuid
from urllib.parse import urlparse

import click
import redis
from flask import Flask, Response, g, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from pydantic import ValidationError
from sqlalchemy import create_engine, select, text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import sessionmaker
from werkzeug.exceptions import HTTPException

from auth_service.config import Settings
from auth_service.email import DevelopmentEmail
from auth_service.errors import Problem
from auth_service.github import GitHubClient
from auth_service.models import User
from auth_service.schemas import Register
from auth_service.security import hasher


def create_app(settings: Settings | None = None) -> Flask:
    settings = settings or Settings.from_env()
    settings.validate()
    app = Flask(__name__)
    app.config.update(
        MAX_CONTENT_LENGTH=16384,
        RATELIMIT_HEADERS_ENABLED=True,
        TRUSTED_HOSTS=[urlparse(settings.public_url).hostname, "localhost", "127.0.0.1"],
    )
    engine = create_engine(
        settings.database_url, pool_pre_ping=True, connect_args={"connect_timeout": 3}
    )
    app.extensions.update(
        settings=settings,
        engine=engine,
        sessions=sessionmaker(engine, expire_on_commit=False),
        mail=DevelopmentEmail(settings.mail_dir),
        github=GitHubClient(),
        redis=redis.Redis.from_url(settings.redis_url, socket_connect_timeout=2, socket_timeout=2),
    )
    limiter = Limiter(
        get_remote_address,
        app=app,
        storage_uri=settings.redis_url,
        storage_options={"socket_connect_timeout": 2, "socket_timeout": 2},
        swallow_errors=False,
        in_memory_fallback_enabled=False,
    )
    app.extensions["auth_limiter"] = limiter

    @app.before_request
    def begin() -> None:
        g.request_id = str(uuid.uuid4())
        g.db = app.extensions["sessions"]()

    @app.teardown_request
    def close(_error: BaseException | None) -> None:
        if "db" in g:
            g.db.close()

    @app.after_request
    def headers(response: Response) -> Response:
        response.headers["X-Request-ID"] = g.get("request_id", "")
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    @app.errorhandler(Exception)
    def error(exc: Exception) -> tuple[Response, int]:
        g.request_id = g.get("request_id") or str(uuid.uuid4())
        if "db" in g:
            g.db.rollback()
        if isinstance(exc, Problem):
            status, code, detail = exc.status, exc.code, exc.detail
        elif isinstance(exc, ValidationError):
            status, code, detail = 422, "validation_error", "Request fields are invalid"
        elif isinstance(exc, IntegrityError):
            status, code, detail = 409, "conflict", "Operation conflicts with existing data"
        elif isinstance(exc, (SQLAlchemyError, redis.RedisError)):
            status, code, detail = 503, "dependency_unavailable", "Required service unavailable"
        elif isinstance(exc, HTTPException):
            status, code, detail = exc.code or 500, exc.name.lower().replace(" ", "_"), exc.name
        else:
            status, code, detail = 500, "internal_error", "Unexpected server error"
        if status >= 500:
            # Exception strings/tracebacks may contain SQL parameters or provider credentials.
            logging.getLogger("auth_service").error(
                "request_failure code=%s request_id=%s", code, g.get("request_id")
            )
        response = jsonify(
            type=f"urn:auth-service-lab:{code}",
            title=code,
            status=status,
            detail=detail,
            request_id=g.get("request_id"),
        )
        response.content_type = "application/problem+json"
        return response, status

    @app.get("/health/live")
    @limiter.exempt
    def live() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/health/ready")
    @limiter.exempt
    def ready() -> dict[str, str]:
        g.db.execute(text("SELECT 1"))
        app.extensions["redis"].ping()
        return {"status": "ready"}

    @app.cli.command("seed-demo")
    @click.option("--email", required=True)
    @click.password_option(confirmation_prompt=True)
    def seed(email: str, password: str) -> None:
        if settings.environment != "development":
            raise click.ClickException("Demo seeding is development only")
        try:
            data = Register.model_validate({"email": email, "password": password})
        except ValidationError:
            raise click.ClickException(
                "Invalid email or password; password must contain 15–128 characters"
            ) from None
        email, password = str(data.email), data.password
        with app.extensions["sessions"]() as db:
            if db.scalar(select(User).where(User.email == email.casefold())):
                raise click.ClickException("User already exists")
            db.add(
                User(
                    email=email.casefold(),
                    password_hash=hasher.hash(password),
                    role="admin",
                    verified=True,
                    display_name="Demo Admin",
                )
            )
            db.commit()
        click.echo("Created development administrator")

    from auth_service.api import bp
    from auth_service.docs import docs_bp
    from auth_service.oauth import oauth_bp

    app.register_blueprint(bp, url_prefix="/api/v1")
    app.register_blueprint(oauth_bp, url_prefix="/api/v1/auth/oauth/github")
    app.register_blueprint(docs_bp)
    return app
