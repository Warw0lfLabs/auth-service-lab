import json
import os
from pathlib import Path
from urllib.parse import urlparse

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from auth_service import create_app
from auth_service.config import Settings
from auth_service.models import User
from auth_service.security import hasher

PASSWORD = "a sufficiently long password"


@pytest.fixture(scope="session")
def database_url():
    url = os.environ["TEST_DATABASE_URL"]
    if not url.rsplit("/", 1)[-1].endswith("_test"):
        raise RuntimeError("Tests require a database ending in _test")
    previous = os.environ.get("DATABASE_URL")
    os.environ["DATABASE_URL"] = url
    command.upgrade(Config("alembic.ini"), "head")
    if previous:
        os.environ["DATABASE_URL"] = previous
    else:
        os.environ.pop("DATABASE_URL", None)
    return url


@pytest.fixture()
def app(database_url, tmp_path):
    engine = create_engine(database_url)
    with engine.begin() as conn:
        conn.execute(
            text(
                "TRUNCATE security_events, oauth_identities, action_tokens, refresh_tokens, "
                "auth_sessions, users CASCADE"
            )
        )
    engine.dispose()
    if urlparse(os.environ["TEST_REDIS_URL"]).path != "/15":
        raise RuntimeError("Tests require isolated Redis database 15")
    settings = Settings(
        database_url=database_url,
        redis_url=os.environ["TEST_REDIS_URL"],
        jwt_secret="test-only-" + "x" * 48,
        environment="test",
        mail_dir=str(tmp_path),
        auth_limit="1000/minute",
        account_limit="1000/minute",
    )
    app = create_app(settings)
    app.config["TESTING"] = True
    app.extensions["redis"].flushdb()
    yield app
    app.extensions["engine"].dispose()


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def account(app, client):
    response = client.post(
        "/api/v1/auth/register", json={"email": "user@example.com", "password": PASSWORD}
    )
    assert response.status_code == 202
    mail = json.loads(next(Path(app.extensions["settings"].mail_dir).glob("*.json")).read_text())
    assert (
        client.post(
            "/api/v1/auth/email-verification/confirm", json={"token": mail["token"]}
        ).status_code
        == 204
    )
    response = client.post(
        "/api/v1/auth/login", json={"email": "user@example.com", "password": PASSWORD}
    )
    assert response.status_code == 200
    return response.json


@pytest.fixture()
def admin(app, client):
    with Session(app.extensions["engine"]) as db:
        db.add(
            User(
                email="admin@example.com",
                password_hash=hasher.hash(PASSWORD),
                verified=True,
                role="admin",
            )
        )
        db.commit()
    return client.post(
        "/api/v1/auth/login", json={"email": "admin@example.com", "password": PASSWORD}
    ).json
