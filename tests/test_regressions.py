import json
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from auth_service.github import GitHubClient
from auth_service.models import ActionToken, AuthSession, User, now
from tests.conftest import PASSWORD
from tests.test_auth import headers
from tests.test_integrations import PROFILE


def test_concurrent_refresh(app, account):
    def refresh(_):
        with app.test_client() as client:
            response = client.post("/api/v1/auth/refresh", json={"token": account["refresh_token"]})
            return response.status_code, response.json

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(refresh, range(2)))
    assert sorted(status for status, _ in results) == [200, 401]
    winner = next(body for status, body in results if status == 200)
    assert app.test_client().get("/api/v1/users/me", headers=headers(winner)).status_code == 401


def test_concurrent_duplicate_registration(app):
    def register(_):
        with app.test_client() as client:
            return client.post(
                "/api/v1/auth/register", json={"email": "race@example.com", "password": PASSWORD}
            ).status_code

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert list(pool.map(register, range(2))) == [202, 202]
    with Session(app.extensions["engine"]) as db:
        assert len(list(db.scalars(select(User)))) == 1


def test_verification_reuse_and_resend(app, client):
    client.post("/api/v1/auth/register", json={"email": "verify@example.com", "password": PASSWORD})
    directory = Path(app.extensions["settings"].mail_dir)
    old = json.loads(next(directory.glob("*.json")).read_text())["token"]
    client.post("/api/v1/auth/email-verification/request", json={"email": "verify@example.com"})
    messages = [json.loads(path.read_text())["token"] for path in directory.glob("*.json")]
    new = next(token for token in messages if token != old)
    endpoint = "/api/v1/auth/email-verification/confirm"
    assert client.post(endpoint, json={"token": old}).status_code == 400
    assert client.post(endpoint, json={"token": new}).status_code == 204
    assert client.post(endpoint, json={"token": new}).status_code == 400


def test_action_purpose_confusion(app, client, account):
    client.post("/api/v1/auth/password/forgot", json={"email": "user@example.com"})
    messages = [
        json.loads(p.read_text()) for p in Path(app.extensions["settings"].mail_dir).glob("*")
    ]
    token = next(m["token"] for m in messages if m["purpose"] == "reset")
    assert (
        client.post("/api/v1/auth/email-verification/confirm", json={"token": token}).status_code
        == 400
    )
    assert (
        client.post(
            "/api/v1/auth/password/reset", json={"token": token, "password": PASSWORD}
        ).status_code
        == 204
    )


def test_concurrent_reset(app, client, account):
    client.post("/api/v1/auth/password/forgot", json={"email": "user@example.com"})
    messages = [
        json.loads(p.read_text()) for p in Path(app.extensions["settings"].mail_dir).glob("*")
    ]
    token = next(m["token"] for m in messages if m["purpose"] == "reset")

    def reset(_):
        return (
            app.test_client()
            .post(
                "/api/v1/auth/password/reset",
                json={"token": token, "password": "a new sufficiently long password"},
            )
            .status_code
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(reset, range(2))) == [204, 400]


def test_session_expiration_and_token_confusion(app, client, account):
    assert (
        client.get(
            "/api/v1/users/me", headers={"Authorization": "Bearer " + account["refresh_token"]}
        ).status_code
        == 401
    )
    assert (
        client.post("/api/v1/auth/refresh", json={"token": account["access_token"]}).status_code
        == 401
    )
    with Session(app.extensions["engine"]) as db:
        session = db.scalar(select(AuthSession))
        session.expires_at = now() - timedelta(seconds=1)
        db.commit()
    assert client.get("/api/v1/users/me", headers=headers(account)).status_code == 401
    assert (
        client.post("/api/v1/auth/refresh", json={"token": account["refresh_token"]}).status_code
        == 401
    )


def test_reset_invalidated_by_password_change(app, client, account):
    client.post("/api/v1/auth/password/forgot", json={"email": "user@example.com"})
    client.post(
        "/api/v1/auth/password/change",
        headers=headers(account),
        json={"current_password": PASSWORD, "new_password": "a new sufficiently long password"},
    )
    with Session(app.extensions["engine"]) as db:
        assert all(
            token.consumed
            for token in db.scalars(select(ActionToken).where(ActionToken.purpose == "reset"))
        )


def test_logout_all(client, account):
    second = client.post(
        "/api/v1/auth/login", json={"email": "user@example.com", "password": PASSWORD}
    ).json
    assert client.post("/api/v1/auth/logout-all", headers=headers(account)).status_code == 204
    assert client.get("/api/v1/users/me", headers=headers(second)).status_code == 401


def test_oauth_email_collision(app, client, account):
    from dataclasses import replace

    app.extensions["settings"] = replace(
        app.extensions["settings"], github_client_id="id", github_client_secret="secret"
    )
    state = parse_qs(urlparse(client.get("/api/v1/auth/oauth/github/start").location).query)[
        "state"
    ][0]

    def upstream(request):
        if request.url.host == "github.com":
            return httpx.Response(200, json={"access_token": "provider-token"})
        if request.url.path == "/user/emails":
            return httpx.Response(
                200, json=[{"primary": True, "verified": True, "email": "user@example.com"}]
            )
        return httpx.Response(200, json=PROFILE)

    app.extensions["github"] = GitHubClient(httpx.MockTransport(upstream))
    assert client.get("/api/v1/auth/oauth/github/callback?code=x&state=" + state).status_code == 409


def test_http_outside_transactions(app, client, account):
    from auth_service.models import OAuthIdentity

    with Session(app.extensions["engine"]) as db:
        user = db.scalar(select(User))
        db.add(OAuthIdentity(user_id=user.id, subject="123", handle="octocat"))
        db.commit()

    def upstream(request):
        from flask import g

        assert not g.db.in_transaction()
        return httpx.Response(200, json=PROFILE)

    app.extensions["github"] = GitHubClient(httpx.MockTransport(upstream))
    assert (
        client.get("/api/v1/users/me/external-profile", headers=headers(account)).status_code == 200
    )


def test_logging_does_not_leak(app, caplog):
    from dataclasses import replace

    from auth_service import create_app

    broken = create_app(
        replace(
            app.extensions["settings"],
            database_url="postgresql+psycopg://secretuser:secretpassword@localhost:1/test",
        )
    )
    broken.test_client().post(
        "/api/v1/auth/login", json={"email": "user@example.com", "password": "sensitive-password"}
    )
    assert "secretpassword" not in caplog.text
    assert "sensitive-password" not in caplog.text
    assert "user@example.com" not in caplog.text
    broken.extensions["engine"].dispose()
