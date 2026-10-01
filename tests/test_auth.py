import json
from datetime import timedelta
from pathlib import Path

import jwt
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from auth_service.models import ActionToken, AuthSession, SecurityEvent, User, now
from auth_service.security import hasher, verify_password
from tests.conftest import PASSWORD


def headers(tokens):
    return {"Authorization": "Bearer " + tokens["access_token"]}


def test_registration_duplicate_and_injection(app, client):
    payload = {"email": "Person@example.com", "password": PASSWORD}
    assert (
        client.post("/api/v1/auth/register", json={**payload, "role": "admin"}).status_code == 422
    )
    assert client.post("/api/v1/auth/register", json=payload).status_code == 202
    assert client.post("/api/v1/auth/register", json=payload).status_code == 202
    with Session(app.extensions["engine"]) as db:
        users = list(db.scalars(select(User)))
        assert len(users) == 1
        assert users[0].email == "person@example.com"
        assert users[0].role == "user"
        assert users[0].password_hash != PASSWORD
        assert verify_password(users[0].password_hash, PASSWORD)
    assert client.post("/api/v1/auth/login", json=payload).status_code == 401


def test_password_hashing():
    encoded = hasher.hash(PASSWORD)
    assert encoded.startswith("$argon2id$")
    assert verify_password(encoded, PASSWORD)
    assert not verify_password(encoded, "wrong")
    assert not verify_password(None, PASSWORD)


@pytest.mark.parametrize(
    "email,password", [("user@example.com", "wrong"), ("unknown@example.com", PASSWORD)]
)
def test_invalid_credentials(client, account, email, password):
    response = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert response.status_code == 401
    assert response.content_type == "application/problem+json"
    assert response.json["detail"] == "Authentication failed"


def test_disabled_user(app, client, account):
    with Session(app.extensions["engine"]) as db:
        user = db.scalar(select(User))
        user.disabled = True
        db.commit()
    assert client.get("/api/v1/users/me", headers=headers(account)).status_code == 401
    assert (
        client.post(
            "/api/v1/auth/login", json={"email": "user@example.com", "password": PASSWORD}
        ).status_code
        == 401
    )


@pytest.mark.parametrize("mutation", ["expired", "signature", "audience", "issuer", "type"])
def test_jwt_validation(app, client, account, mutation):
    settings = app.extensions["settings"]
    claims = jwt.decode(
        account["access_token"], settings.jwt_secret, algorithms=["HS256"], audience="access"
    )
    secret = settings.jwt_secret
    if mutation == "expired":
        claims["exp"] = now() - timedelta(seconds=1)
    elif mutation == "signature":
        secret = "z" * 48
    else:
        claims[{"audience": "aud", "issuer": "iss", "type": "type"}[mutation]] = "wrong"
    token = jwt.encode(claims, secret, algorithm="HS256")
    assert (
        client.get("/api/v1/users/me", headers={"Authorization": "Bearer " + token}).status_code
        == 401
    )


def test_refresh_reuse_revokes_family(app, client, account):
    rotated = client.post("/api/v1/auth/refresh", json={"token": account["refresh_token"]})
    assert rotated.status_code == 200
    assert rotated.json["refresh_token"] != account["refresh_token"]
    assert (
        client.post("/api/v1/auth/refresh", json={"token": account["refresh_token"]}).status_code
        == 401
    )
    assert client.get("/api/v1/users/me", headers=headers(rotated.json)).status_code == 401
    assert (
        client.post(
            "/api/v1/auth/refresh", json={"token": rotated.json["refresh_token"]}
        ).status_code
        == 401
    )
    with Session(app.extensions["engine"]) as db:
        assert db.scalar(select(AuthSession)).revoked
        assert db.scalar(select(SecurityEvent).where(SecurityEvent.kind == "refresh_reuse"))


def test_logout(client, account):
    assert client.post("/api/v1/auth/logout", headers=headers(account)).status_code == 204
    assert client.get("/api/v1/users/me", headers=headers(account)).status_code == 401
    assert (
        client.post("/api/v1/auth/refresh", json={"token": account["refresh_token"]}).status_code
        == 401
    )


def test_password_change(client, account):
    endpoint = "/api/v1/auth/password/change"
    assert (
        client.post(
            endpoint,
            headers=headers(account),
            json={
                "current_password": "wrong",
                "new_password": "another sufficiently long password",
            },
        ).status_code
        == 401
    )
    assert (
        client.post(
            endpoint,
            headers=headers(account),
            json={
                "current_password": PASSWORD,
                "new_password": "another sufficiently long password",
            },
        ).status_code
        == 204
    )
    assert client.get("/api/v1/users/me", headers=headers(account)).status_code == 401
    assert (
        client.post(
            "/api/v1/auth/login", json={"email": "user@example.com", "password": PASSWORD}
        ).status_code
        == 401
    )
    assert (
        client.post(
            "/api/v1/auth/login",
            json={"email": "user@example.com", "password": "another sufficiently long password"},
        ).status_code
        == 200
    )


def test_password_reset(app, client, account):
    assert (
        client.post(
            "/api/v1/auth/password/forgot", json={"email": "unknown@example.com"}
        ).status_code
        == 202
    )
    assert (
        client.post("/api/v1/auth/password/forgot", json={"email": "user@example.com"}).status_code
        == 202
    )
    messages = [
        json.loads(path.read_text())
        for path in Path(app.extensions["settings"].mail_dir).glob("*.json")
    ]
    token = next(mail["token"] for mail in messages if mail["purpose"] == "reset")
    payload = {"token": token, "password": "a replacement long password"}
    assert client.post("/api/v1/auth/password/reset", json=payload).status_code == 204
    assert client.post("/api/v1/auth/password/reset", json=payload).status_code == 400
    assert client.get("/api/v1/users/me", headers=headers(account)).status_code == 401
    assert (
        client.post(
            "/api/v1/auth/login",
            json={"email": "user@example.com", "password": payload["password"]},
        ).status_code
        == 200
    )


def test_expired_action_token(app, client, account):
    client.post("/api/v1/auth/password/forgot", json={"email": "user@example.com"})
    messages = [
        json.loads(p.read_text()) for p in Path(app.extensions["settings"].mail_dir).glob("*")
    ]
    token = next(m["token"] for m in messages if m["purpose"] == "reset")
    with Session(app.extensions["engine"]) as db:
        action = db.scalar(select(ActionToken).where(ActionToken.purpose == "reset"))
        action.expires_at = now() - timedelta(seconds=1)
        db.commit()
    assert (
        client.post(
            "/api/v1/auth/password/reset", json={"token": token, "password": PASSWORD}
        ).status_code
        == 400
    )


def test_rbac_and_admin_safeguard(app, client, account, admin):
    assert client.get("/api/v1/admin/users", headers=headers(account)).status_code == 403
    assert (
        client.patch(
            "/api/v1/users/me",
            headers=headers(account),
            json={"display_name": "x", "role": "admin"},
        ).status_code
        == 422
    )
    users = client.get("/api/v1/admin/users", headers=headers(admin)).json["items"]
    user_id = next(u["id"] for u in users if u["role"] == "user")
    admin_id = next(u["id"] for u in users if u["role"] == "admin")
    assert (
        client.patch(
            f"/api/v1/admin/users/{admin_id}", headers=headers(admin), json={"role": "user"}
        ).status_code
        == 409
    )
    assert (
        client.patch(
            f"/api/v1/admin/users/{user_id}", headers=headers(admin), json={"role": "admin"}
        ).status_code
        == 200
    )
    assert client.get("/api/v1/admin/users", headers=headers(account)).status_code == 200
    assert (
        client.patch(
            f"/api/v1/admin/users/{user_id}", headers=headers(admin), json={"disabled": True}
        ).status_code
        == 200
    )
    assert client.get("/api/v1/users/me", headers=headers(account)).status_code == 401


def test_refresh_expiration(app, client, account):
    from auth_service.models import RefreshToken

    with Session(app.extensions["engine"]) as db:
        token = db.scalar(select(RefreshToken))
        token.expires_at = now() - timedelta(seconds=1)
        db.commit()
    assert (
        client.post("/api/v1/auth/refresh", json={"token": account["refresh_token"]}).status_code
        == 401
    )


def test_jwt_missing_claim_and_unsigned(app, client, account):
    settings = app.extensions["settings"]
    claims = jwt.decode(
        account["access_token"], settings.jwt_secret, algorithms=["HS256"], audience="access"
    )
    del claims["sid"]
    signed = jwt.encode(claims, settings.jwt_secret, algorithm="HS256")
    unsigned = jwt.encode(claims, key="", algorithm="none")
    for token in [signed, unsigned, "malformed"]:
        assert (
            client.get("/api/v1/users/me", headers={"Authorization": "Bearer " + token}).status_code
            == 401
        )
