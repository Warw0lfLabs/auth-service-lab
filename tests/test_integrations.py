from dataclasses import replace

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from auth_service import create_app
from auth_service.config import Settings
from auth_service.errors import Problem
from auth_service.github import GitHubClient
from auth_service.models import OAuthIdentity, User
from tests.test_auth import headers

PROFILE = {
    "id": 123,
    "login": "octocat",
    "name": "Octocat",
    "avatar_url": "https://example.com/avatar",
    "html_url": "https://github.com/octocat",
}


def test_github_success():
    client = GitHubClient(httpx.MockTransport(lambda _: httpx.Response(200, json=PROFILE)))
    assert client.profile("octocat").login == "octocat"


@pytest.mark.parametrize(
    "status,body,expected",
    [(500, {}, 502), (429, {}, 503), (200, {"id": "invalid"}, 502), (404, {}, 502)],
)
def test_github_failures(status, body, expected):
    client = GitHubClient(httpx.MockTransport(lambda _: httpx.Response(status, json=body)))
    with pytest.raises(Problem) as error:
        client.profile("octocat")
    assert error.value.status == expected


def test_github_timeout():
    def timeout(request):
        raise httpx.ReadTimeout("timeout", request=request)

    with pytest.raises(Problem) as error:
        GitHubClient(httpx.MockTransport(timeout)).profile("octocat")
    assert error.value.status == 504


def test_github_invalid_json_and_oversize():
    for content in [b"not json", b"x" * (1024 * 1024 + 1)]:
        with pytest.raises(Problem):
            GitHubClient(
                httpx.MockTransport(lambda _, content=content: httpx.Response(200, content=content))
            ).profile("x")


def test_profile_endpoint(app, client, account):
    with Session(app.extensions["engine"]) as db:
        user = db.scalar(select(User))
        db.add(OAuthIdentity(user_id=user.id, subject="123", handle="octocat"))
        db.commit()
    app.extensions["github"] = GitHubClient(
        httpx.MockTransport(lambda _: httpx.Response(200, json=PROFILE))
    )
    assert (
        client.get("/api/v1/users/me/external-profile", headers=headers(account)).json["login"]
        == "octocat"
    )


def test_rate_limit(app, client):
    app.extensions["settings"] = replace(app.extensions["settings"], auth_limit="2/minute")
    for _ in range(2):
        assert (
            client.post(
                "/api/v1/auth/login", json={"email": "unknown@example.com", "password": "x"}
            ).status_code
            == 401
        )
    assert (
        client.post(
            "/api/v1/auth/login", json={"email": "unknown@example.com", "password": "x"}
        ).status_code
        == 429
    )


def test_health_and_database_failure(app, client):
    assert client.get("/health/live").status_code == 200
    assert client.get("/health/ready").status_code == 200
    broken = create_app(
        replace(
            app.extensions["settings"],
            database_url="postgresql+psycopg://invalid:invalid@127.0.0.1:1/unavailable",
        )
    )
    assert broken.test_client().get("/health/ready").status_code == 503
    assert broken.test_client().get("/health/live").status_code == 200
    broken.extensions["engine"].dispose()


def test_redis_failure_closed(app):
    broken = create_app(replace(app.extensions["settings"], redis_url="redis://127.0.0.1:1/0"))
    response = broken.test_client().post(
        "/api/v1/auth/login", json={"email": "unknown@example.com", "password": "x"}
    )
    assert response.status_code == 503
    assert broken.test_client().get("/health/ready").status_code == 503
    broken.extensions["engine"].dispose()


@pytest.mark.parametrize(
    "field,value",
    [
        ("database_url", "sqlite://"),
        ("redis_url", "memory://"),
        ("jwt_secret", "short"),
        ("environment", "wrong"),
        ("public_url", "http://localhost/path"),
        ("github_client_id", "without-secret"),
        ("environment", "production"),
    ],
)
def test_configuration(app, field, value):
    with pytest.raises(ValueError):
        replace(app.extensions["settings"], **{field: value}).validate()


def test_missing_environment(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("JWT_SECRET", raising=False)
    with pytest.raises(ValueError):
        Settings.from_env()


def test_oauth_flow_and_replay(app, client):
    from urllib.parse import parse_qs, urlparse

    app.extensions["settings"] = replace(
        app.extensions["settings"], github_client_id="test-id", github_client_secret="test-secret"
    )
    redirect = client.get("/api/v1/auth/oauth/github/start")
    query = parse_qs(urlparse(redirect.location).query)
    assert query["code_challenge_method"] == ["S256"]
    assert "HttpOnly" in redirect.headers["Set-Cookie"]
    assert "SameSite=Lax" in redirect.headers["Set-Cookie"]

    def upstream(request):
        if request.url.host == "github.com":
            assert b"code_verifier=" in request.content
            return httpx.Response(200, json={"access_token": "provider-token"})
        if request.url.path == "/user/emails":
            return httpx.Response(
                200, json=[{"primary": True, "verified": True, "email": "oauth@example.com"}]
            )
        return httpx.Response(200, json=PROFILE)

    app.extensions["github"] = GitHubClient(httpx.MockTransport(upstream))
    url = "/api/v1/auth/oauth/github/callback?code=abc&state=" + query["state"][0]
    response = client.get(url)
    assert response.status_code == 200
    assert client.get("/api/v1/users/me", headers=headers(response.json)).status_code == 200
    assert client.get(url).status_code == 400


def test_oauth_binding_required(app, client):
    from urllib.parse import parse_qs, urlparse

    app.extensions["settings"] = replace(
        app.extensions["settings"], github_client_id="id", github_client_secret="secret"
    )
    response = client.get("/api/v1/auth/oauth/github/start")
    state = parse_qs(urlparse(response.location).query)["state"][0]
    attacker = app.test_client()
    assert (
        attacker.get("/api/v1/auth/oauth/github/callback?code=x&state=" + state).status_code == 400
    )


def test_oauth_unconfigured(client):
    assert client.get("/api/v1/auth/oauth/github/start").status_code == 503
