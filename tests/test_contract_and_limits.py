import json
import stat
from dataclasses import replace
from pathlib import Path

from tests.conftest import PASSWORD
from tests.test_auth import headers


def test_openapi_covers_routes(app):
    document = json.loads(Path("docs/openapi.json").read_text())
    assert document["openapi"] == "3.1.0"
    actual = {
        (rule.rule.replace("<user_id>", "{user_id}"), method.lower())
        for rule in app.url_map.iter_rules()
        if rule.endpoint != "static" and not rule.endpoint.startswith("docs.")
        for method in rule.methods - {"HEAD", "OPTIONS"}
    }
    documented = {
        (path, method) for path, operations in document["paths"].items() for method in operations
    }
    assert actual == documented

    def references(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "$ref":
                    assert value.startswith("#/components/schemas/")
                    assert value.rsplit("/", 1)[1] in document["components"]["schemas"]
                else:
                    references(value)
        elif isinstance(node, list):
            for item in node:
                references(item)

    references(document)


def test_public_documentation(client):
    response = client.get("/docs")
    assert response.status_code == 200
    assert response.mimetype == "text/html"
    assert 'url: "/openapi.json"' in response.text
    assert "SwaggerUIBundle" in response.text
    assert "persistAuthorization: false" in response.text
    assert "validatorUrl: null" in response.text
    assert response.headers["Cache-Control"] == "no-store"

    response = client.get("/openapi.json")
    assert response.status_code == 200
    assert response.mimetype == "application/json"
    document = response.get_json()
    assert document == json.loads(Path("docs/openapi.json").read_text())
    assert document["servers"] == [{"url": "/"}]
    assert document["components"]["securitySchemes"]["bearerAuth"] == {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "JWT",
    }
    assert client.get("/health/live").status_code == 200
    assert client.get("/health/ready").status_code == 200
    assert client.get("/api/v1/users/me").status_code == 401


def test_documentation_keeps_host_validation(client):
    for path in ("/docs", "/openapi.json"):
        assert client.get(path, headers={"Host": "attacker.example"}).status_code == 400


def test_account_limit_across_ips(app, client):
    app.extensions["settings"] = replace(app.extensions["settings"], account_limit="2/minute")
    for ip in ["10.0.0.1", "10.0.0.2"]:
        assert (
            client.post(
                "/api/v1/auth/login",
                json={"email": "unknown@example.com", "password": "wrong"},
                environ_overrides={"REMOTE_ADDR": ip},
            ).status_code
            == 401
        )
    assert (
        client.post(
            "/api/v1/auth/login",
            json={"email": "UNKNOWN@example.com", "password": "wrong"},
            environ_overrides={"REMOTE_ADDR": "10.0.0.3"},
        ).status_code
        == 429
    )


def test_mailbox_permissions(app, client):
    directory = Path(app.extensions["settings"].mail_dir)
    directory.chmod(0o755)
    client.post("/api/v1/auth/register", json={"email": "user@example.com", "password": PASSWORD})
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    for path in directory.glob("*.json"):
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_profile_update_and_audit(client, account, admin):
    assert (
        client.patch(
            "/api/v1/users/me", headers=headers(account), json={"display_name": "Updated"}
        ).json["display_name"]
        == "Updated"
    )
    assert client.get("/api/v1/admin/security-events", headers=headers(account)).status_code == 403
    events = client.get("/api/v1/admin/security-events", headers=headers(admin)).json["items"]
    assert any(event["kind"] == "profile_updated" for event in events)
    users = client.get("/api/v1/admin/users", headers=headers(admin)).json["items"]
    user_id = next(user["id"] for user in users if user["role"] == "user")
    assert client.get(f"/api/v1/admin/users/{user_id}", headers=headers(admin)).status_code == 200
    assert client.get("/api/v1/admin/users/not-found", headers=headers(admin)).status_code == 404
    assert client.get("/api/v1/admin/users?page=invalid", headers=headers(admin)).status_code == 422
    assert (
        client.patch(
            f"/api/v1/admin/users/{user_id}", headers=headers(admin), json={"role": "superadmin"}
        ).status_code
        == 422
    )


def test_seed_cli(app):
    result = app.test_cli_runner().invoke(
        args=["seed-demo", "--email", "demo@example.com"], input=PASSWORD + "\n" + PASSWORD + "\n"
    )
    assert result.exit_code != 0


def test_unauthenticated_and_invalid_json(client):
    assert client.get("/api/v1/users/me").status_code == 401
    assert (
        client.post(
            "/api/v1/auth/register", data="not json", content_type="application/json"
        ).status_code
        == 400
    )
    assert (
        client.post(
            "/api/v1/auth/register", json={"email": "user@example.com", "password": "x" * 129}
        ).status_code
        == 422
    )
    assert (
        client.post(
            "/api/v1/auth/register", data="x" * 20000, content_type="application/json"
        ).status_code
        == 413
    )


def test_seed_success_and_duplicate(app):
    from auth_service import create_app

    development = create_app(replace(app.extensions["settings"], environment="development"))
    runner = development.test_cli_runner()
    args = ["seed-demo", "--email", "demo@example.com"]
    result = runner.invoke(args=args, input=PASSWORD + "\n" + PASSWORD + "\n")
    assert result.exit_code == 0
    assert "Created development administrator" in result.output
    result = runner.invoke(args=args, input=PASSWORD + "\n" + PASSWORD + "\n")
    assert result.exit_code != 0
    response = development.test_client().post(
        "/api/v1/auth/login", json={"email": "demo@example.com", "password": PASSWORD}
    )
    assert response.status_code == 200
    assert (
        development.test_client()
        .get("/api/v1/admin/users", headers=headers(response.json))
        .status_code
        == 200
    )
    development.extensions["engine"].dispose()


def test_environment_helper(tmp_path):
    import subprocess
    import sys

    script = Path("scripts/init_dev_env.py").resolve()
    (tmp_path / ".env.example").write_text(Path(".env.example").read_text())
    result = subprocess.run(
        [sys.executable, str(script)], cwd=tmp_path, capture_output=True, text=True, check=True
    )
    content = (tmp_path / ".env").read_text()
    assert "REPLACE_PASSWORD" not in content
    assert stat.S_IMODE((tmp_path / ".env").stat().st_mode) == 0o600
    assert content not in result.stdout
    again = subprocess.run(
        [sys.executable, str(script)], cwd=tmp_path, capture_output=True, text=True
    )
    assert again.returncode != 0
    assert (tmp_path / ".env").read_text() == content


def test_account_limit_uses_validated_email(app, client):
    app.extensions["settings"] = replace(app.extensions["settings"], account_limit="2/minute")
    for index, email in enumerate(
        ["person@bücher.de", "person@xn--bcher-kva.de", "person@bücher.de"]
    ):
        response = client.post(
            "/api/v1/auth/login",
            json={"email": email, "password": "wrong"},
            environ_overrides={"REMOTE_ADDR": f"10.1.0.{index + 1}"},
        )
        assert response.status_code == (429 if index == 2 else 401)


def test_untrusted_host_rejected(client):
    response = client.get("/health/live", headers={"Host": "attacker.example"})
    assert response.status_code == 400
    assert response.content_type == "application/problem+json"
    assert response.json["request_id"] == response.headers["X-Request-ID"]
    assert response.json["request_id"]


def test_proxy_headers_do_not_change_peer_limits(app, client):
    app.extensions["settings"] = replace(app.extensions["settings"], auth_limit="2/minute")
    for index in range(3):
        response = client.post(
            "/api/v1/auth/login",
            json={"email": f"unknown{index}@example.com", "password": "wrong"},
            headers={"X-Forwarded-For": f"10.2.0.{index + 1}"},
        )
        assert response.status_code == (429 if index == 2 else 401)


def test_seed_rejects_invalid_credentials(app):
    from auth_service import create_app

    development = create_app(replace(app.extensions["settings"], environment="development"))
    runner = development.test_cli_runner()
    for email, password in [
        ("not-an-email", PASSWORD),
        ("valid@example.com", "short"),
        ("valid@example.com", "x" * 129),
    ]:
        result = runner.invoke(
            args=["seed-demo", "--email", email], input=password + "\n" + password + "\n"
        )
        assert result.exit_code != 0
        assert "Invalid email or password" in result.output
    development.extensions["engine"].dispose()


def test_database_guard_checks_name_not_query():
    import pytest

    from tests.conftest import require_test_database

    require_test_database("postgresql+psycopg://user:password@localhost/authlab_test")
    with pytest.raises(RuntimeError):
        require_test_database(
            "postgresql+psycopg://user:password@localhost/authlab?application_name=_test"
        )
