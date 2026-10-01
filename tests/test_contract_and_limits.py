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
        if rule.endpoint != "static"
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


def test_seed_cli(app, client):
    app.extensions["settings"] = replace(app.extensions["settings"], environment="development")
    # CLI closes over the factory's validated settings; test configuration still prohibits seed.
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
