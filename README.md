# Auth Service Lab

A Python authentication and user-management REST API built to demonstrate backend engineering:
explicit transaction boundaries, revocable JWT sessions, real PostgreSQL concurrency tests,
validated third-party responses, and reproducible Docker setup.

V1 implements registration, email verification, login/logout, password change/recovery, rotating
JWT refresh tokens, user/admin authorization, GitHub OAuth login, a GitHub profile integration,
Redis-backed authentication rate limits, and database security events.

**Email delivery is a development adapter:** messages are private local JSON files. There is no
frontend, production mail transport, or production deployment claim. `APP_ENV=production` fails
at startup until a production email adapter is implemented.

## Start with Docker

Requires Docker Compose and Python 3.12+ for the configuration helper.

```sh
python3 scripts/init_dev_env.py
docker compose up -d --build --wait
curl --fail http://localhost:8000/health/live
curl --fail http://localhost:8000/health/ready
```

The helper creates `.env` with random credentials and mode `0600`; it refuses to overwrite it.
Compose starts PostgreSQL 17, Redis 7, runs Alembic in a one-shot migration container, and starts
Gunicorn with two workers. Host ports bind to loopback: API `8000`, PostgreSQL `55432`, Redis `56379`.
PostgreSQL data and development messages persist in named volumes. `docker compose down` stops
the stack without removing those volumes.

Create an optional verified demo administrator with an interactive password prompt:

```sh
docker compose exec app flask --app auth_service seed-demo --email admin@example.com
```

No default administrator password is shipped. The seed command works only in development.

## Try registration and verification

```sh
curl --fail http://localhost:8000/api/v1/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"person@example.com","password":"a sufficiently long demo password"}'
```

The generic `202` response does not expose whether the account already exists. Login is blocked
until email verification. Inspect development messages locally:

```sh
docker compose exec app python -c 'from pathlib import Path; [print(p.read_text()) for p in Path(".dev-mail").glob("*.json")]'
```

Messages contain `to`, `purpose` (`verify` or `reset`), and `token`. Treat these files as credentials.
Pass the verification token to `POST /api/v1/auth/email-verification/confirm`:

```json
{"token": "COPY_FROM_DEVELOPMENT_MESSAGE"}
```

Then `POST /api/v1/auth/login` with email/password returns `access_token`, `refresh_token`,
`token_type`, and `expires_in`. Send the access token as `Authorization: Bearer <access_token>`
to `GET /api/v1/users/me`. Send `{"token":"<refresh_token>"}` to `POST /api/v1/auth/refresh`.

Every refresh replaces the previous refresh token. Reusing it revokes the entire session,
including access tokens. Serialize refresh requests; an ambiguous network result should lead to
fresh login rather than blindly retrying a consumed refresh token. Tokens must be handled as secrets.

## API reference

The complete [OpenAPI 3.1 contract](docs/openapi.json) describes request/response schemas and access
requirements. Application endpoints use `/api/v1`; health endpoints are unversioned.

### Interactive Swagger UI

Open [Swagger UI](http://localhost:8000/docs) after starting Compose, or
`http://localhost:8001/docs` for the local Flask server. The public `/openapi.json` endpoint serves
the existing `docs/openapi.json` file; the relative server URL targets the service you opened.
Use **Authorize** with a login access token (without the `Bearer` prefix) to try protected endpoints.
Authorization is cleared on page reload; requests can modify development data.

The page loads version-pinned Swagger UI assets from unpkg with integrity checks, so the browser
needs internet access. Remote schema validation is disabled. Run the local server from the repository
root so it can find the specification; the Docker image includes that file.

| Area | Endpoints |
|---|---|
| Authentication | `POST /auth/register`, `/auth/login`, `/auth/refresh`, `/auth/logout`, `/auth/logout-all` |
| Email verification | `POST /auth/email-verification/request`, `/auth/email-verification/confirm` |
| Passwords | `POST /auth/password/change`, `/auth/password/forgot`, `/auth/password/reset` |
| Current user | `GET/PATCH /users/me`, `GET /users/me/external-profile` |
| Administration | `GET /admin/users`, `GET/PATCH /admin/users/{user_id}`, `GET /admin/security-events` |
| GitHub OAuth | `GET /auth/oauth/github/start`, `/auth/oauth/github/callback` |
| Operations | `GET /health/live`, `GET /health/ready` |

Unknown JSON fields are rejected, including role injection. Registration/password replacement
requires 15–128 characters; passwords are not truncated or normalized. Email addresses are
casefolded without provider-specific transformations. Profile editing only changes display name.
Administrators can promote/demote or disable/re-enable users, but cannot remove the last active
administrator. Admin user lists use pages of 50; event inspection returns the latest 100.

Errors use `application/problem+json` with `type`, `title`, `status`, `detail`, and `request_id`.
Required dependency failures return sanitized `503`; upstream errors/timeouts use `502`/`504`.
Existing bearer access depends on PostgreSQL and can continue during a Redis outage; login and
other rate-limited authentication endpoints fail closed. Readiness checks both services. Rate limits
return `429`. Recovery responses are generic; action tokens expire after 30 minutes and are single-use.
Password change and reset revoke every session and invalidate outstanding password-reset tokens.

## GitHub OAuth configuration

Create a GitHub OAuth App with callback:

```text
http://localhost:8000/api/v1/auth/oauth/github/callback
```

Set `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET` in `.env`, then recreate the application:

```sh
docker compose up -d --force-recreate app
```

Open `/api/v1/auth/oauth/github/start` in a browser. After GitHub consent, the callback returns JSON
application tokens. The flow uses state, S256 PKCE, and a short-lived browser-binding cookie. A
verified primary GitHub email is required. An email matching an existing local account returns
`409`; V1 does not automatically merge or link accounts. The provider access token is discarded.

`GET /api/v1/users/me/external-profile` retrieves the public profile for the authenticated GitHub
identity through a service adapter. Local-password accounts receive `404` for this endpoint.
The adapter uses fixed GitHub origins, validated responses, bounded reads, and explicit timeouts;
HTTP requests execute outside database transactions. Automated tests use mocked HTTP transports;
the manual pass also exercised real public GitHub profile requests with a disposable identity fixture.
Real consent requires your own OAuth credentials and was not completed in that pass.

## Local development and validation

```sh
test -f .env || python3 scripts/init_dev_env.py
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.lock
.venv/bin/python -m pip install --no-deps -e .
set -a
source .env
set +a
docker compose up -d db redis --wait
.venv/bin/alembic upgrade head
PUBLIC_URL=http://localhost:8001 .venv/bin/flask --app auth_service run --port 8001
```

The local Flask command is for development; Docker runs Gunicorn. `PUBLIC_URL` must match the OAuth
callback origin; register a separate GitHub callback on port 8001 when using the local server.
`.env` is explicitly loaded by your shell or Compose, not automatically by the app.

Create a dedicated test database once:

```sh
docker compose exec -T db createdb -U authlab authlab_test
export TEST_DATABASE_URL="${DATABASE_URL}_test"
export TEST_REDIS_URL=redis://localhost:56379/15
.venv/bin/pytest --cov=auth_service --cov-report=term-missing
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/mypy src migrations scripts
.venv/bin/alembic check
```

Tests require a database name ending in `_test` and Redis database `15`. They apply migrations,
truncate test tables, and flush that Redis database. Never point them at shared data. PostgreSQL and
Redis are required; missing dependencies fail the suite rather than silently skipping integration
checks. Unit and integration tests run together; concurrency regressions use separate connections.
The CI workflow performs these checks on Python 3.12 and builds the Docker image. The workflow has
also completed successfully on GitHub Actions.

Coverage includes duplicate/concurrent registration, invalid credentials, disabled users, password
hashing, JWT validation/expiry, refresh rotation/replay/concurrency, logout, password change/reset,
verification, RBAC/injection, OAuth state/replay/collision, rate limits, upstream failures, and
configuration/database/Redis failures.

## Quality & Security

Checks recorded on 2026-10-01:

- **Automated validation:** 66 tests passed with 96% statement coverage using real PostgreSQL and
  Redis; Ruff lint/format, mypy, and Alembic schema checks passed. See
  [validation results](docs/validation.md) for commands and migration checks.
- **Manual/E2E testing:** real HTTP workflows passed against local Flask and Docker deployments,
  including authentication, RBAC, token replay, rate limits, persistence, and dependency restarts.
  [Manual testing](docs/manual-testing.md) records expected/actual results and untested scenarios.
  Full GitHub browser consent and HTTPS cookie behavior remain unverified.
- **Security review:** authentication, authorization, recovery, configuration, logging, and repository
  hygiene were reviewed; identified fixes and remaining deployment risks are documented in the
  [security review](docs/security-review.md). This is an internal review, not an independent audit.
- **Docker validation:** image build, fresh Compose startup/migrations, health endpoints, and the
  Python 3.12 container test suite passed locally.
- **CI validation:** GitHub Actions successfully runs linting, formatting, type checking, migrations,
  tests with coverage, and the Docker image build on Python 3.12.

## Configuration and repository map

`.env.example` lists all environment variables. `DATABASE_URL` requires `postgresql+psycopg://`;
`REDIS_URL` requires Redis. `JWT_SECRET` must have at least 32 bytes and should be randomly generated.
`PUBLIC_URL` is an origin without a path/query; `MAIL_DIR` is private local storage. GitHub credentials
are optional as a pair; unconfigured OAuth returns `503`.

- `src/auth_service/`: factory, typed configuration, models, services, API/OAuth routes, adapters
- `migrations/`: explicit Alembic schema evolution
- `tests/`: HTTP flow, dependency failure, and concurrency regression tests
- `docs/`: OpenAPI, architecture, and security review
- `.github/workflows/ci.yml`: lint, typing, migrations, tests, image build

[Architecture decisions](docs/architecture.md) explain the stateful JWT model and transaction order.
Signing-key replacement invalidates existing JWTs. V1 defers key rollover, automated retention,
MFA, account deletion/linking, email changes, and production email delivery. Host headers are
restricted to the public hostname and localhost/127.0.0.1. No proxy headers are trusted; review
proxy/IP handling and TLS before any public deployment. Access logging is disabled in Gunicorn
to keep OAuth callback codes out of logs. Security events remain available in PostgreSQL.
