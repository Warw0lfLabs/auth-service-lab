# V1 validation record

Release checks performed on 2026-10-01. Automated tests mocked external GitHub responses and used
real PostgreSQL 17 and Redis 7. Live HTTP testing, including real public GitHub profile requests,
is recorded separately in [manual-testing.md](manual-testing.md). GitHub Actions has been configured
but has not yet run remotely.

## Application checks

With `.env` generated, database `authlab_test` created, and the dependency containers running:

```sh
set -a
source .env
set +a
export TEST_DATABASE_URL="${DATABASE_URL}_test"
export TEST_REDIS_URL=redis://localhost:56379/15
.venv/bin/pytest -q --cov=auth_service --cov-report=term-missing
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/mypy src migrations scripts
.venv/bin/alembic check
```

Results: 66 tests passed, 96% application statement coverage; lint, formatting, typing, and schema
consistency passed. The supported Python 3.12 runtime was checked inside the Docker image with:

```sh
docker compose run --rm --no-deps \
  -v "$PWD/tests:/app/tests:ro" \
  -v "$PWD/docs:/app/docs:ro" \
  -v "$PWD/scripts:/app/scripts:ro" \
  -v "$PWD/.env.example:/app/.env.example:ro" \
  -e TEST_REDIS_URL=redis://redis:6379/15 \
  -e COVERAGE_FILE=/tmp/authlab.coverage \
  -e RUFF_CACHE_DIR=/tmp/authlab-ruff \
  -e MYPY_CACHE_DIR=/tmp/authlab-mypy \
  app sh -c 'export TEST_DATABASE_URL="${DATABASE_URL}_test"; python --version && pytest -q -p no:cacheprovider --cov=auth_service --cov-report=term-missing && ruff check . && ruff format --check . && mypy src migrations scripts && alembic check'
```

## Empty-database migration verification

A fresh isolated database was created and tested through upgrade, complete rollback, and reapply:

```sh
docker compose exec -T db createdb -U authlab authlab_migration_review_test
set -a
source .env
set +a
export DATABASE_URL="${DATABASE_URL%/*}/authlab_migration_review_test"
.venv/bin/alembic upgrade head
.venv/bin/alembic check
.venv/bin/alembic downgrade base
.venv/bin/alembic upgrade head
.venv/bin/alembic check
```

All commands passed. Both schema checks reported `No new upgrade operations detected.`
The migrations were also applied automatically to the test database and by Compose's migration
container.

## Container and health verification

```sh
docker compose up -d --build --wait
curl --fail --silent --show-error http://localhost:8000/health/live
curl --fail --silent --show-error http://localhost:8000/health/ready
docker compose ps --format '{{.Service}} {{.State}} {{.Health}}'
```

Results: build/startup passed; migration container exited successfully; application, PostgreSQL,
and Redis were healthy. Liveness returned `{"status":"ok"}` and readiness returned
`{"status":"ready"}`.

## Swagger UI verification

On 2026-10-01, the complete suite passed after adding Swagger UI on both local Python 3.14.7
(66 tests in 12.52s) and container Python 3.12.14 (66 tests in 13.02s), with 96% coverage on each.
New tests verify public documentation access, JSON equality with the source file, the Bearer scheme,
health/protected endpoint behavior, and Host validation. Documentation routes are excluded from
the application API route inventory. The spec's server URL is relative to the running service.

The rebuilt image includes `docs/openapi.json`. Real HTTP checks on ports 8000 and 8001 returned
200 for `/docs`, `/openapi.json`, and both health endpoints, and 401 for unauthenticated
`/api/v1/users/me`.
Browser rendering, Authorize, authenticated requests, and reload behavior are recorded in
[manual-testing.md](manual-testing.md). No migrations or dependency lockfile changes were required.

## Review

Authentication/security self-review is documented in [security-review.md](security-review.md).
The review includes manual checks of authentication, authorization, token lifecycle, external HTTP,
configuration, logging, container configuration, and release-file hygiene. Local configuration,
mailbox files, credentials, editor settings, caches, and coverage output are excluded from Git and
the Docker context. Review release changes with `git diff --check`, `git diff`, and `git status`.

Manual setup still required: GitHub OAuth application credentials and browser consent for a live
provider test. Production email delivery, deployment TLS/proxy policy, key rollover, and automated
retention are deliberately outside V1.

## Dependency advisories

The release lockfile was checked with:

```sh
.venv/bin/python -m pip install pip-audit
.venv/bin/pip-audit --no-deps --disable-pip -r requirements.lock --cache-dir /tmp/authlab-audit
```

No known vulnerabilities were reported for the 49 locked packages. The audit tool is an optional
review tool, not an application dependency. Advisory checks do not cover unknown vulnerabilities
or operating-system packages in container images.

## Publication-readiness validation — 2026-10-05

The application-check commands above were rerun against real development PostgreSQL/Redis:
66 tests passed in 9.13s with 96% statement coverage. Ruff lint and formatting passed (27 files),
mypy passed (16 source files), and Alembic reported no schema changes. `git diff --check` passed.

Read-only HTTP checks against the running Compose application returned 200 for both health
endpoints, `/docs`, and `/openapi.json`; unauthenticated `/api/v1/users/me` returned 401. The served
OpenAPI JSON matched the source file. This was a validation follow-up, not a new complete manual
walkthrough. Earlier browser/OAuth limitations and the unverified remote CI status remain unchanged.
