# V1 validation record

Validated locally on 2026-10-01. External GitHub responses were mocked; real PostgreSQL 17 and
Redis 7 were used. GitHub Actions has been configured but was not executed on GitHub in this session.

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

Results: 59 tests passed, 97% application statement coverage; lint, formatting, typing, and schema
consistency passed. The host interpreter is Python 3.14.7. The suite also passed on Python 3.12.14
inside the Docker image, using this command:

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
  app sh -c 'export TEST_DATABASE_URL="${DATABASE_URL}_test"; python --version && pytest -q -p no:cacheprovider --cov=auth_service --cov-report=term-missing && ruff check . && ruff format --check . && mypy src migrations scripts'
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

## Review

Authentication/security self-review is documented in [security-review.md](security-review.md).
Issues corrected included concurrent duplicate registration, account limits across different IPs,
audit target attribution, migration rollback constraint naming, and private mailbox directory/file
permissions. Regression tests cover the security-critical transaction and token behavior.

`git diff --check` and per-file diff whitespace checks passed. New repository files were scanned
against the actual generated local JWT/database secrets and private-key markers; none were found.
`.env`, virtual environments, mailbox files, caches, and coverage output are ignored and excluded
from the Docker context where applicable. No commit or remote publication was performed.

Manual setup still required: GitHub OAuth application credentials and browser consent for a live
provider test. Production email delivery, deployment TLS/proxy policy, key rollover, and automated
retention are deliberately outside V1.
