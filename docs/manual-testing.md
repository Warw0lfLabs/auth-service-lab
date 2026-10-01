# Manual end-to-end testing

Performed on 2026-10-01 against running applications, using real HTTP requests and development
PostgreSQL/Redis. The HTTP walkthrough used HTTPX clients, not Flask's test client or mocked servers.
The separate pytest run is supplemental evidence.

## Environment

- Fresh working-tree copy, newly generated private `.env`, isolated Compose project `authlab-manual`.
- PostgreSQL 17.11, Redis 7.4.11, migrations applied automatically to an empty PostgreSQL volume.
- Docker: Python 3.12.14, Gunicorn with two workers, API on `http://localhost:8000`.
- Local: Python 3.14.7, Flask development server on `http://localhost:8001`.
- OAuth negative probes: real local Flask process on port 8002 with deliberately unusable GitHub
  credentials and a matching public URL. No successful OAuth login is represented by these probes.
- Existing project containers were stopped temporarily; their volumes were preserved. Disposable
  clients/accounts and separate test volumes were used throughout.

Private generated credentials, JWTs, action tokens, and raw mailbox output are excluded. The
public README example password appears only in its example command.

## Commands used

Setup ran in the fresh copy with `COMPOSE_PROJECT_NAME=authlab-manual` exported in the shell.
The existing stack was stopped first to release the development ports; its volumes were preserved.

```sh
python3 scripts/init_dev_env.py
docker compose up -d --build --wait
curl --fail http://localhost:8000/health/live
curl --fail http://localhost:8000/health/ready
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.lock
.venv/bin/python -m pip install --no-deps -e .
set -a
source .env
set +a
docker compose up -d db redis --wait
.venv/bin/alembic upgrade head
.venv/bin/flask --app auth_service run --port 8001
```

The original local-server command inherited port 8000 in `PUBLIC_URL`; the corrected command was
used for the local restart:

```sh
PUBLIC_URL=http://localhost:8001 .venv/bin/flask --app auth_service run --port 8001
```

The README's literal example registration was exercised:

```sh
curl --fail http://localhost:8000/api/v1/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"person@example.com","password":"a sufficiently long demo password"}'
docker compose exec -T app flask --app auth_service seed-demo --email admin@example.com
docker compose exec -T app python -c 'from pathlib import Path; [print(p.read_text()) for p in Path(".dev-mail").glob("*.json")]'
```

Mailbox output was redirected to a private temporary file. The example account was verified through
HTTP, logged in, and used to access `/api/v1/users/me`; the demo administrator accessed the admin API.
Interactive administrator passwords were supplied through stdin and were not placed in shell arguments.

Temporary HTTPX client drivers issued the requests below and in the scenario tables, retained
credentials only in private temporary files, and recorded sanitized outcomes. The drivers are not
required project tooling. These representative HTTP requests show the exercised methods, paths,
and bodies; angle-bracket values stand for private credentials obtained during the walkthrough:

```http
POST /api/v1/auth/email-verification/confirm
Content-Type: application/json

{"token":"<verification-token>"}

POST /api/v1/auth/login
Content-Type: application/json

{"email":"person@example.com","password":"a sufficiently long demo password"}

GET /api/v1/users/me
Authorization: Bearer <access-token>

POST /api/v1/auth/refresh
Content-Type: application/json

{"token":"<refresh-token>"}

POST /api/v1/auth/password/forgot
Content-Type: application/json

{"email":"<disposable-recovery-account>"}

POST /api/v1/auth/password/reset
Content-Type: application/json

{"token":"<reset-token>","password":"<replacement-password>"}

POST /api/v1/auth/logout
Authorization: Bearer <access-token>
```

Refresh was repeated with the consumed token to verify session-family revocation. Recovery,
password-change, and logout checks used separate fresh logins, so replay revocation did not mask
their results. Repeat the walkthrough against ports 8000 and 8001 with separate disposable accounts.
Other request schemas are in [OpenAPI](openapi.json); expected/observed outcomes follow below.

Restart/outage operations used only the isolated project:

```sh
docker compose restart app
docker compose stop redis
docker compose start redis
docker compose stop db
docker compose start db
docker compose ps --format '{{.Service}} {{.State}} {{.Health}}'
```

Three simultaneously running Docker clients supplied distinct real peer IPs for limiter checks:

```sh
docker compose run -d --no-deps --name authlab-manual-peer-a app tail -f /dev/null
docker compose run -d --no-deps --name authlab-manual-peer-b app tail -f /dev/null
docker compose run -d --no-deps --name authlab-manual-peer-c app tail -f /dev/null
```

## Authentication: local and Docker HTTP paths

Each row was exercised on both deployments unless its scope explicitly says otherwise.

| Scenario | Expected | Actual | Result |
|---|---|---|---|
| Live / ready | 200 / 200 | 200 / 200 | PASS |
| Register valid account | Generic 202 | 202; user/message created | PASS |
| Duplicate registration | Same generic 202 | 202 | PASS |
| Invalid email / short password | 422 | 422 | PASS |
| Registration role injection | 422; no privilege assignment | 422 | PASS |
| Verify development email token | 204; verified account | 204 | PASS |
| Reuse verification token | 400 | 400 | PASS |
| Login valid credentials | 200 and JWT pair | 200 | PASS |
| Wrong password / unknown account | Generic 401 | 401 / 401 | PASS |
| Bearer access to current user | 200, current role user | 200, user | PASS |
| Rotate refresh token | 200, replacement differs | 200, new token | PASS |
| Reuse consumed refresh | 401; revoke session family | 401 | PASS |
| Access / refresh issued before replay | Both rejected | 401 / 401 | PASS |
| Logout | 204; revoke session | 204 | PASS |
| Logged-out access / refresh | Both rejected | 401 / 401 | PASS |
| Forgot-password known / unknown | Same generic 202 | 202; identical response JSON | PASS |
| Reset token used for verification | 400 without consuming reset capability | 400; subsequent reset worked | PASS |
| Invalid reset token | 400 | 400 | PASS |
| Password reset | 204; revoke existing session | 204; access/refresh rejected | PASS |
| Reuse reset token | 400 | 400 | PASS |
| Old password after reset | 401 | 401 | PASS |
| Replacement password | 200 | 200 | PASS |
| Change password with wrong current password | 401 | 401 | PASS |
| Change password with correct current password | 204 | 204 | PASS |
| Change revokes current and second session | Both rejected | 401 / 401 | PASS |
| Old password after change | 401 | 401 | PASS |
| Changed password | 200 | 200 | PASS |
| Logout all sessions | 204; second access/refresh rejected | 204; 401 / 401 | PASS |
| Two concurrent real refresh requests | One 200, one 401; winner revoked by replay | 200 / 401; winner access 401 | PASS |

Additional local verification checks: unverified login returned 401; resend returned 202 and
invalidated the old token (400); the new token verified (204), allowing login (200).

## Tokens, inputs, and authorization

| Scenario | Scope | Expected | Actual | Result |
|---|---|---|---|---|
| Unauthenticated protected user/admin endpoints | Both | 401 | 401 | PASS |
| User listing/admin mutation/audit access | Both | 403 | 403 | PASS |
| Administrator list/inspect/audit access | Both | 200 | 200 | PASS |
| Promote user; existing JWT gains admin access | Both | 200 | 200 | PASS |
| Demote user; existing JWT loses admin access | Both | Mutation 200; access 403 | 200 / 403 | PASS |
| Disable user | Both | Mutation 200; login/access 401 | 200 / 401 | PASS |
| Re-enable user | Both | New login works; old tokens stay revoked | 200; old access/refresh 401 | PASS |
| Last active admin demotion/disable | Both | 409 | 409 | PASS |
| Nonexistent or SQL-like resource ID | Both | 404, no SQL effects | 404; subsequent queries worked | PASS |
| Invalid pagination/role; unknown admin field | Both | 422 | 422 | PASS |
| Profile role injection | Both | 422 | 422 | PASS |
| Profile display name at 100 / 101 characters | Both | 200 / 422 | 200 / 422 | PASS |
| SQL text in display name | Both | Store as data, no SQL execution | 200; database remained usable | PASS |
| Malformed JSON / wrong content type | Both | 400 / 415 | 400 / 415 | PASS |
| 20 KB JSON body | Both | 413 | 413 | PASS |
| Password length 129 | Both | 422 | 422 | PASS |
| Password lengths 14 / 15 / 128 | Local | 422 / 202 / 202 | 422 / 202 / 202 | PASS |
| Array/null/wrong-type/injection login inputs | Local | 422 | 422 | PASS |
| Refresh token used as access; access used as refresh | Both | 401 | 401 | PASS |
| Malformed or wrong-signature JWT | Both | 401 | 401 | PASS |
| Wrong issuer/audience/type | Both | 401 | 401 | PASS |
| Unsigned JWT | Both | 401 | 401 | PASS |
| Signed access/refresh with past expiry | Both | 401 | 401 | PASS |
| Three-second dev-signed access token, before/after elapsed expiry | Docker | 200 then 401 | 200 then 401 | PASS |
| Original active session after short token expires | Docker | 200 | 200 | PASS |
| URL or cookie token without bearer header | Both | 401 | 401 | PASS |
| Host outside allowlist | Both | 400 | 400 | PASS |
| Cross-origin response and OPTIONS preflight | Both | No allow-origin header | Header absent | PASS |
| Cache/request-ID/referrer/content-type security headers | Both | Configured values present | Present | PASS |
| Error responses | Both | Problem JSON, no credentials/tracebacks | No tested secret or traceback found | PASS |

JWT fixtures were signed with the isolated development key; the server itself was not mocked or
reconfigured to shorten JWT lifetimes. Action-token expiry was tested locally by expiring only a
disposable account's database records: verification/reset returned 400, the user stayed unverified
until a fresh token was used, and an expired reset left the original password valid. Natural
30-minute/7-day/30-day expiry was not waited out.

## Abuse controls and persistence

| Scenario | Expected | Actual | Result |
|---|---|---|---|
| Account limit across distinct real IPs and Unicode/punycode aliases | 10 login failures; next alias request 429 | 10 × 401, then 429 from different peer | PASS |
| IP limit across different accounts with changing forwarded headers | First 20 failures; subsequent requests 429 | 20 × 401, then 2 × 429 | PASS |
| Repeated registration | 10 × 202, then 429 | Expected sequence | PASS |
| Repeated forgot-password requests | 10 × 202, then 429 | Expected sequence | PASS |
| Repeated verification requests | 10 × 202, then 429 | Expected sequence | PASS |
| Rate-limit retry guidance | Retry-After header | Present | PASS |
| Known/unknown login and forgot responses | Equivalent public response fields | Equivalent, excluding request IDs | PASS |
| Database password storage | Argon2id, no plaintext | Argon2id hash; changed password verified | PASS |
| User verification/role/disabled fields | Expected current values | Verified user role; enabled after re-enable | PASS |
| Refresh-token storage | SHA-256 digest, consumed state | Digest matched actual token; current token unconsumed | PASS |
| Revoked sessions / consumed action tokens | Records retained | Records present | PASS |
| Admin audit actor/target | Administrator actor; affected user target | Correct IDs through audit API | PASS |
| Redis limits / OAuth TTL and consumption | Counters, bounded TTL, one-time state | Counters present; TTL <=300s; consumed key absent | PASS |

Two initial limiter attempts reused a disposable container's IP. They were invalid probes for
cross-IP/clean-IP thresholds and are excluded from the verdict. The simultaneous-client reruns
above verified both thresholds without changing the application or disabling its limits.

## Restart and outage behavior

| Scenario | Expected | Actual | Result |
|---|---|---|---|
| Docker API restart | Active session works; revoked access/refresh rejected | 200; 401 / 401 | PASS |
| Local API process restart | Same persistent session behavior | 200; 401 / 401 | PASS |
| Redis stopped: live / ready | 200 / 503 | 200 / 503 on both APIs | PASS |
| Redis stopped: login | Fail closed | 503 on both APIs | PASS |
| Redis stopped: existing bearer access | PostgreSQL-backed access continues | 200 on both APIs | PASS |
| Redis restarted | Readiness/session behavior recovers | 200; revoked tokens still 401 | PASS |
| Pending OAuth state through clean same-container Redis restart | Retained until TTL | Retained | PASS |
| PostgreSQL stopped: live / ready | 200 / 503 | 200 / 503 on both APIs | PASS |
| PostgreSQL stopped: protected access | Dependency error | 503 on both APIs | PASS |
| PostgreSQL restarted | Readiness/session behavior recovers | 200; revoked tokens still 401 | PASS |
| User records across database restart | Same count | 10 before and after | PASS |
| Revocation after restart | Stored flag true; still-unexpired JWT rejected | True; 401 | PASS |
| Active refresh after restarts | Rotate successfully | 200; new access worked | PASS |

These were graceful stop/start/restart checks, not crash recovery or Redis volume-loss tests.

## GitHub: exercised and unavailable

| Scenario | Expected | Actual | Result |
|---|---|---|---|
| Unconfigured OAuth start/callback | 503 | 503 on local and Docker APIs | PASS |
| Configured start with unusable credentials | GitHub redirect, fixed callback, S256 PKCE | 302; challenge matched Redis verifier | PASS |
| Development binding cookie | HttpOnly, SameSite=Lax, scoped path | Attributes present | PASS |
| Missing code, unknown state, absent/wrong cookie | Reject locally | 400 | PASS |
| Expired state with shortened development Redis TTL | Reject locally | 400 | PASS |
| Invalid provider code/credentials with matching state | Sanitized upstream error, consume state | 502; state absent | PASS |
| State replay | Reject locally | 400 | PASS |
| Real GitHub public profile | Normalized success | 200; octocat and numeric ID | PASS with fixture |
| Real GitHub nonexistent profile | Sanitized upstream failure | 502 | PASS with fixture |
| Local user without provider identity | Not connected | 404 on both APIs | PASS |
| Valid client credentials + browser consent + OAuth login | Real provider login | Credentials/consent unavailable | NOT TESTED |
| Live provider timeout/malformed response | Safe failure | Not induced against GitHub | NOT TESTED manually |
| HTTPS browser cookie behavior | Secure transport/cookie behavior | No local TLS/browser setup | NOT TESTED |

For profile requests, an operator temporarily seeded an OAuthIdentity on a disposable local account,
then removed it. No provider login, account linking, or verified identity association is claimed.
GitHub traffic was real HTTPS; provider success/failure was not mocked. Timeout/malformed-response
coverage remains automated, not a manual result.

## Findings and fixes

No application-code bug was found in the completed manual scenarios.

Documentation corrections:

1. The local setup did not explicitly initialize `.env` when followed independently. It now invokes
   the helper if the file is absent, preserving existing configuration.
2. The local server ran on port 8001 while inheriting a public URL on port 8000. Its command now sets
   the matching origin and explains the separate GitHub callback registration. Live consent remains
   unverified; the corrected origin was used for the successful local-process restart checks.
3. Redis-outage wording was too broad. README/architecture now distinguish rate-limited login flows
   from existing PostgreSQL-backed bearer authorization; both behaviors were observed through HTTP.

The corrections affected README/architecture documentation; no application code changed during
this testing pass.

## Supplemental validation

The README's test setup ran against a separate `authlab_test` database and Redis database 15:

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

Result: 64 tests passed, 96% coverage; lint, formatting, typing, and schema consistency passed.
A supplemental Docker pytest attempt using the temporary directory collected no tests because the
local Docker VM did not expose those bind mounts. That attempt is not a pass; the container suite
was rerun from the shared project workspace. Normal README image builds use the build context
and did not require these test-only mounts.
The successful container rerun used the original shared workspace with the original Compose project:

```sh
docker compose run --rm --no-deps \
  -v "$PWD/tests:/app/tests:ro" -v "$PWD/docs:/app/docs:ro" \
  -v "$PWD/scripts:/app/scripts:ro" -v "$PWD/.env.example:/app/.env.example:ro" \
  -e TEST_REDIS_URL=redis://redis:6379/15 -e COVERAGE_FILE=/tmp/authlab.coverage \
  -e RUFF_CACHE_DIR=/tmp/authlab-ruff -e MYPY_CACHE_DIR=/tmp/authlab-mypy \
  app sh -c 'export TEST_DATABASE_URL="${DATABASE_URL}_test"; pytest -q -p no:cacheprovider --cov=auth_service --cov-report=term-missing && ruff check . && ruff format --check . && mypy src migrations scripts && alembic check'
```

Fresh Docker build/startup and both health endpoints passed.

Verdict: the exercised V1 development workflows pass. Full GitHub browser login, TLS deployment,
production email, Redis data-loss recovery, load testing, and long natural-expiry periods remain
outside this pass. The project's production limitations in `security-review.md` still apply.
Temporary API/client containers were stopped; the original Compose stack was restored healthy.
The isolated development volumes were retained, and no original data volume was removed.

## Swagger UI follow-up — 2026-10-01

The original Compose deployment was rebuilt with `docker compose up -d --build --wait`.
Local Flask ran from the repository root using the corrected port-8001 command above.
PostgreSQL/Redis remained real dependencies.

| Scenario | Scope | Expected | Actual | Result |
|---|---|---|---|---|
| Public `/docs` | Both | HTML 200 | 200; Swagger UI rendered in Chromium | PASS |
| Public `/openapi.json` | Both | JSON 200 matching source | Exact parsed JSON equality | PASS |
| Health/live and health/ready | Both | 200 / 200 | 200 / 200 | PASS |
| Protected current user without token | Both | 401 | 401 | PASS |
| Authorize with real login access token | Both | Authenticated request succeeds | Try it out sent Bearer header; `/users/me` returned 200 | PASS |
| Relative server URL | Both | Request targets current origin | Browser used port 8000 / 8001 respectively | PASS |
| Reload documentation page | Both | Authorization not persisted | Token field empty after reload | PASS |

Reproducible smoke commands, exercised on both deployments:

```sh
for port in 8000 8001; do
  curl --fail --silent --show-error "http://localhost:$port/docs" -o /dev/null
  curl --fail --silent --show-error "http://localhost:$port/openapi.json" -o /dev/null
  curl --fail --silent --show-error "http://localhost:$port/health/live"
  curl --fail --silent --show-error "http://localhost:$port/health/ready"
done
```

Headless Chromium used temporary Playwright tooling outside the repository, actual CDN assets,
and no network mocks. Separate disposable accounts were registered, verified using development
mailbox tokens, and logged in on each deployment. To reproduce, open `/docs`, use **Authorize**
with the access token, expand `GET /api/v1/users/me`, select **Try it out**, then **Execute**; expect
200. Reload and reopen Authorize; expect an empty token field. Successful test sessions were logged out.

An initial browser test timed out because the dialog button's accessible name is `Apply credentials`,
not its visible text `Authorize`. Correcting the temporary selector produced successful reruns on
both deployments. No application bug was found. Automated validation recorded 66 passing tests
with 96% coverage on local and Docker runtimes, plus passing lint, format, typing, and schema checks.
GitHub Actions remains unexecuted remotely.

Status: PASS for the exercised documentation workflows. Browser internet access is required for
pinned CDN assets; offline rendering and other browsers were not tested. Earlier OAuth/TLS
limitations still apply. The temporary local Flask process was stopped after verification.
