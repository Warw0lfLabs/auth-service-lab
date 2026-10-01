# V1 security review

Review scope: authentication, authorization, JWT handling, recovery, configuration, external
requests, and logging. Regression tests live in tests/test_regressions.py in addition to flow tests.

| Concern | Control and verification |
|---|---|
| Password storage | Argon2id; verification, wrong-password, dummy-hash, and stored-hash tests |
| Account discovery | Generic login, registration, forgot-password responses; unknown-user tests |
| Privilege injection | Strict schemas reject unknown fields; registration always assigns user |
| Stale privileges | Database role/session check on each request; promotion/disable tests |
| JWT confusion | Fixed HS256, issuer/audience/type/required claims; expiry and mutation tests |
| Token theft/replay | Rotation, stored digests, family revocation; real PostgreSQL concurrency test |
| Recovery replay | Expiry, purpose separation, user/token locks; concurrent consumption tests |
| Password compromise | Password change/reset revoke all sessions and invalidate reset tokens |
| OAuth login CSRF | State, PKCE, browser binding, atomic one-time state; replay/binding tests |
| OAuth account takeover | Subject identity; reject local-email collisions; collision test |
| Upstream failure | Fixed origins, no redirects, bounded response/timeouts, validated JSON |
| Transaction exhaustion | External HTTP outside DB transactions; explicit assertion test |
| Dependency outages | PostgreSQL/Redis failures return sanitized 503; fail-closed tests |
| Audit/log secrets | IDs-only security records; sanitized error logging; leakage regression |
| Concurrent registration | Unique constraint plus generic duplicate handling; race regression |
| Last administrator | Serialized admin mutations; last-admin regression |

Limitations: no MFA, password breach lookup, production email adapter, email change, account linking,
automated signing-key rollover, or access-token recovery after network-ambiguous refresh. Rate limits
reduce abuse but do not replace edge protection. Argon2 parameters must be benchmarked for a target
host. Development mailbox files contain plaintext action tokens and must be treated as credentials.
Database backups also contain sensitive account and security data. Public TLS/reverse proxy and
operational retention policies are deployment work outside V1.

Signing-key replacement invalidates all existing JWTs. Retain replay records until their session
expires. Security events and expired records currently require operator-managed retention; V1 has
no automated cleanup job. Restrict database and mailbox access and never expose .dev-mail over HTTP.

## Pre-release findings

No critical or high-severity issue was identified in the manual review.

- **Medium, fixed:** account rate-limit keys used raw email text while authentication used validated
  email normalization. Unicode/punycode aliases could split limits for one account. Limiter keys now
  use the same validation; a regression checks equivalent addresses across different peer IPs.
- **Low, fixed:** arbitrary Host headers were accepted. Hosts are now restricted to the configured
  public hostname and localhost/127.0.0.1; forwarded headers remain untrusted.
- **Low, fixed:** CI actions used mutable tags and persisted checkout credentials. Actions now use
  verified commit IDs and checkout does not persist its token.
- **Low, fixed:** ignore rules missed secret variants and nested Docker build artifacts. Environment
  files, private keys, editor files, and nested caches/build output are excluded. Package-build
  metadata created during image installation is removed from the final image.
- **Low, fixed:** demo seeding bypassed API email/password validation. It now applies the registration
  schema so demo accounts can authenticate through the API.
- **Low, fixed:** the test database guard checked the URL suffix instead of the parsed database name.
  It now rejects production database names even when a query parameter ends in `_test`.

No authentication bypass, RBAC/ownership bypass, SQL injection, unsafe deserialization, caller-driven
SSRF, open redirect, or secret-bearing error/log output was found. OAuth state, browser binding,
PKCE, one-time action consumption, password/session revocation, and replay transactions were traced
manually as well as tested. Bearer API endpoints do not use cookie authentication; CORS is disabled.

Remaining deployment risks: Compose uses a PostgreSQL superuser for local convenience and Redis
has no authentication on its loopback-only host port. Do not expose these ports or reuse this setup
as production infrastructure. Audit records have no HTTP mutation endpoint but are not tamper-proof
against a database administrator or compromised application database credentials. Not every rejected
operation emits an audit event. Generic account responses do not guarantee indistinguishable timing.
Dependencies are version-pinned without artifact hashes; container image tags are mutable. These
supply-chain and operating controls require maintenance, even when an advisory scan is clean.

References: [Flask Host validation](https://flask.palletsprojects.com/en/stable/web-security/)
and [GitHub Actions security](https://docs.github.com/en/actions/reference/security/secure-use).
