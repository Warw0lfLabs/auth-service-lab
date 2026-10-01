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
