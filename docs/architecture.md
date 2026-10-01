# Architecture and design decisions

Auth Service Lab is a synchronous Flask modular monolith. The application factory wires an
SQLAlchemy engine/session factory, Redis, Flask-Limiter, and development email/GitHub adapters.
API modules validate requests and serialize responses; AuthService owns authentication state
changes and transaction boundaries. Models express database constraints. Security helpers own
password and JWT mechanics. There is no generic repository or dependency-injection framework.

## Authentication

V1 is an API with bearer access tokens and JSON refresh tokens. It does not authenticate application
requests with cookies, implement a frontend, or store tokens in browser local storage. Consequently
application endpoints do not need cookie CSRF protection. OAuth uses an HttpOnly, SameSite=Lax
browser-binding cookie; it is Secure when PUBLIC_URL is HTTPS. The cookie cannot authenticate API
requests. Access and refresh tokens have distinct types/audiences and required claims. HS256 is
fixed by the server. Keys must be generated randomly, never derived from passwords.

Protected requests check PostgreSQL for the current user, role, and active session. JWTs are not
stateless: logout, disabling, and password recovery revoke access immediately on subsequent
requests. In-flight requests may complete. Default access lifetime is 10 minutes; refresh lifetime
is 7 days with an absolute 30-day session lifetime. Refresh rotates on every use. Tokens are stored
as SHA-256 digests. Consumed tokens remain available for replay detection.

Refresh/password flows acquire user locks before session/token mutations. Reuse revocation commits
before the error is raised. Concurrent refresh requests produce one success and one replay failure,
revoking the family; clients must serialize refreshes and must not blindly retry an ambiguous
refresh result. Administrator mutations also use a transaction-level PostgreSQL advisory lock to
preserve the last active administrator.

## Recovery and email

Verification and reset tokens are random 256-bit opaque values, stored as digests, with 30-minute
expiry and one-time consumption. Resending invalidates the previous token for that purpose.
Password changes and resets revoke every session and invalidate outstanding reset tokens.
Unknown accounts receive generic responses. Timing equalization is used for password verification,
not guaranteed for registration or development email delivery.

Development email messages are written synchronously to randomly named private files. Delivery
occurs after commit and may fail independently; users can request another message. There is no
production email delivery or durable retry worker. APP_ENV=production fails at startup to prevent
accidentally deploying this adapter as a production email solution.

## GitHub

OAuth uses authorization code + S256 PKCE, random state, a browser binding, and a five-minute Redis
record consumed atomically with GETDEL. Provider subject IDs establish identity. Verified primary
email is required for new accounts. Matching local emails never merge automatically; account
linking is deferred. Provider access tokens are used transiently and discarded.

External profile requests use an application-owned schema and a fixed GitHub origin, bounded
response size, explicit timeouts, and no redirects. HTTP calls happen before opening database
transactions, or after closing a read transaction. V1 intentionally makes one request without
automatic retries so upstream failures have a predictable latency budget.

## Dependencies and operations

PostgreSQL is authoritative. Redis backs rate limits and short-lived OAuth state. Authentication
fails closed on Redis errors; readiness checks both dependencies. Liveness only checks the process.
Rate limits apply by direct peer IP and normalized-email digest. Proxy headers are not trusted.
Deployment behind a reverse proxy requires an explicitly reviewed proxy/IP configuration.

Successful security events commit with their state changes. Failed credential checks are recorded
separately. Events contain IDs and event names, never secrets. Unexpected errors log only a stable
code and request ID; SQL parameters and provider response bodies are not logged. Gunicorn access
logging is disabled because OAuth callback URLs contain temporary codes.
