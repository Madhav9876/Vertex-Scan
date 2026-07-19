# Vertex Scan — Security Implementation & Production Checklist

This document records how each requested security control is implemented in the
Vertex Scan codebase, and which items are **Not Applicable (N/A)** to this
architecture. The app is a **stateless JSON API** authenticated with **Bearer
JWT** (no cookie sessions, no file uploads), so cookie/session/file-upload
controls are documented as N/A rather than stubbed with dead code.

## Implemented controls

### Authentication & Authorization
- JWT secret is **required** from env; server refuses to start with a weak default (`src/middleware/auth.js`).
- Passwords hashed with bcrypt (cost 12); API keys hashed before storage.
- Every protected route uses `authenticateToken`; ownership is enforced per-row
  (`WHERE user_id = $1`). `requireRole` available for admin endpoints.
- **Token hardening:** JWTs now carry `jti`/`iss`/`aud` claims and default to a
  short `15m` lifetime. A per-user `token_version` column lets `/auth/logout` and
  `PATCH /auth/password` **revoke all active sessions** (stateless revocation).
- **New:** login brute-force lockout after 10 failures / 15 min (`src/routes/auth.js`).
- **New:** authenticated password change (`PATCH /api/auth/password`) and logout
  (`POST /api/auth/logout`) endpoints.

### Input Validation
- `src/utils/validation.js`: email regex, password length 8–128, UUID check,
  module allowlist, HTML escaping (`escapeHtml`).
- Scan `options` sanitized (`timeout` 5–120, `user_agent` length-capped).
- Report `scan_id` must be a valid UUID.

### Secrets & Environment
- `.env` is **git-ignored** (see `.gitignore`); a committed `.env.example` ships
  only placeholders. `JWT_SECRET` is required at startup; request body capped at 1 MB.
- **Removed** the shadowing `https` npm dependency and unused deps
  (`socket.io`, `json2csv`, `axios`, `cheerio`, `pdfkit`).

### SQL / NoSQL Injection
- All queries use parameterized `$1,$2…` placeholders — no string concatenation.
  No NoSQL store in use.

### SSRF
- `assertPublicTarget()` resolves the hostname **once** and pins the validated
  IP (`resolvedAddress`/`family`). The scanners connect to that pinned address
  with SNI/Host preserved, closing the earlier **DNS-rebinding / TOCTOU** bypass.
  Private, loopback, link-local, and cloud-metadata ranges
  (e.g. `169.254.169.254`, `localhost`, `192.168.x`) are rejected.

### CORS & Security Headers
- CORS is an **allowlist** (`CORS_ORIGIN`, comma-separated); unknown origins →
  clean `403`.
- Helmet enabled: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
  `Referrer-Policy: no-referrer`, `Cache-Control: no-store`, prod CSP + HSTS.

### Rate Limiting & Abuse
- `express-rate-limit`: global 300/15 min, auth 20/15 min (skip successes),
  scan-create 10/min. Scan creation records client IP + user-agent to audit log.

### CSRF Protection — **N/A (Beaker/JWT)**
- The API uses **Bearer tokens in the `Authorization` header**, not cookies,
  so there is no ambient cookie-based auth and therefore no CSRF surface.
- If cookie auth is ever added: enable `csrf` tokens, set cookies
  `HttpOnly; Secure; SameSite=Strict`, and rotate on login/privilege change.

### XSS Protection
- All report output is HTML-escaped via `escapeHtml` (`src/routes/reports.js`);
  validated with a malicious-finding unit check.
- CSP enforced in production.

### File Upload Security — **N/A**
- The API has **no file upload endpoints**. Reports are generated server-side
  (JSON/CSV/HTML) and returned inline; nothing is written to disk.
- If uploads are added later: restrict MIME/extension allowlist, enforce size
  limit, store outside web root / object storage, and AV-scan.

### Logging & Monitoring
- `src/middleware/security.js`: structured `security_events` table logs
  `login_failed`, `login_success`, `register_*`, `login_lockout`,
  `server_error`, etc. with IP + reason.
- **Secrets are never logged** — `password`, `token`, `api_key`, `Authorization`,
  etc. are redacted (`redact()`).
- `X-Request-Id` correlation header added to every response.

### Dependency Security
- `npm audit` integrated into CI; **0 vulnerabilities** currently (upgraded
  `uuid` to v11 to clear the advisory).
- Dependabot configured (weekly) for backend & frontend.
- Unused packages (`dns`, `tls`, `node-fetch` npm shims) removed.

### HTTPS
- Production enforces HTTPS: plain-HTTP requests redirected to HTTPS, HSTS
  enabled (1 year, includeSubDomains, preload).

### Database Security
- Connections use environment-provided credentials; pool limited to 20.
- **TLS to Postgres is enforced in production** (`ssl: { rejectUnauthorized: true }`
  in `src/db/connection.js` when `NODE_ENV=production` and `DB_SSL !== 'false'`).
- **Least-privilege role** is created/granted by `migrate.js` when
  `DB_CREATE_ROLE=true` (run once as a superuser). The app connects as
  `vertex_app`, which only has DML + default-privilege grants on its schema.
- Encrypt sensitive columns at rest via the cloud provider's volume encryption.

### API Security
- Request size + `Content-Type: application/json` enforced (415 on violation).
- Generic error messages in production (no stack/impl leak).
- Consistent `authenticateToken` ownership checks across all endpoints.
- API versioned under `/api/v1` (alias of `/api`) for safe future changes.

### Session Security — **N/A (stateless JWT)**
- No server-side sessions. Token lifetime is `JWT_EXPIRES_IN` (24h).
- If cookie/session auth is introduced: rotate session id on login & privilege
  change, set expiry, invalidate on logout/password change.

### Security Testing
- Automated security test suite: `backend/test/security.test.js`
  (run `npm run test:security`) — covers SSRF, auth, validation, CORS, headers,
  content-type, 404.
- CI workflow (`.github/workflows/security.yml`): **SAST via Semgrep + GitHub
  CodeQL**, **DAST via OWASP ZAP baseline**, `npm audit` (moderate+), migrate,
  and the security test suite — on every PR and weekly.
- Recommendation: periodic **penetration testing** and tune ZAP rules
  (`.zap/rules.tsv`).

## Production security checklist
- [x] Strong authentication (bcrypt + JWT, secret enforced, jti/iss/aud, 15m expiry)
- [x] Server-side authorization on every protected endpoint
- [x] Session/token revocation (logout + password change bump `token_version`)
- [x] Comprehensive input validation
- [x] Parameterized SQL queries
- [x] Secrets git-ignored; no real secrets committed (`.gitignore` + `.env.example`)
- [x] CORS restricted to trusted origins
- [x] Helmet + secure HTTP headers (incl. CORP/COOP/Permissions-Policy)
- [x] Rate limiting & abuse protection (global/auth/scan + concurrency + daily quota)
- [x] HTTPS enforced (redirect + HSTS in prod)
- [x] XSS protections + CSP
- [x] Generic error messages (no leakage)
- [x] Content-type / request-size validation + bounded pagination
- [x] SSRF fixed (DNS-rebind/TOCTOU closed via pinned resolved address)
- [N/A] CSRF protection (no cookie auth)
- [N/A] Secure file upload handling (no uploads)
- [N/A] Secure cookies HttpOnly/Secure/SameSite (no cookie auth)
- [x] Dependency vulnerability scanning (`npm audit` + Dependabot)
- [x] Security logging & monitoring (`security_events`, no secret leakage; SSRF/quota events)
- [x] Automated security testing in CI/CD (SAST: Semgrep + CodeQL; DAST: OWASP ZAP)
- [x] Least-privilege DB user + DB TLS (implemented, see Database Security)
- [ ] Periodic penetration testing (recommended)
