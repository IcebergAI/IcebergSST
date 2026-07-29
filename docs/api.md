# API surface

IcebergSST is **API-first**: the FastAPI OpenAPI schema is the contract, and the HTMX/Alpine UI
is just another client of these routes. Routes are grouped into a **human-facing API** (OIDC +
RBAC) and an **engine-facing API** (per-engine token; the only ingress for results).

## Auth
- `GET  /auth/login` → 307 to the OIDC provider (authorization code + PKCE). Optional `?next=`,
  reduced to a local path so it cannot become an open redirect.
- `GET  /auth/callback` → verifies `state`, the ID token (signature/issuer/audience/expiry), and the
  `nonce`; provisions the user on first login; sets the session cookie; 303 to `next`.
- `POST /auth/logout` → clears the session. A POST, and CSRF-protected.
- `GET  /auth/me` → current user + role + **this session's CSRF token** (how the UI obtains one).

Sessions are signed, expiring `HttpOnly`/`SameSite=Lax` cookies carrying the user id and CSRF
token — never the role. Every request re-loads the user, so a demotion or a disable takes effect on
the next request rather than at cookie expiry.

## Users (admin)
- `GET   /users` (paginated) — list users
- `PATCH /users/{id}` — assign `role`, set `disabled`. Every change writes an `AuditEvent`; nobody
  may modify their own account (see `docs/security.md` § Bootstrap).

## Sources
- `GET    /sources` · `POST /sources` · `GET/PATCH/DELETE /sources/{id}`
- `POST   /sources/{id}/test` → connectivity check (uses stored credential)
- `POST   /sources/{id}/scan` → trigger an on-demand scan

## Schedules
- `GET /schedules` · `POST /schedules` · `GET/PATCH/DELETE /schedules/{id}`

## Scans
- `GET  /scans` (filter by source/status) · `GET /scans/{id}`
- `GET  /scans/{id}/tasks`
- `POST /scans/{id}/cancel`

## Findings
- `GET   /findings` (filter: source, state, rule, severity, assignee; paginated)
- `GET   /findings/{id}` (includes FindingEvent history)
- `PATCH /findings/{id}` (state, assignee, notes → records a FindingEvent)

## Suppressions
- `GET /suppressions` · `POST /suppressions` · `DELETE /suppressions/{id}`

## Rules
- `GET /rules` → rule-pack listing + metadata (read-only; rules are code, per ADR 0008)

## Notifications
- `GET /notifications/channels` · `POST …` · `PATCH/DELETE /notifications/channels/{id}`

## Engine-facing (per-engine token auth)
These are the **only** routes that accept results. Lease semantics are defined in ADR 0009.
- `POST /engines/register` → obtain/rotate engine credential (first token minted at deploy
  time via CLI/Job — see `docs/security.md` § Bootstrap)
- `POST /engines/{id}/heartbeat`
- `POST /scan-tasks/{id}/lease` → claim a task; response carries the task spec, task-scoped
  source credential, fingerprint pepper, and applicable suppressions
- `POST /scan-tasks/{id}/results` → submit redacted findings + task completion; requires an
  **idempotency key** (task id + attempt) so retries never duplicate findings
- Discovery tasks return `TaskSpec`s through the same results route (two-phase scans, ADR 0009)

## Ops
- `GET /healthz` · `GET /metrics` (Prometheus)

## Conventions
- **Versioned paths:** all routes live under `/api/v1/…` from day one (paths above omit the
  prefix for brevity). `/healthz` and `/metrics` stay unversioned — operators and scrapers are not
  API clients.
- RBAC enforced by a dependency on every human route (`admin`/`analyst`/`viewer`).
- CSRF token required on every session-authenticated mutating route (HTMX posts include it).
- Mutations that change finding state always write a `FindingEvent` for audit.
- Engine routes reject anything but a valid engine token; human sessions cannot post results and
  engine tokens cannot read findings.
- Pagination via `limit`/`cursor`; list endpoints return stable ordering. Cursors are **keyset**
  (the last row's `created_at` + `id`), because offsets skip and repeat rows when the underlying set
  shifts between requests. A malformed cursor is a `400`, never a wrong page.
- **401 vs 403:** unauthenticated requests get `401`; authenticated requests with the wrong role, or
  a missing CSRF token, get `403`. Failure messages never say *which* check failed.
