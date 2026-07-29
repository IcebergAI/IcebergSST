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
- `GET    /sources` (paginated) · `POST /sources` · `GET/PATCH/DELETE /sources/{id}`
  Writes are admin-only; reads are open to any authenticated role, because an analyst triaging a
  finding needs to see where it came from.
- `POST   /sources/{id}/test` → connectivity check using the stored credential. **Admin-only**: it
  makes an outbound request to an operator-supplied URL with a real credential.
- `POST   /sources/{id}/scan` → trigger an on-demand scan (analyst+). `202`, not `201`: the scan
  exists but nothing has been scanned until an engine leases its discovery task.

The `connection` blob is validated against a per-type model on write — a bad `base_url` fails when
the source is saved, not hours later inside a scan task. Post-MVP types (`jira`, `smb`) are refused
with an explanation. Credentials are write-only: supplying one on `POST`/`PATCH` seals it through the
secret store, and no response ever carries the plaintext *or* the sealed ref — `has_credential` says
whether one exists.

## Schedules
- `GET /schedules` (paginated, `?source_id=`) · `POST /schedules` · `GET/PATCH/DELETE /schedules/{id}`
- Cron is validated on write; `next_run_at` is computed on create, on enable, and when the expression
  changes, so "when does this fire next?" is answerable from the row.
- A schedule re-enabled after a week off fires on its next beat — it does not owe a scan for every
  beat missed.

## Scans
- `GET  /scans` (paginated; `?source_id=`, `?status=`, `?active=`) · `GET /scans/{id}`
- `GET  /scans/{id}/tasks` — task states for the live-status view. **Specs are omitted**: they name
  the resources being fetched.
- `POST /scans/{id}/cancel` (analyst+) — marks the scan and its unfinished tasks. Queued tasks can
  then never be leased; a running engine finds out at its next heartbeat. Cancelling a finished scan
  is a `409`, and a cancelled scan never reconciles.

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
Authentication is `Authorization: Bearer <engine token>`; session cookies are ignored here, and an
engine token is ignored everywhere else.

- `POST /engines/register` → mint or **rotate** an engine credential. **Admin session**, not an
  engine token: an engine that could enrol itself would let anyone who reaches the API join the
  fleet. The token is returned once — only its SHA-256 hash is stored. The first one is minted at
  deploy time with `python -m iceberg_api mint-engine-token --name engine-1`
  (`docs/security.md` § Bootstrap).
- `GET  /engines` → fleet status for the engine-health view (admin). Never any token material.
- `POST /engines/{id}/heartbeat` → extends the leases this engine holds and **returns any of its
  tasks that have been cancelled**, which is the only way to tell a working engine to stop. The path
  id must match the token.
- `POST /scan-tasks/{id}/lease` → claim a task. `409` for every refusal (already leased, finished,
  cancelled, unknown) because the engine's response to all of them is to drop the message. The
  response carries the spec, the task-scoped source credential, the fingerprint pepper, and the
  applicable suppressions.
- `POST /scan-tasks/{id}/results` → submit redacted findings + task completion. Requires a live
  lease held by this engine and an **idempotency key** (`<task id>:<attempt>`): the same key replays
  as a no-op, a different key against a finished task is a `409`. An engine may report `completed`
  or `failed` only — cancellation is the API's decision.
- Discovery tasks return `TaskSpec`s through the same results route (two-phase scans, ADR 0009).

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
