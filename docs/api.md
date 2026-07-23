# API surface

IcebergSST is **API-first**: the FastAPI OpenAPI schema is the contract, and the HTMX/Alpine UI
is just another client of these routes. Routes are grouped into a **human-facing API** (OIDC +
RBAC) and an **engine-facing API** (per-engine token; the only ingress for results).

## Auth
- `GET  /auth/login` → redirect to OIDC provider
- `GET  /auth/callback` → establish session
- `POST /auth/logout`
- `GET  /auth/me` → current user + role

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
  prefix for brevity).
- RBAC enforced by a dependency on every human route (`admin`/`analyst`/`viewer`).
- CSRF token required on every session-authenticated mutating route (HTMX posts include it).
- Mutations that change finding state always write a `FindingEvent` for audit.
- Engine routes reject anything but a valid engine token; human sessions cannot post results and
  engine tokens cannot read findings.
- Pagination via `limit`/`cursor`; list endpoints return stable ordering.
