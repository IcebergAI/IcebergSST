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
the source is saved, not hours later inside a scan task. Post-MVP types (`smb`) are refused
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
- `GET  /scans/{id}/coverage` — the frozen terminal coverage manifest. Active scans return `409`.
- `GET  /scans/{id}/coverage/export` — the same manifest as byte-stable downloadable JSON, with
  `Cache-Control: no-store` and a UUID-only filename.
- `GET  /sources/{id}/coverage` — the source's latest terminal manifest, ignoring a newer active
  scan. This is `404` until the source has a terminal scan.
- `POST /scans/{id}/cancel` (analyst+) — marks the scan and its unfinished tasks. Queued tasks can
  then never be leased; a running engine finds out at its next heartbeat. Cancelling a finished scan
  is a `409`, and a cancelled scan never reconciles.

The manifest separates enumerated object outcomes (`requested`, `discovered`, `scanned`, `skipped`,
`failed`) from scope gaps whose remaining object count is unknowable (for example permission loss
or a collection failing mid-pagination). Reason codes are a versioned enum. Per-object gaps carry
only a domain-separated HMAC reference; the response never includes source configuration, names,
paths, filenames, task specs/errors, finding locators, snippets, or the legacy arbitrary count map.
An old engine that reported no structured coverage is shown as `unreported`, never as clean.
Only a terminal manifest whose coverage state is `complete` can authorize finding reconciliation
or completion notifications. A task set may be operationally `completed` while its manifest is
`partial` because content was skipped or an old engine omitted evidence; that run resolves nothing.

`source_configuration_version` is captured at launch. Source edits and credential rotations are
refused while a scan is active, so every task in the run leases the configuration revision named by
the manifest. Cancel or finish the active scan before editing its source.

## Findings
- `GET   /findings` (filter: `?source_id=`, `?state=`, `?rule_id=`, `?severity=`, `?assignee_id=`,
  `?suppressed=`; paginated). Filters compose — every one narrows the same query. **No filter is
  implicit**: the analyst's default view is `?state=open&suppressed=false`, sent by the client, not
  applied silently by the server, so a count can always be reconciled against the table.
- `GET   /findings/{id}` — the finding plus its full `FindingEvent` history, oldest first. The
  history ships with the detail because "why is this finding in this state" is the question the
  detail view exists to answer.
- `PATCH /findings/{id}` (analyst+) — `state`, `assignee_id`, `notes`, plus an optional `comment`
  recorded on the events the change writes. Returns the detail shape, history included.

Responses never carry `secret_hash` — not reversible, but a comparison oracle nobody should be
handed casually. The one deliberate, scoped exception to "never anything derived from the secret"
is the **correlation id** (ADR 0011): an API-minted equality label under a key that never leaves
the API, shown to analyst+ as `correlation` on the finding detail and served by the cluster
routes below. Viewers get `correlation: null` — role-shaped, not merely absent.

## Correlation (analyst+, ADR 0011)
- `GET /correlation/clusters` (paginated; `?min_findings=`, `?source_id=`) — every exposure
  cluster: the same secret value grouped across all its locations, with finding/source/open
  counts, worst severity, first-seen and last-activity. `min_findings` defaults to 1 — the
  endpoint hides nothing; the console's spread view sends `?min_findings=2` explicitly.
- `GET /correlation/clusters/{correlation_id}` — the topology: members grouped by source, each
  member in the findings-API shape so per-location remediation state rides along.
- `GET /correlation/clusters/{correlation_id}/export` — byte-stable JSON download (versioned
  manifest, `Content-Disposition: attachment`, `Cache-Control: no-store`). Locations and states
  only — no snippets, no notes. Every download writes a `correlation.cluster_exported` audit
  event. The manifest's counts are computed from the members it lists, and the export is
  **complete or refused**: a cluster larger than the export bound answers `409` naming
  `GET /findings?correlation_id=…`, which pages. A short work order reads as the full list of
  places the secret lives, so it is never produced.

All three are analyst+ and 403 for viewers: clustering is the "same secret elsewhere" capability,
scoped to the roles that remediate. A `source_id` filter narrows *which clusters appear* (those
with a member in that source) without narrowing the aggregates — a spread view that hid the
spread would defeat itself. `GET /findings?correlation_id=…` is the paginated way to walk one
cluster of any size, and carries the same analyst+ gate for the same reason.

**The state machine.** `open` → `false_positive` / `accepted_risk` / `resolved`, and any of those
back to `open`. There is no direct move between judgements: relabelling one in place would leave an
audit trail reading "it was always this" rather than "somebody reopened it and decided again".
An illegal transition is a `409`, and nothing else in the same `PATCH` is applied either — a
rejected request must not leave the assignee changed. Re-sending the state a finding is already in
is a no-op, not a conflict: a retried request is not an error.

Every real change writes a `FindingEvent` — `state_change`, `reopened` (any return to `open`,
whoever or whatever caused it), `assign`, `comment`. Notes are recorded as events as well as on the
row, so editing them does not erase what the last analyst wrote. `assignee_id: null` unassigns;
omitting the field leaves the assignee alone. Assigning to an unknown or disabled user is a `422`.
Resolving by hand sets `resolution: manual`; reopening clears it, so a reopened finding never keeps
reconciliation's `auto`.

## Remediation (ADR 0012)
- `GET  /remediation/guidance/{rule_id}` — versioned advice for one rule, split into revoke /
  rotate / scope-reduce / remove-source steps; falls back to the `default` entry and says so in
  `matched`. Never executed by the platform — advice for a human.
- `GET  /findings/{id}/remediations` — the finding's actions, oldest first. Role-shaped: analysts
  see notes and evidence-link URLs; viewers see the fact of each action with link labels only.
- `POST /findings/{id}/remediations` (analyst+) — record what was done: kind, when it was
  performed, a note, up to ten evidence links (http(s) only, no embedded credentials). Stamps the
  live guidance version. Content is write-once — retract and re-record to correct.
- `POST /findings/{id}/remediations/{rid}/verify` (analyst+) — one-way confirmation the action
  took effect; repeating it is a `409`.
- `POST /findings/{id}/remediations/{rid}/retract` (analyst+) — set-once, reason required;
  a retracted action stops satisfying the evidence policy.

Every mutation writes a `FindingEvent` (`remediation`, `remediation_verified`,
`remediation_retracted`) and an audit row. The finding detail carries `remediations` alongside
`events` in the caller's shape.

**Required-evidence policy.** With `ICEBERG_REMEDIATION_EVIDENCE_MIN_SEVERITY` set, resolving a
finding at or above that severity without a non-retracted, evidence-carrying action is a `409`
naming the fix. Judgements (`false_positive`, `accepted_risk`) and reconciliation's auto-resolve
are exempt by design; unset (the default) changes nothing.

## Suppressions
- `GET  /suppressions` (paginated; `?source_id=`, `?scope=`, `?active=`) · `GET /suppressions/{id}`
- `POST /suppressions` (analyst+) — `scope` (`path_glob` / `fingerprint` / `rule`), `pattern`,
  optional `source_id` (null = global), `reason` (required, non-blank), optional `expires_at`
  (must be in the future).
- `DELETE /suppressions/{id}` (analyst+)

`?source_id=` returns that source's suppressions **and the global ones**, because "what is hidden
from this source" is the question being asked. Create and delete are audited.

Suppression is applied and lifted eagerly, not only at the next scan:
- creating one suppresses the findings it already covers;
- deleting one releases them, with an event saying why they came back — releasing before the row
  goes, so the finding is never left hidden pointing at a nulled foreign key;
- the maintenance round releases findings whose suppression has expired, so expiry is a property of
  the clock rather than of a source's scan cadence.

Suppressed findings are **recorded, not discarded** (ADR 0008): they stay in the table with
`suppressed_at`/`suppressed_by_id` set and a `suppressed` event, out of the active view but not out
of the record. There is no `PATCH`: editing a live suppression's pattern would silently re-scope
what it hides, and creating a replacement leaves both decisions in the audit trail.

## Rules
- `GET /rules` → the detection surface currently in force (read-only; rules are code, per ADR 0008)

Sourced from **what the engines report**, not from anything the API ships. Rule packs live inside
engine images, so the API has no pack to list, and one hard-coded here would describe what the
fleet is *supposed* to be running — which is the thing this endpoint exists to check. Engines
report their pack at registration and on every heartbeat, so a rolling deploy is visible as it
happens.

Disagreement is a first-class answer rather than an error: mid-deploy two rule-pack versions are
both in force, and a response that picked one would be wrong about half the fleet. The payload
carries `fleet_consistent`, every `rulepack_version` with the engines running it, each rule with
the versions that define it, `engines_without_a_rulepack`, and the current `confidence_threshold`.
Only draining and active engines count — an offline engine's pack is history, not the current
surface.

Rules are metadata only — id, description, severity. **Never a regex**: patterns stay in the image,
and serving them would invite a client to re-implement detection against them.

The **confidence threshold** is configured on the API (`ICEBERG_CONFIDENCE_THRESHOLD`), delivered
to engines in the lease response, and applied again at ingest. One value in one place, and an
engine running a stale image still cannot fill the queue with matches this deployment has decided
are noise. A finding reported without a confidence score is kept: `null` means the engine did not
judge it, which is not the same as judging it noise.

## Notifications
- `GET /notifications/channels` · `POST …` · `GET/PATCH/DELETE /notifications/channels/{id}`

**Admin-only, every route.** A webhook channel carries redacted snippets and
resource locations out of the deployment, so who may configure one is the control
(docs/security.md § Notification egress), and every mutation is audited with the
destination it points at — never with the secret.

The `config` blob is validated per channel type: a webhook needs an absolute
`http(s)` URL and may carry non-secret `headers`; an email channel needs
recipients. The header names browsers and proxies use for authentication
(`Authorization`, `Proxy-Authorization`, `Cookie`) are **refused**, because
config is stored as plain JSON and a token in one would be a plaintext secret at
rest — pointing the operator at `secret`, which is sealed through the secret
store (ADR 0007), is the whole reason the field exists.

A channel secret is write-only, exactly like a source credential: supplying one
on `POST`/`PATCH` seals it, no response carries the plaintext *or* the sealed
ref, and `has_secret` says whether one exists. Editing `config` keeps the sealed
ref — fixing a typo in a URL is not a request to drop the signing key. There is
no way to remove a secret and no way to change a channel's `type`: a config
validated as an email list is not a webhook config, so the honest operation is a
replacement.

Dispatch itself is M4. These routes are the configuration surface the console
drives; the delivery loop reads these rows.

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
- Results may include a versioned `coverage` object. Its equations and reason subtotals are
  validated before ingest and the accepted object is stored once with the task's idempotency key.
  The field is temporarily optional for rolling upgrades; omission becomes an explicit
  `unreported` coverage gap. Discovery's observed-scope count must equal its returned task-spec
  count, and discovery/fetch payload types cannot cross phases.
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
- **The console is a client of these routes.** The HTML surface at the application root calls these
  handlers directly rather than reimplementing them, so a change here changes the UI too. It is
  excluded from this schema on purpose — see [`docs/web.md`](./web.md).
