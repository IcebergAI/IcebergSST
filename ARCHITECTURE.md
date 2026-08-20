# IcebergSST — Architecture

This document is the authoritative design specification for IcebergSST. It captures the system
shape, component boundaries, and the confirmed decisions that constrain implementation. Rationale
for each decision lives as an ADR under [`docs/adr/`](./docs/adr/).

## 1. Purpose & scope

IcebergSST finds secrets (passwords, API keys, tokens, private keys) that have been
inappropriately stored in enterprise collaboration systems and file shares. It deliberately
targets sources that git-oriented scanners miss:

- **Confluence** — pages, comments, and text-extractable attachments.
- **Jira** — issues, comments, attachments, and opt-in field history (Cloud; DC not certified).
- **File shares** — SMB/CIFS and NFS, over a read-only mount rather than two protocol clients.

All three ship, on a versioned connector SDK with a conformance kit
([`docs/connectors.md`](./docs/connectors.md), [`docs/connector-sdk.md`](./docs/connector-sdk.md)).

It is a **single-organization** internal security tool: one deployment serves one org. There is
no tenant partitioning.

## 2. High-level architecture

```
                    ┌────────────────────────────────────────┐
                    │            Management Plane             │
   Browser ──HTMX──▶│  FastAPI (API-first, OpenAPI)          │
   (Alpine+HTMX)    │   • Auth (OIDC / RBAC)                  │
                    │   • Sources / Scans / Findings / Rules  │◀── progress + results
                    │   • Ownership / clusters / hand-over    │    (REST, token-auth)
                    │   • Scheduler (cron → enqueue)          │        ▲
                    │   • Notifications                       │        │
                    └───────┬─────────────────┬──────────────┘         │
                            │ SQLModel         │ enqueue (Dramatiq)     │
                            ▼                  ▼                        │
                     ┌────────────┐      ┌──────────┐                   │
                     │ PostgreSQL │      │  Redis   │                   │
                     └────────────┘      └────┬─────┘                   │
                                              │ consume jobs            │
                              ┌───────────────┼───────────────┐         │
                              ▼               ▼               ▼         │
                        ┌──────────┐    ┌──────────┐    ┌──────────┐    │
                        │ Engine   │    │ Engine   │    │ Engine   │────┘
                        │ worker   │    │ worker   │    │ worker   │
                        │ (detect) │    │ (detect) │    │ (detect) │
                        └──────────┘    └──────────┘    └──────────┘
                          connectors + detection rulepacks; DB-credential-free
```

Three deployable roles, built from a shared codebase:

1. **API (`apps/api`)** — the FastAPI control plane. The only component that reads/writes
   Postgres. Serves the REST API, the HTMX web UI, the scheduler, and notification dispatch.
2. **Engine (`apps/engine`)** — a Dramatiq worker. Consumes scan-task jobs from Redis, runs a
   connector to fetch content, runs the detection engine, redacts matches, and POSTs normalized
   findings back to the API. Holds **no** database credentials.
3. **Infrastructure** — PostgreSQL (system of record) and Redis (broker).

## 3. Component boundaries & principles

### 3.1 The API is the sole writer of record
Engines never connect to Postgres. They authenticate to the API with a per-engine credential
(bearer token now; mTLS an option later) and submit results through a dedicated engine-facing
endpoint. This keeps the engine blast radius minimal — a compromised engine cannot read the
findings database or other sources' credentials — and honors the requirement that engines are
"separate from the management layer and report back to the API."

### 3.2 Detection logic in code, tuning in data
- **Rule packs** are versioned artifacts (YAML + Python) shipped inside the engine image. Every
  finding records the `rule_id` and `rulepack_version` that produced it, so results are
  reproducible and rule changes are auditable.
- **Suppressions / allowlists** are runtime *data* in Postgres, editable by analysts through the
  UI. They are applied both at result-ingest time (server side) and surfaced in the UI. Scopes:
  per-path glob, per-fingerprint, per-rule, with an optional expiry.

### 3.3 Never persist plaintext secrets
Redaction happens **inside the engine**, before any result leaves the worker. Only a masked
snippet (e.g. `AKIA…4 chars`) and a salted hash of the secret cross the wire and reach the DB.
The salt/pepper is retrieved through the secret-store interface. The findings database therefore
never contains a usable secret.

### 3.4 Pluggable secret store
`packages/core` defines a `SecretStore` interface used for **connector credentials** and the
**fingerprint pepper**. The default backend encrypts at the app layer (AES-GCM / Fernet) with a
master key injected via environment / k8s secret. A `VaultBackend` seam is documented for
production. This is the ".env now, Vault later" path.

## 4. Data flow: a scan (two-phase, ADR 0009 and ADR 0013)

1. A scan is triggered — **on-demand** (user or API) or by the **cron scheduler** (guarded by a
   Postgres advisory lock so multiple API replicas never double-fire). A schedule's **mode** is a
   request, not a guarantee: the API promotes an incremental scan to a full one whenever a
   watermark cannot be trusted — a rule-pack change, a source edit, a pepper rotation, a fleet that
   disagrees about its rule pack, or the source's full-scan interval having elapsed — and records
   why (ADR 0013 §5).
2. The API creates a `Scan` row and enqueues a single **discovery task** (the broker message is
   an id-only hint — no secrets, no specs).
3. An **engine** leases the discovery task — the lease response delivers the task spec, the
   task-scoped source credential, the fingerprint pepper, applicable suppressions, and, for an
   incremental scan against a connector that declares `INCREMENTAL`, the per-scope **cursors** —
   runs `connector.discover()`, and POSTs the resulting `TaskSpec`s back.
4. The API persists them as **fetch tasks** and enqueues each; engines lease fetch tasks and run
   connector fetch → detection → redaction. Redaction happens **inside the engine**: only a masked
   snippet and a salted hash ever leave it (ADR 0004).
5. A fetch does not have to end before it reports. A connector declaring `CHECKPOINTS` flushes
   batches mid-fetch to `POST /scan-tasks/{id}/progress`, which ingests the findings **and**
   advances the task's resume position in one transaction — a checkpoint that outran its findings
   would tell the next attempt to start past content nobody stored (ADR 0013 §1). The batch is cut
   where the connector's published position and the accumulated findings describe the same prefix
   of the work, so a resumed attempt neither skips nor double-counts.
6. The terminal submission (idempotency-keyed) carries what the batches did not, plus a proposed
   **cursor** for the next scan of that scope. The API validates the engine credential, applies
   suppressions, and persists findings. Task outcome is judged from the **merged** totals, not the
   last body, so a unit that failed in the first batch still fails the task (ADR 0013 §3).
7. Every task also reports **coverage**: each enumerated object classified exactly once as scanned,
   skipped or failed, plus scope gaps for work whose cardinality could not be established. Gap
   references are HMACs under the scan's pepper, so the same blind spot correlates across manifests
   without exporting a page id, filename or path. That is what makes "what did this scan actually
   read?" a question with an answer.
8. Dead engines are handled by lease expiry → API reclaim; Dramatiq retries are disabled so that
   this is the **single** re-delivery path (ADR 0009 §2). A reclaimed task resumes from its stored
   checkpoint when the configuration it was taken under still holds.
9. When the **last task completes** (atomic DB count), and only if the scan reached `completed`
   **and** ran in full mode, the API runs **reconciliation** (see §6) and commits the proposed
   cursors, then fires notifications for newly opened findings. `partial`/`failed` scans never
   auto-resolve, and neither does an incremental scan — it deliberately did not look at unchanged
   content, so a finding it did not see is not evidence of anything (ADR 0013 §4). Notifications
   are outside that gate: finding new secrets sooner is the point of an incremental scan.

## 5. Technology decisions (summary)

| Area | Decision | ADR |
|------|----------|-----|
| Runtime | Python 3.14, containers | — |
| API | FastAPI, API-first | — |
| ORM/DB | SQLModel + PostgreSQL | — |
| Web UI | HTMX + Alpine.js | — |
| Queue | Redis + Dramatiq | [0001](./docs/adr/0001-job-queue.md) |
| Engine boundary | Separate workers, API-mediated results, no DB creds | [0002](./docs/adr/0002-engine-boundary.md) |
| Detection | Custom regex + entropy + proximity | [0003](./docs/adr/0003-detection-engine.md) |
| Finding storage | Redacted snippet + salted hash, no plaintext | [0004](./docs/adr/0004-secret-redaction.md) |
| Auth | OIDC/SSO + RBAC | [0005](./docs/adr/0005-auth.md) |
| Fingerprinting | source+location+rule+secret-hash | [0006](./docs/adr/0006-fingerprinting.md) |
| Secret store | Pluggable; env-key default, Vault later | [0007](./docs/adr/0007-secret-store.md) |
| Rule mgmt | Code rules + DB suppressions | [0008](./docs/adr/0008-rule-management.md) |
| Task lifecycle | Two-phase scans; API-authoritative lease; broker = dumb transport | [0009](./docs/adr/0009-task-lifecycle.md) |
| Liveness validation | Opt-in, policy-gated, never persists plaintext | [0010](./docs/adr/0010-secret-liveness-validation.md) |
| Correlation | API-minted ids under a dedicated key; the value never leaves | [0011](./docs/adr/0011-credential-correlation.md) |
| Remediation | Versioned guidance + structured evidence, one-way verification | [0012](./docs/adr/0012-remediation-evidence.md) |
| Incremental scanning | Durable checkpoints, per-scope cursors; never auto-resolves | [0013](./docs/adr/0013-incremental-scanning.md) |
| External hand-over | One signed POST; the receiver's reply is recorded, not applied | [0014](./docs/adr/0014-external-handover.md) |
| Tenancy | Single-org | — |
| Deployment | compose (dev) + Helm (prod) | — |

## 6. Finding identity & re-scan reconciliation

A finding's **fingerprint** is a stable identity:

```
fingerprint = hash(connector_type, resource_locator, rule_id, salted_secret_hash)
```

On scan completion, incoming fingerprints are diffed against the source's current open set:

- **New** fingerprint → create `Finding` in state `open`.
- **Matching** fingerprint → keep its existing triage state, bump `last_seen_scan`.
- **Missing** (previously open, not seen now) → transition to `resolved (auto)`.
- **Suppressed** fingerprint → recorded but not surfaced as active.

Because triage state is keyed on the fingerprint, analyst decisions (false-positive,
accepted-risk) persist across scans. A resolved secret that reappears re-opens automatically.

## 7. Deployment topology

- **Dev:** `docker-compose` brings up api, engine, postgres, redis on one host. Scale engines by
  replica count.
- **Prod:** a **Helm chart** — API `Deployment`, engine `Deployment` with an `HPA`, plus
  Postgres and Redis (managed services or operators). Engine autoscaling is safe precisely
  because engines are stateless workers with no DB coupling.

See [`docs/deployment.md`](./docs/deployment.md).

## 8. Security model

The findings database is itself a high-value target (it maps where secrets live). The threat
model, its nine trust boundaries, and the mitigations are documented in
[`docs/security.md`](./docs/security.md). Key properties: no plaintext at rest, engines
credential-isolated from the DB, encrypted connector credentials, full audit trail on finding state
changes, and RBAC on every API route.

Three features deliberately send traffic **out** of the deployment — the source connectivity test,
webhook notification channels, and hand-over targets — and one accepts traffic **in** from neither
a browser nor an engine: the signed, sessionless `POST /handoff/callback`. All four are covered
there; adding a fifth means revisiting that document, which is the rule the out-of-scope list
carries.

## 9. Roadmap (see GitHub milestones)

- **M0 — Foundations:** repo scaffold, core package, containers, CI.
- **M1 — Control plane MVP:** auth, sources/schedules, scan orchestration, findings/triage.
- **M2 — Detection + Confluence:** detection engine, connector framework, Confluence connector,
  engine worker.
- **M3 — Web UI:** HTMX/Alpine screens, served by the API at the application root and driving the
  same route handlers the JSON API exposes ([`docs/web.md`](./docs/web.md)).
- **M4 — Notifications & prod deploy:** notification dispatch, Helm, hardening.
- **M5 — Source coverage and scan assurance:** the connector SDK and conformance kit, coverage
  manifests, the Jira connector, incremental and resumable scanning, and the SMB/NFS file-share
  connector over a read-only mount.
- **M6 — Remediation and exposure closure:** exposure clusters, rotation guidance and remediation
  evidence, ownership with response targets and overdue escalation, and external hand-over.

M0–M6 are shipped; [`docs/backlog.md`](./docs/backlog.md) is the live list of what is left.

Non-goals for MVP: image OCR and multi-tenancy. SMB connectors, incremental/delta scanning and
external ticket hand-over were on this list and shipped in M5/M6 — which is why the roadmap above
names them.
