# IcebergSST — Architecture

This document is the authoritative design specification for IcebergSST. It captures the system
shape, component boundaries, and the confirmed decisions that constrain implementation. Rationale
for each decision lives as an ADR under [`docs/adr/`](./docs/adr/).

## 1. Purpose & scope

IcebergSST finds secrets (passwords, API keys, tokens, private keys) that have been
inappropriately stored in enterprise collaboration systems and file shares. It deliberately
targets sources that git-oriented scanners miss:

- **Confluence** — pages, comments, and text-extractable attachments (MVP).
- **Jira** — issues, comments, attachments (post-MVP).
- **File shares** — SMB/CIFS and NFS (post-MVP).

It is a **single-organization** internal security tool: one deployment serves one org. There is
no tenant partitioning.

## 2. High-level architecture

```
                    ┌────────────────────────────────────────┐
                    │            Management Plane             │
   Browser ──HTMX──▶│  FastAPI (API-first, OpenAPI)          │
   (Alpine+HTMX)    │   • Auth (OIDC / RBAC)                  │
                    │   • Sources / Scans / Findings / Rules  │◀── results (REST, token-auth)
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

## 4. Data flow: a scan (two-phase, ADR 0009)

1. A scan is triggered — **on-demand** (user or API) or by the **cron scheduler** (guarded by a
   Postgres advisory lock so multiple API replicas never double-fire).
2. The API creates a `Scan` row and enqueues a single **discovery task** (the broker message is
   an id-only hint — no secrets, no specs).
3. An **engine** leases the discovery task — the lease response delivers the task spec, the
   task-scoped source credential, the fingerprint pepper, and applicable suppressions — runs
   `connector.discover()`, and POSTs the resulting `TaskSpec`s back.
4. The API persists them as **fetch tasks** and enqueues each; engines lease fetch tasks, run
   connector fetch → detection → redaction, and POST findings + completion (idempotency-keyed).
5. The API validates the engine credential, applies suppressions, and persists findings. Dead
   engines are handled by lease expiry → API reclaim (Dramatiq retries are disabled).
6. When the **last task completes** (atomic DB count), and only if the scan reached
   `completed`, the API runs **reconciliation** (see §6), then fires notifications for newly
   opened findings. `partial`/`failed` scans never auto-resolve.

## 5. Technology decisions (summary)

| Area | Decision | ADR |
|------|----------|-----|
| Runtime | Python 3.14, containers (3.13 fallback if M0 compat spike finds blockers) | — |
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
model, trust boundaries, and mitigations are documented in [`docs/security.md`](./docs/security.md).
Key properties: no plaintext at rest, engines credential-isolated from the DB, encrypted
connector credentials, full audit trail on finding state changes, and RBAC on every API route.

## 9. Roadmap (see GitHub milestones)

- **M0 — Foundations:** repo scaffold, core package, containers, CI.
- **M1 — Control plane MVP:** auth, sources/schedules, scan orchestration, findings/triage.
- **M2 — Detection + Confluence:** detection engine, connector framework, Confluence connector,
  engine worker.
- **M3 — Web UI:** HTMX/Alpine screens, served by the API at the application root and driving the
  same route handlers the JSON API exposes ([`docs/web.md`](./docs/web.md)).
- **M4 — Notifications & prod deploy:** notification dispatch, Helm, hardening.

Non-goals for MVP: Jira/SMB connectors, incremental/delta scanning, image OCR, external ticket
creation, multi-tenancy.
