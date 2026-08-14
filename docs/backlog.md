# Work breakdown

This mirrors the GitHub milestones/epics/issues. MVP path is **M0 → M2** (a demoable
Confluence-scan-to-triaged-finding flow). M3–M4 complete the product.

**Labels:** `area:api`, `area:engine`, `area:web`, `area:detect`, `area:connector`,
`area:infra`, `area:security`, `type:epic`, `type:feature`, `type:chore`, `type:docs`.

## M0 — Foundations
- **Epic: Repo scaffold & tooling** — uv/PDM workspace, ruff, mypy, pytest, pre-commit, CI
  (incl. secret-scanning CI on this repo), **Python 3.14 compat spike** (3.13 fallback policy),
  observability baseline (structured logging + Prometheus metrics).
- **Epic: Containers & local stack** — docker-compose (api/engine/postgres/redis), Makefile.
- **Epic: Core package** — SQLModel base + config, secret-store interface + EnvKey backend,
  redaction + fingerprinting utilities, Alembic bootstrap.

## M1 — Control plane MVP
- **Epic: Auth** — OIDC login/callback/session, RBAC dependency, roles, CSRF protection,
  bootstrap admin (env-configured subject), user & role management API.
- **Epic: Sources & schedules** — CRUD, credential storage via secret store, cron scheduler →
  enqueue (advisory-lock leader election).
- **Epic: Scan orchestration** — two-phase scans + API-authoritative lease (ADR 0009),
  Scan/ScanTask models, engine register/lease/heartbeat + reclaim, idempotent results ingest,
  reconciliation (completed-only guard, atomic completion, one active scan per source),
  scans read API + cancellation semantics.
- **Epic: Findings & triage** — list/filter, state machine, FindingEvent audit, suppressions.

## M2 — Detection engine + Confluence connector
- **Epic: Detection engine** — rulepack loader, regex+entropy+proximity, confidence scoring +
  threshold config, allowlist application (suppressions delivered via lease), seed rule pack +
  tests/benchmarks, `GET /rules` metadata endpoint.
- **Epic: Connector framework** — connector interface (discover → fetch → content units),
  text-extraction step with untrusted-content guards (size caps, timeouts, bomb limits).
- **Epic: Confluence connector** — **Cloud first, DC-ready interface**; auth, space/page
  discovery + pagination, comments, text-attachment extraction, test-fixture strategy
  (in-process mock Confluence for CI — see `docs/connectors.md` for why not recorded
  fixtures). Lives in `packages/connectors/src/iceberg_connectors/confluence/`.
- **Epic: Engine worker app** — Dramatiq consumer running lease → connector → detect → redact →
  report (ADR 0009 semantics).

## M3 — Web UI
- **Epic: HTMX + Alpine shell** — layout, auth-gated nav, base templates. Server-rendered Jinja
  under a strict CSP (`script-src 'self'`), self-hosted Alpine CSP build + HTMX + fonts with SRI,
  the shared Iceberg design system. See [`docs/web.md`](./web.md).
- **Epic: Screens** — sources list/form, scan launch + live status, findings table + filters +
  detail/triage, suppressions, schedules, engine health dashboard, notification channels,
  user & role management. Every screen calls the corresponding API route handler; the boundary is
  asserted by `apps/api/tests/test_web_invariants.py`.
- Notification-channel **CRUD** landed here rather than in M4, because the M3 screen needs routes
  to drive. Dispatch remains M4.

## M4 — Notifications & prod deploy *(shipped)*
- **Epic: Notifications** — email/SMTP + webhook **dispatch**, new-finding events. The channel model
  and its CRUD API shipped with M3. Dispatch is a transactional outbox
  (`notification_delivery`): reconciliation queues, the maintenance loop delivers and retries.
  See [`notifications.md`](./notifications.md).
- **Epic: Helm chart** — api Deploy + Service + Ingress, engine Deploy + HPA, a migration hook Job,
  two Secrets, a NetworkPolicy pair. Postgres and Redis are deliberately **not** in the chart; point
  it at a managed instance ([`deployment.md`](./deployment.md) § Helm chart).
- **Epic: Hardening** — security review, rate limiting, audit logging, data-retention policy,
  key + pepper rotation runbook, docs polish.

## M5 — Source coverage and scan assurance
- **Epic: Connector SDK & conformance kit (#149)** *(shipped)* — the published `Connector` protocol,
  `ConnectorMetadata`/capabilities, and `assert_connector_conformance`.
- **Epic: Scan coverage & gap manifest (#148)** *(shipped)* — every enumerated object gets exactly
  one disposition; unknown remainder is a scope gap, never an invented clean count.
- **Epic: Jira connector (#144)** — Cloud (REST v3): projects, issues, comments, attachments, and
  opt-in field history. First consumer of the #149 SDK. Discovery windows each project by the
  immutable `created` field, which bounds what an interrupted task re-reads; **not** checkpointed
  resume, which stays with #143. Data Center seams exist but are uncertified. Shares its transport
  with Confluence via `iceberg_connectors.http`, which is also where the 401-vs-403 split lives —
  Jira permissions are per-issue, so a 403 is one object rather than the site.
  See [`connectors.md`](./connectors.md) § Jira.
- **Epic: Incremental & resumable scanning (#143)** — connector cursors, durable checkpoints, and
  the `CHECKPOINTS` capability, which no connector may declare until it lands.
- **Epic: SMB/NFS file-share connector (#145)**.

## M6 — Remediation and exposure closure
- **Epic: Exposure clusters (#140)** *(shipped)* — correlate findings that contain the same secret
  value into one exposure cluster without exposing the value: API-minted correlation ids under a
  dedicated key (ADR 0011), analyst cluster list/topology/audited export plus console screens,
  key rotation by reindex (`reindex-correlation`, no rescan).
- **Epic: Rotation guidance & remediation evidence (#142)** *(shipped)* — versioned per-rule
  guidance catalog, structured remediation actions with evidence links, one-way verification and
  set-once retraction, an opt-in required-evidence policy by severity, viewer redaction, and
  evidence scrubbing under retention (ADR 0012). A reappearing credential — including one a
  validator (ADR 0010) reports live, since validation only accompanies a sighting — reopens with
  its remediation history intact.

## MVP non-goals
SMB connectors, incremental/delta scanning, image OCR, external ticket creation,
multi-tenancy.
