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
- **Epic: HTMX + Alpine shell** — layout, auth-gated nav, base templates.
- **Epic: Screens** — sources list/form, scan launch + live status, findings table + filters +
  detail/triage, suppressions, schedules, engine health dashboard, notification channels,
  user & role management.

## M4 — Notifications & prod deploy
- **Epic: Notifications** — channel model, email/SMTP + webhook dispatch, new-finding events.
- **Epic: Helm chart** — api Deploy, engine Deploy + HPA, pg/redis, secrets, ingress, values.
- **Epic: Hardening** — security review, rate limiting, audit logging, data-retention policy,
  key + pepper rotation runbook, docs polish.

## MVP non-goals
Jira/SMB connectors, incremental/delta scanning, image OCR, external ticket creation,
multi-tenancy.
