# Work breakdown

This mirrors the GitHub milestones/epics/issues. MVP path is **M0 → M2** (a demoable
Confluence-scan-to-triaged-finding flow). M3–M4 complete the product.

**Labels:** `area:api`, `area:engine`, `area:web`, `area:detect`, `area:connector`,
`area:infra`, `area:security`, `type:epic`, `type:feature`, `type:chore`, `type:docs`.

## M0 — Foundations
- **Epic: Repo scaffold & tooling** — uv/PDM workspace, ruff, mypy, pytest, pre-commit, CI.
- **Epic: Containers & local stack** — docker-compose (api/engine/postgres/redis), Makefile.
- **Epic: Core package** — SQLModel base + config, secret-store interface + EnvKey backend,
  redaction + fingerprinting utilities, Alembic bootstrap.

## M1 — Control plane MVP
- **Epic: Auth** — OIDC login/callback/session, RBAC dependency, roles.
- **Epic: Sources & schedules** — CRUD, credential storage via secret store, cron scheduler → enqueue.
- **Epic: Scan orchestration** — Scan/ScanTask models, Dramatiq enqueue, engine register/lease/
  heartbeat, results-ingest endpoint, reconciliation logic.
- **Epic: Findings & triage** — list/filter, state machine, FindingEvent audit, suppressions.

## M2 — Detection engine + Confluence connector
- **Epic: Detection engine** — rulepack loader, regex+entropy+proximity, confidence scoring,
  allowlist application, seed rule pack + tests/benchmarks.
- **Epic: Connector framework** — connector interface (discover → fetch → content units),
  text-extraction step.
- **Epic: Confluence connector** — auth, space/page discovery + pagination, comments,
  text-attachment extraction.
- **Epic: Engine worker app** — Dramatiq consumer running connector → detect → redact → report.

## M3 — Web UI
- **Epic: HTMX + Alpine shell** — layout, auth-gated nav, base templates.
- **Epic: Screens** — sources list/form, scan launch + live status, findings table + filters +
  detail/triage, suppressions, schedules, engine health dashboard.

## M4 — Notifications & prod deploy
- **Epic: Notifications** — channel model, email/SMTP + webhook dispatch, new-finding events.
- **Epic: Helm chart** — api Deploy, engine Deploy + HPA, pg/redis, secrets, ingress, values.
- **Epic: Hardening** — security review, rate limiting, audit logging, docs polish.

## MVP non-goals
Jira/SMB connectors, incremental/delta scanning, image OCR, external ticket creation,
multi-tenancy.
