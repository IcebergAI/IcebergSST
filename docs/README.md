# IcebergSST documentation

Design specification and reference docs. Start with [`../ARCHITECTURE.md`](../ARCHITECTURE.md).

## Reference
- [`data-model.md`](./data-model.md) — SQLModel entities and relationships
- [`api.md`](./api.md) — REST surface (human + engine-facing)
- [`web.md`](./web.md) — the console: HTMX/Alpine conventions, CSP, assets, design system
- [`connectors.md`](./connectors.md) — connector interface + Confluence (MVP)
- [`rules.md`](./rules.md) — detection engine, rule packs, suppressions
- [`security.md`](./security.md) — threat model and mitigations
- [`deployment.md`](./deployment.md) — docker-compose (dev) + Helm (prod)
- [`backlog.md`](./backlog.md) — milestones, epics, and issues (mirrors GitHub)

## Decision records (ADRs)
- [0001 — Job queue: Redis + Dramatiq](./adr/0001-job-queue.md)
- [0002 — Engine boundary: API-mediated results](./adr/0002-engine-boundary.md)
- [0003 — Detection engine: custom regex + entropy + proximity](./adr/0003-detection-engine.md)
- [0004 — Finding storage: redacted snippet + salted hash](./adr/0004-secret-redaction.md)
- [0005 — Auth: OIDC/SSO + RBAC](./adr/0005-auth.md)
- [0006 — Fingerprint & reconciliation](./adr/0006-fingerprinting.md)
- [0007 — Secret store: pluggable, env-key default](./adr/0007-secret-store.md)
- [0008 — Rule management: code rules + DB suppressions](./adr/0008-rule-management.md)
- [0009 — Task lifecycle: two-phase scans, API-authoritative leases](./adr/0009-task-lifecycle.md)
