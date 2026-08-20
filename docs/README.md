# IcebergSST documentation

Design specification and reference docs. Start with [`../ARCHITECTURE.md`](../ARCHITECTURE.md).

## Reference
- [`data-model.md`](./data-model.md) — SQLModel entities and relationships
- [`api.md`](./api.md) — REST surface (human + engine-facing)
- [`web.md`](./web.md) — the console: HTMX/Alpine conventions, CSP, assets, design system
- [`connectors.md`](./connectors.md) — connector interface + Confluence, Jira, and file shares
- [`connector-sdk.md`](./connector-sdk.md) — versioned connector contract and conformance kit
- [`rules.md`](./rules.md) — detection engine, rule packs, suppressions
- [`secret-validation.md`](./secret-validation.md) — opt-in credential liveness contracts and controls
- [`security.md`](./security.md) — threat model and mitigations
- [`notifications.md`](./notifications.md) — channels, the delivery outbox, escalation, payloads
- [`handoff.md`](./handoff.md) — handing a finding to an external workflow, once
- [`retention.md`](./retention.md) — what is pruned, when, and what is kept forever
- [`deployment.md`](./deployment.md) — docker-compose (dev) + Helm (prod)
- [`releases.md`](./releases.md) — versioning, support window, compatibility, upgrade and rollback
- [`runbooks/production-install.md`](./runbooks/production-install.md) — production-oriented
  installation and go-live checks
- [`runbooks/backup-restore.md`](./runbooks/backup-restore.md) — isolated recovery rehearsal
- [`runbooks/key-rotation.md`](./runbooks/key-rotation.md) — rotating the master key and the
  fingerprint pepper without losing triage history
- [`runbooks/controlled-pilot.md`](./runbooks/controlled-pilot.md) — running a first scan against
  a real source, with the blast radius bounded
- [`runbooks/release.md`](./runbooks/release.md) — cutting a release, and verifying a published one
- [`backlog.md`](./backlog.md) — milestones, epics, and issues (mirrors GitHub)
- [`spikes/python-3.14-compat.md`](./spikes/python-3.14-compat.md) — why the workspace pins 3.14,
  and what had to be true first
- [`../web/README.md`](../web/README.md) — vendoring the console's frontend assets

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
- [0010 — Credential liveness validation](./adr/0010-secret-liveness-validation.md)
- [0011 — Credential correlation & exposure clusters](./adr/0011-credential-correlation.md)
- [0012 — Rotation guidance & remediation evidence](./adr/0012-remediation-evidence.md)
- [0013 — Incremental & resumable scanning](./adr/0013-incremental-scanning.md)
- [0014 — External hand-over: one signed POST, a recorded reply](./adr/0014-external-handover.md)
