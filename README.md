# IcebergSST

**Iceberg Secret Scanning Tool** — a secret-scanning platform for finding passwords and other
secrets that have been inappropriately stored across enterprise systems.

Most secret-scanning tooling is git-centric. IcebergSST targets the *non-git* long tail where
credentials quietly accumulate — **Confluence**, **Jira**, and **network file shares** — with an
API-first management plane and horizontally scalable, isolated scanner engines.

> ⚠️ **Status: design phase.** This repository currently contains the design specification and
> the planned work breakdown only. No product code has been written yet. See
> [`ARCHITECTURE.md`](./ARCHITECTURE.md) and [`docs/`](./docs/) for the spec, and the GitHub
> milestones/issues for the backlog.

## What it does

- **Discover & scan** content in Confluence (MVP), with Jira and SMB/NFS file shares to follow.
- **Detect** secrets with a custom regex + entropy + keyword-proximity engine driven by
  versioned rule packs.
- **Never store plaintext** — findings keep only a redacted snippet and a salted fingerprint
  hash.
- **Triage** findings through a lifecycle (open → false-positive / accepted-risk / resolved) with
  an audit trail, suppressions/allowlists, and notifications.
- **Re-scan reconciliation** — a stable per-finding fingerprint means triage decisions persist
  across scans; resolved secrets that reappear re-open, and secrets that vanish auto-resolve.

## Architecture at a glance

| Layer | Technology |
|-------|------------|
| Control-plane API | FastAPI (API-first; OpenAPI is the contract) |
| ORM / database | SQLModel over PostgreSQL |
| Web UI | Server-rendered HTML driven by HTMX + Alpine.js |
| Job queue | Redis + Dramatiq |
| Scanner engines | Separate Dramatiq worker processes; consume jobs from Redis, **POST results back to the API** (no database credentials) |
| Auth | OIDC/SSO + RBAC (admin / analyst / viewer) |
| Runtime | Python 3.14, containers (docker-compose for dev, Helm for prod) |

See [`ARCHITECTURE.md`](./ARCHITECTURE.md) for the full picture and
[`docs/adr/`](./docs/adr/) for the rationale behind each decision.

## Repository layout (planned)

```
apps/api        FastAPI control plane
apps/engine     Dramatiq scanner worker
packages/core   shared models, config, secret-store, fingerprinting, redaction
packages/detect rule packs + detection engine
packages/connectors  connector interface + Confluence (Jira/SMB later)
web/            HTMX templates + Alpine components
deploy/         docker-compose (dev) + Helm chart (prod)
docs/           design spec, ADRs, threat model
```

## License

See [`LICENSE`](./LICENSE).
