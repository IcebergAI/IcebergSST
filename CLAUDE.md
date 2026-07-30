# CLAUDE.md

Guidance for AI assistants (and humans) working in this repository.

## What this is

IcebergSST — a secret-scanning platform for non-git enterprise sources (Confluence, Jira, file
shares). See [`ARCHITECTURE.md`](./ARCHITECTURE.md) for the design spec and [`docs/adr/`](./docs/adr/)
for decision rationale.

**Where the code is:** M0–M2 are built. `packages/core` (config, DB session, secret store,
redaction, fingerprinting, the SQLModel schema), `packages/detect` (rule packs, the detection
engine), `packages/connectors` (Confluence, extraction, the sandbox), `apps/api` (auth, sources,
scans, findings, engine-facing routes, scheduler/maintenance), `apps/engine` (the Dramatiq
worker), Alembic, and the docker-compose stack all exist and are tested. The HTMX/Alpine web UI
(M3) and notifications/Helm (M4) are still to come — `docs/backlog.md` tracks those.

## Non-negotiable invariants

These come from confirmed design decisions. Do not violate them without an explicit decision to
change the corresponding ADR:

1. **API is the only writer of record.** `apps/engine` must never hold database credentials or
   import DB session code. Engines talk to Redis (jobs in) and the API (results out) only.
2. **Never persist plaintext secrets.** Redaction happens inside the engine before results leave
   it. Only a masked snippet + salted hash are stored. If you find code that would store a raw
   secret, it is a bug.
3. **Detection logic in code, tuning in data.** Rules live in versioned rule packs
   (`packages/detect`). Suppressions/allowlists live in the DB and are analyst-editable.
4. **API-first.** The FastAPI OpenAPI schema is the contract; the HTMX/Alpine UI is just another
   client of the same routes.
5. **Single-org.** No `tenant_id`, no row-level tenancy.

## Stack

Python 3.14 · FastAPI · SQLModel/PostgreSQL · Redis + Dramatiq · HTMX + Alpine.js ·
docker-compose (dev) / Helm (prod).

## Planned layout

`apps/api`, `apps/engine`, `packages/core`, `packages/detect`, `packages/connectors`, `web/`,
`deploy/`, `docs/`.

## Invariants that are already tests

Prefer extending these over adding prose:

- `apps/engine/tests/test_no_db_access.py` — imports the engine in a subprocess and fails if
  `iceberg_core.db`, `iceberg_core.models`, or SQLAlchemy appears in its module graph.
- `packages/core/tests/test_no_raw_env_reads.py` — `iceberg_core.config` is the only module allowed
  to read the environment.
- `tests/test_deploy_invariants.py` — the engine image and compose service carry no database
  configuration, no master key, and stay scalable; `.env.example` documents every variable compose
  interpolates.
- `apps/api/tests/test_migrations.py` — migrations apply, match the metadata, and reverse.

## Working style

- Keep the engine boundary clean; when in doubt, route through the API.
- Match existing patterns. Add tests with each unit.
- Reference the relevant ADR in commit messages when a change touches a decided area.
- `make check` is what CI runs; run it before pushing.
