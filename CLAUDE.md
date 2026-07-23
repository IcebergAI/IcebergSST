# CLAUDE.md

Guidance for AI assistants (and humans) working in this repository.

## What this is

IcebergSST — a secret-scanning platform for non-git enterprise sources (Confluence, Jira, file
shares). See [`ARCHITECTURE.md`](./ARCHITECTURE.md) for the design spec and [`docs/adr/`](./docs/adr/)
for decision rationale. The project is in the **design phase**: spec + backlog only, no product
code yet.

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

## Working style

- Keep the engine boundary clean; when in doubt, route through the API.
- Match existing patterns once code exists. Add tests with each unit.
- Reference the relevant ADR in commit messages when a change touches a decided area.
