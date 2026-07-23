# ADR 0002 — Engine trust boundary: API-mediated results

**Status:** Accepted

## Context
Engines run detection against potentially sensitive content and must report findings. Where
should the engine's trust boundary sit — can it write directly to Postgres, or only through the
API?

## Decision
Engines are **API-mediated**. They consume jobs from Redis and submit results to a dedicated,
authenticated engine-facing REST endpoint. Engines hold **no database credentials** and never
open a DB connection.

Engine authentication uses a per-engine bearer token (registered via `/engines`), with mTLS as a
future hardening option. The results-ingest endpoint is the *only* path by which findings enter
the system.

## Consequences
- A compromised or malicious engine cannot read the findings DB or other sources' stored
  credentials — its blast radius is limited to the content of the task it was given.
- The API owns all validation, suppression application, and persistence — a single choke point
  for correctness and audit.
- Costs a lease/heartbeat + results endpoint and slightly more API surface than letting workers
  write directly. Accepted deliberately: this is a tool whose database maps where secrets live,
  so isolation is worth the surface.
