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

## Credential & pepper delivery
Engines need the source credential to fetch content and the fingerprint pepper to hash matches
(redaction/hashing happens engine-side, ADR 0004). Both are delivered **in the lease response**
(ADR 0009), scoped to the leased task's source, over mandatory TLS. They are never baked into
the engine image or configured as engine env vars.

## Consequences
- **Honest blast radius:** a compromised engine can read the content it is given, the
  credential of any source whose tasks it leases, and the shared fingerprint pepper. It cannot
  read the findings DB, stored credentials at rest, or results submitted by other engines. This
  is narrower than direct-DB workers, but not zero — see `docs/security.md`.
- **Redis is a shared trust surface:** engines can read and enqueue broker messages. Mitigated
  by keeping message payloads to task-id hints (no secrets, no specs) and validating everything
  at lease time; Redis requires auth + TLS (see `docs/security.md`).
- The API owns all validation, suppression application, and persistence — a single choke point
  for correctness and audit.
- Costs a lease/heartbeat + results endpoint and slightly more API surface than letting workers
  write directly. Accepted deliberately: this is a tool whose database maps where secrets live,
  so isolation is worth the surface.
