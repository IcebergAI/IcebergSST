# ADR 0009 — Task lifecycle: two-phase scans, API-authoritative leases

**Status:** Accepted

## Context
Design review surfaced two coordination holes:

1. **Discovery paradox.** The API fans a scan out into `ScanTask`s (e.g. one per Confluence
   space), but enumerating spaces is connector work requiring connector code + the source
   credential — and connectors run only inside engines (ADR 0002). As originally written, the
   API could not perform fan-out without violating its own boundary.
2. **Competing coordination layers.** Dramatiq's ack/retry and the API's lease/heartbeat were
   both in the design with no defined authority: it was unclear who re-delivers work when an
   engine dies, and API-side reclaim would collide with broker-side retry.

## Decision

### 1. Two-phase scans
A scan begins with a single **discovery task**. An engine leases it, runs
`connector.discover()`, and POSTs the resulting `TaskSpec`s back to the API. The API persists
them as **fetch tasks** and enqueues them. Connectors never run in the control plane.

### 2. The API lease is authoritative; the broker is dumb transport
- The Dramatiq message carries **only the task id** — a delivery hint, never secrets or specs.
- An engine must successfully `POST /scan-tasks/{id}/lease` before doing any work. The lease
  response delivers the task spec, the source credential (scoped to that task's source), the
  fingerprint pepper, and applicable suppressions.
- A failed lease (task already leased/completed/cancelled) → the engine drops the message
  silently.
- **Dramatiq retries are disabled.** Heartbeats extend the lease; on lease expiry the API marks
  the task `queued` again and enqueues a fresh message (reclaim). There is exactly one
  re-delivery mechanism.
- `POST /scan-tasks/{id}/results` carries an **idempotency key** (task id + attempt) so engine
  retries after API errors cannot duplicate findings.

### 3. Completion detection & concurrency
- Task completion is counted **atomically in Postgres**; the transition that completes the last
  task triggers reconciliation exactly once (no race between simultaneously finishing tasks).
- **One active scan per source**, enforced by a partial unique index. Concurrent scans of the
  same source cannot race reconciliation.

### 4. Reconciliation guard
Reconciliation (ADR 0006) runs **only for scans that reach `completed`**. A `partial` or
`failed` scan never auto-resolves findings — otherwise a single failed space would silently
mass-resolve every finding in the unscanned remainder.

## Consequences
- The API is the single source of truth for task state; broker compromise or loss degrades to
  re-delivery noise, not incorrect state.
- Queue poisoning by a compromised engine is limited to enqueuing task-id noise — the lease
  validates everything before work or credentials are released.
- Discovery adds one round-trip per scan; acceptable.
- Credential + pepper transit the engine↔API channel at lease time — TLS is mandatory; see
  ADR 0002 and `docs/security.md` for the honest blast-radius statement.
