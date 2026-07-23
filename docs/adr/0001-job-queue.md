# ADR 0001 — Job queue: Redis + Dramatiq

**Status:** Accepted

## Context
Scanner engines are separate from the management layer and must receive scan work and report
results back. Options considered: a message broker (Redis/RabbitMQ/NATS), engines polling a REST
API, the API pushing to engines, or a Postgres-backed queue reusing the existing DB.

A Postgres-backed queue was initially attractive (one fewer service) but conflicts with the
requirement that engines be isolated from the management data store — it would force engines to
hold DB credentials.

## Decision
Use **Redis as the broker with Dramatiq** as the task framework. The API enqueues `ScanTask`
jobs; engines are Dramatiq workers that consume them. Redis is also available for caching and
rate-limit state.

## Consequences
- Engines never need Postgres access — jobs arrive via Redis, results go out via the API (see
  ADR 0002). Clean isolation.
- Dramatiq gives native retries, dead-lettering, and a simpler async story than Celery, with
  less operational weight than RabbitMQ.
- Adds Redis as an operational dependency (already desirable for other uses).
- Higher throughput ceiling and better future-proofing than a Postgres queue.
