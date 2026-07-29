# Deployment

Two packaged targets: **docker-compose** for development/small installs and a **Helm chart** for
production.

## Roles / images
Built from the shared monorepo — `deploy/docker/{api,engine}.Dockerfile`, both multi-stage and
both built from the repository root:

| Image | Dockerfile | Entrypoint | Port |
|-------|-----------|------------|------|
| **api** — FastAPI control plane (also serves the HTMX UI). Owns Postgres. | `deploy/docker/api.Dockerfile` | `uvicorn iceberg_api.app:create_app --factory` | 8000 |
| **engine** — Dramatiq worker (connectors + detection). Stateless; no DB credentials. | `deploy/docker/engine.Dockerfile` | `dramatiq iceberg_engine.worker:broker --processes 1` | 9191 (metrics) |

Plus **PostgreSQL** and **Redis**.

Each image installs only its own workspace member (`uv sync --package …`), which is what keeps
the api's dependency graph — and any future database driver — out of the engine image. Both run
as an unprivileged uid and carry a `HEALTHCHECK`.

The engine runs **one worker process per container**: it binds a single Prometheus endpoint, so
throughput is scaled by adding replicas (`--scale engine=N`, or the Helm HPA), not by raising
`--processes`.

`make images` builds both. `make images-verify` builds them and then asserts the properties that
matter — entrypoints serve, both run non-root, and the engine image contains no database client,
ORM, migration tool, or DB environment variables (ADR 0002). CI runs the same check on every PR.

## Development — docker-compose
`deploy/compose/docker-compose.yml` brings up:
```
api        →  FastAPI + UI            (depends on postgres, redis)
engine     →  Dramatiq worker         (depends on redis, api)
postgres   →  system of record
redis      →  Dramatiq broker
```
- Scale engines with `--scale engine=N`.
- Secrets via `.env` (env-key secret-store backend).
- A `Makefile` wraps common tasks (up, migrate, seed, test).

## Production — Helm
`deploy/helm/` chart:
- **api** `Deployment` + `Service` + `Ingress` (OIDC in front).
- **engine** `Deployment` + **HPA** — autoscaling is safe because engines are stateless workers
  with no DB coupling.
- **Postgres** and **Redis** as managed services or operator-provisioned; connection details and
  the master encryption key injected via Kubernetes `Secret`s.
- Migrations run as a pre-upgrade `Job`.
- Values expose: image tags, replica counts/HPA bounds, OIDC config, DB/Redis endpoints,
  secret-store backend selection (env-key vs Vault).

## Migrations
Alembic. Only the **api** role runs migrations (it owns the schema); engines never touch the DB.

## Scaling model
- Throughput scales by adding **engine** replicas — more Dramatiq consumers pulling scan tasks
  from Redis.
- The **api** scales independently for UI/API load. The cron **scheduler must fire once per
  beat regardless of replica count** — a Postgres advisory lock (leader election) guards each
  tick so multiple api replicas never double-fire schedules.
- Redis runs with auth + TLS; engines reach only Redis and the api (no DB route).
- Redis and Postgres sized to the org's content volume.
