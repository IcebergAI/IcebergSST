# Deployment

Two packaged targets: **docker-compose** for development/small installs and a **Helm chart** for
production.

## Roles / images
Built from the shared monorepo:
- **api** — FastAPI control plane (also serves the HTMX UI). Owns Postgres.
- **engine** — Dramatiq worker (connectors + detection). Stateless; no DB credentials.

Plus **PostgreSQL** and **Redis**.

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
Alembic, configured at `apps/api/alembic.ini`. Only the **api** role runs migrations (it owns the
schema); engines never touch the DB. In the compose stack: `make migrate`. Directly:
`uv run alembic -c apps/api/alembic.ini upgrade head`, which reads `ICEBERG_DATABASE_URL`.

## Scaling model
- Throughput scales by adding **engine** replicas — more Dramatiq consumers pulling scan tasks
  from Redis.
- The **api** scales independently for UI/API load. The cron **scheduler must fire once per
  beat regardless of replica count** — a Postgres advisory lock (leader election) guards each
  tick so multiple api replicas never double-fire schedules.
- Redis runs with auth + TLS; engines reach only Redis and the api (no DB route).
- Redis and Postgres sized to the org's content volume.
