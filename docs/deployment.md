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
engine     →  Dramatiq worker         (depends on redis, api; profile `engine`)
postgres   →  system of record
redis      →  Dramatiq broker
```
- Scale engines with `--scale engine=N` (`make scale N=3`). The engine service publishes no host
  port and has no `container_name`, because either would make scaling fail.
- Secrets via `.env` (env-key secret-store backend). `make init-env` generates them — including a
  fingerprint pepper sealed with the master key it just generated.
- A `Makefile` wraps the common tasks:

| Target | What it does |
|---|---|
| `make up` | build, start, wait for every healthcheck, then migrate |
| `make down` / `make destroy` | stop; `destroy` also deletes the Postgres volume |
| `make migrate` | `alembic upgrade head` in the api container |
| `make seed` | development fixtures (refuses to run with `ICEBERG_ENVIRONMENT=prod`) |
| `make scale N=3` | run N engine replicas |
| `make check` | lint + types + tests, the same as CI |

Postgres publishes no host port by default, and Redis requires a password even in dev — the broker
is a shared trust surface (`docs/security.md`).

### Bringing up an engine

```bash
make init-env                      # .env, with generated secrets
make up                            # postgres, redis, api — and migrate
./deploy/compose/engine-token.sh   # mint a token, record it, start the engine
```

The third line is a step of its own because of an ordering nothing in the stack can resolve for
itself. An engine **refuses to start without a token** — a worker that boots without credentials
consumes messages it cannot process, and failing at boot is the honest version of that. Only the
api can mint one (`mint-engine-token` stores the hash, never the token), and only against a schema
that does not exist until `make up` has migrated. A value invented in `.env` beforehand would
authenticate with something the API never issued, which is why `make init-env` deliberately leaves
it blank.

So the engine service sits behind a compose **profile**. Until a token exists it is simply not part
of the stack, and `make up` succeeds rather than waiting on a container that cannot start.
`engine-token.sh` writes `ICEBERG_ENGINE_ID`, `ICEBERG_ENGINE_TOKEN` and `COMPOSE_PROFILES=engine`
into `.env`, so every later `make up`, `make ps` and `make logs` includes engines. `make scale N=3`
names the service explicitly and works either way.

Re-running the script rotates the token; the previous one stops working immediately. Pass a name
(`./deploy/compose/engine-token.sh engine-2`) to register a second engine.

## Production — Helm

`deploy/helm/icebergsst/`. What it renders:

| Object | Notes |
|---|---|
| api `Deployment` + `Service` + `Ingress` | The only role with a Service — engines are consumers, nothing calls them. |
| engine `Deployment` + **HPA** | Autoscaling is on by default and safe: engines hold leases, not state, and a lapsed lease is reclaimed by the api (ADR 0009). |
| migration `Job` | `pre-install,pre-upgrade` hook (weight `-5`), api image, `python -m iceberg_api migrate`. |
| `ConfigMap` | Everything non-secret. Also a hook at weight `-10` — see below. |
| **Two** `Secret`s | See below. The api's is a hook at weight `-10`; the engine's is not. |
| Two `ServiceAccount`s | One per role, neither with a mounted token. |
| `NetworkPolicy` pair | Off by default; needs a policy-enforcing CNI. |

**Postgres and Redis are not in the chart.** A bundled database is a development convenience that
becomes a production liability — no backups, no failover, and a `helm uninstall` that takes the
findings with it. Point the chart at a managed service or an operator-provisioned instance.

### Two Secrets, not one

The api's Secret holds the database URL, the master key, the session secret and the OIDC client
secret. The engine's holds a broker URL and its own token — **no database credential and no master
key**, because there is nothing an engine could correctly do with either (ADR 0002). The engine
Deployment does not reference the api's Secret at all, so separate Kubernetes RBAC on the two
ServiceAccounts expresses the same boundary the code draws.

For production, create both out of band (sealed-secrets, External Secrets, a Vault injector) and
name them:

```yaml
secrets:
  existingApiSecret: icebergsst-api
  existingEngineSecret: icebergsst-engine
```

Values passed to Helm end up in the release's stored manifest, which is not where a master key
belongs. The inline `secrets.api.*` / `secrets.engine.*` values exist so a first install works;
they are not the production path.

### Installing

```bash
helm install icebergsst deploy/helm/icebergsst -f my-values.yaml

# Then mint an engine token against the database, from the api pod:
kubectl exec deploy/icebergsst-api -- python -m iceberg_api mint-engine-token --name engine-1
```

`deploy/helm/example-values.yaml` is a complete, working values file with placeholder credentials.

### Why the ConfigMap and the api Secret are hooks

Helm creates every hook resource before any ordinary manifest. The migration Job is a hook, and it
reads its database URL and the rest of its configuration through `envFrom` — so on a fresh install
the things it reads have to be hooks too, at a lower weight (`-10` against the Job's `-5`), or the
Job starts before they exist and sits in `CreateContainerConfigError` until the deadline. The same
annotation is what makes an upgrade migrate the database the *new* values name rather than the
previous release's.

Their delete policy is `before-hook-creation` and nothing else: both Deployments read them for the
life of the release, so `hook-succeeded` would delete them the moment the migration finished. The
engine's Secret is not a hook — nothing reads it before its Deployment exists.

The cost is ownership. A hook resource is not part of the release manifest, so:

```bash
helm uninstall icebergsst
kubectl delete configmap/icebergsst-config secret/icebergsst-api   # left behind
```

Keeping them is usually what you want between a reinstall against the same database — the master
key in that Secret is the only thing that can open your stored credential refs — but it is a
deliberate deletion, not something `helm uninstall` does for you.

### Two settings that are wrong by default for your cluster

- **`config.rateLimit.trustedProxyHops`** must match the number of proxies in front of the api.
  With an ingress controller and the default of 1 it is right; at 0, every request is charged to
  the controller's address and the auth rate limit protects nothing (`docs/security.md` § Rate
  limiting).
- **`config.oidc.redirectUrl`** defaults to the ingress host when an Ingress is enabled. If you
  terminate TLS somewhere else, set it explicitly — the identity provider will reject a mismatch.

### Verifying a change to the chart

```bash
make helm-verify
```

Lints, renders with the example values, and then asserts things about the **rendered manifests**
that `helm lint` cannot see: the engine carries no database configuration and mounts only its own
Secret, migrations are a pre-upgrade hook running the api image, everything that hook reads is
itself a hook at a lower weight (and none of it is deleted when the hook finishes), every workload
is non-root, unprivileged, read-only-rootfs and has resource requests, the engine has an HPA and no
Service.
CI runs it on every PR. The cheap half — reading the templates — runs in the ordinary test suite
(`tests/test_deploy_invariants.py`).

## Migrations
Alembic, configured at `apps/api/src/iceberg_api/alembic.ini` — inside the package, so it ships in
the wheel with the revisions it points at and the api image can find it without a source tree.
Only the **api** role runs migrations (it owns the schema); engines never touch the DB.

`python -m iceberg_api migrate` is the entry point everywhere: `make migrate` in the compose
stack, the pre-upgrade `Job` in Helm, and `uv run python -m iceberg_api migrate` locally. All of
them read `ICEBERG_DATABASE_URL`.

Two CI legs cover them. `apps/api/tests/test_migrations.py` runs in the ordinary suite on SQLite
and is the drift check: every table in the metadata exists, no column has wandered, the downgrade
is complete. The `migrations` job runs the same revisions against a **Postgres** service container
— upgrade to head, `alembic downgrade base`, upgrade again — because SQLite says nothing about
JSONB, `postgresql_where` partial indexes, or an `ALTER` that SQLite only survives by copying the
table. A revision that is valid in one dialect and not the other fails there rather than in the
pre-upgrade `Job`.

## Draining an engine

A rolling deploy, `make down`, or a `kubectl delete pod` sends SIGTERM to an engine that may be
halfway through a fetch. What it does then is a policy, and the policy is: **wait, then hand the
work back to the lease** (#192).

1. Dramatiq stops handing messages to worker threads. A thread that finishes its task exits rather
   than taking another, and messages already pulled into the local queue go back to Redis.
2. The process waits up to `ICEBERG_DRAIN_SECONDS` (default 90) for the tasks it *already holds*.
   Most finish inside it.
3. Anything still running when the budget expires is abandoned. The API reclaims it when its 300s
   lease lapses and hands it to another engine, which — for Confluence, Jira and file shares —
   resumes from the last checkpoint the old engine flushed rather than re-reading the scope.
   The engine logs `engine_drain_incomplete` naming those tasks first.
4. The heartbeat stops, the API connection pool closes, the metrics server stops, and the process
   logs `engine_stopped`.

Step 4 is why the budget matters: it has to leave **room inside the termination grace period**
(`stop_grace_period` in compose, `terminationGracePeriodSeconds` in the chart — both 120s), or
SIGKILL lands mid-wait and none of it runs. A test holds the default at least 20 seconds below
both — a margin rather than a bare "less than", because Dramatiq spends the budget on the worker
threads and then joins its consumers under a second budget of the same size. A consumer exits
within its poll interval, so that second join costs seconds; "in practice" is not a bound, so the
margin is.

An abandoned task is not failed. An engine may only report a task `completed` or `failed`, and a
failed task is terminal — never reclaimed, and it makes its scan `partial`, which may not
auto-resolve findings (ADR 0009 §4). Interrupting in-flight work to report it would trade one
lease TTL of latency for a scan that cannot close a secret somebody has already fixed, on every
deploy that lands mid-scan. Waiting costs latency instead, and keeps lease expiry the single
re-delivery authority (ADR 0009 §2).

Raise `ICEBERG_DRAIN_SECONDS` **and** both grace periods together if your fetches routinely run
longer than the budget; raising one without the other only moves where the work is lost.

## Scaling model
- Throughput scales by adding **engine** replicas — more Dramatiq consumers pulling scan tasks
  from Redis.
- The **api** scales independently for UI/API load. The cron **scheduler must fire once per
  beat regardless of replica count** — a Postgres advisory lock (leader election) guards each
  tick so multiple api replicas never double-fire schedules. Implemented in
  `iceberg_api.scheduler`: `pg_try_advisory_xact_lock` for the duration of the tick's transaction,
  so the lock is released even if the replica dies mid-round, and a replica that loses the race
  returns immediately instead of queuing a redundant tick. Note that on SQLite (tests, local runs)
  there is nothing to serialise and the tick always reports leadership, so the lock itself is only
  exercised against Postgres.
- Redis runs with **auth** (`requirepass` in compose, credentials in the broker URL under Helm);
  engines reach only Redis and the api (no DB route). **Transport security to the broker is the
  operator's**: nothing here provisions or terminates TLS. The URL is passed through to the client
  unchanged, so a broker that terminates TLS is addressed by setting `secrets.api.redisUrl` and
  `secrets.engine.redisUrl` to `rediss://…`; a service mesh or a managed Redis is the other way.
  The compose stack is plaintext on a private bridge network and is not a production posture.
- Redis and Postgres sized to the org's content volume.
