#!/usr/bin/env bash
#
# Acceptance checks for the role images (issue #20): both images run their
# entrypoints, and the engine image carries no database configuration.
#
# The last of those is the ADR 0002 invariant. It is checked here rather than
# left to review because "engine has no DB access" is the kind of property that
# decays quietly — a transitive dependency is all it takes.
#
# Assumes the images already exist; `make images-verify` builds them first.
set -euo pipefail

API_IMAGE="${API_IMAGE:-icebergsst/api:local}"
ENGINE_IMAGE="${ENGINE_IMAGE:-icebergsst/engine:local}"
API_PORT="${API_PORT:-18000}"
ENGINE_METRICS_PORT="${ENGINE_METRICS_PORT:-19191}"

containers=()

cleanup() {
    if [ ${#containers[@]} -gt 0 ]; then
        docker rm -f "${containers[@]}" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

pass() {
    echo "  ok — $*"
}

wait_for_http() {
    local url=$1
    for _ in $(seq 1 60); do
        if curl -fsS "$url" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.5
    done
    return 1
}

assert_runs_as_non_root() {
    local image=$1 role=$2 uid
    uid=$(docker run --rm --entrypoint id "$image" -u)
    [ "$uid" != "0" ] || fail "$role image runs as root"
    pass "$role runs as uid $uid, not root"
}

echo "== api image ($API_IMAGE) =="
api_cid=$(docker run -d -p "${API_PORT}:8000" "$API_IMAGE")
containers+=("$api_cid")

if ! wait_for_http "http://127.0.0.1:${API_PORT}/healthz"; then
    docker logs "$api_cid" >&2 || true
    fail "api entrypoint never served /healthz"
fi
pass "entrypoint serves /healthz"

curl -fsS "http://127.0.0.1:${API_PORT}/healthz" | grep -q '"status":"ok"' \
    || fail "unexpected /healthz body"
pass "/healthz reports ok"

curl -fsS "http://127.0.0.1:${API_PORT}/metrics" | grep -q 'iceberg_findings_ingested_total' \
    || fail "/metrics is missing the iceberg_* series"
pass "/metrics exposes the iceberg_* series"

assert_runs_as_non_root "$API_IMAGE" api

echo "== engine image ($ENGINE_IMAGE) =="
engine_cid=$(docker run -d -p "${ENGINE_METRICS_PORT}:9191" "$ENGINE_IMAGE")
containers+=("$engine_cid")

if ! wait_for_http "http://127.0.0.1:${ENGINE_METRICS_PORT}/metrics"; then
    docker logs "$engine_cid" >&2 || true
    fail "engine entrypoint never served its metrics port"
fi
pass "entrypoint boots a worker and serves /metrics"

# Proves the worker-boot hook fired, which is what makes the engine observable
# at all — the metrics server and JSON logging both hang off it.
if ! docker logs "$engine_cid" 2>&1 | grep -q '"event": "engine_worker_ready"'; then
    docker logs "$engine_cid" >&2 || true
    fail "engine did not log engine_worker_ready"
fi
pass "worker-boot observability hook fired"

assert_runs_as_non_root "$ENGINE_IMAGE" engine

echo "== engine database-isolation invariant (ADR 0002) =="
docker run --rm -i --entrypoint python "$ENGINE_IMAGE" - <<'PY' || fail "engine image contains database packages"
import importlib.util
import sys

FORBIDDEN = ["sqlalchemy", "sqlmodel", "psycopg", "psycopg2", "asyncpg", "pg8000", "alembic"]
present = [name for name in FORBIDDEN if importlib.util.find_spec(name) is not None]
if present:
    print(f"database packages installed in the engine image: {present}", file=sys.stderr)
    sys.exit(1)
PY
pass "no database client, ORM, or migration tool installed"

db_env=$(docker image inspect "$ENGINE_IMAGE" --format '{{range .Config.Env}}{{println .}}{{end}}' \
    | grep -Ei '^(DATABASE_|POSTGRES_|PG[A-Z]+=|SQLALCHEMY_)' || true)
[ -z "$db_env" ] || fail "engine image bakes in database environment variables: $db_env"
pass "no database environment variables baked into the image"

echo
echo "All image acceptance checks passed."
