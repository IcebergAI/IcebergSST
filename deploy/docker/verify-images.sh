#!/usr/bin/env bash
#
# Build both role images and assert the properties they are supposed to have.
#
#   make images-verify          # build, then check
#   ./deploy/docker/verify-images.sh --no-build   # check images already built
#
# This exists because the alternative is reading the Dockerfiles and believing
# them. tests/test_deploy_invariants.py does read them — it catches a DATABASE_URL
# added to the engine service — but it cannot tell you that the image builds, that
# the entrypoint serves, or that sqlalchemy is genuinely absent rather than merely
# unmentioned. Those are properties of the built artefact, so they are checked
# against the built artefact (#81).
#
# The engine's database isolation (ADR 0002) is the check that matters most: an
# engine that can import an ORM is one refactor away from holding a connection,
# and the invariant is easier to keep when breaking it fails the build.

set -euo pipefail

API_IMAGE="${API_IMAGE:-icebergsst/api:verify}"
ENGINE_IMAGE="${ENGINE_IMAGE:-icebergsst/engine:verify}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

build=1
[[ "${1:-}" == "--no-build" ]] && build=0

failures=0
pass() { printf '  \033[32mok\033[0m   %s\n' "$1"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; failures=$((failures + 1)); }
group() { printf '\n\033[1m%s\033[0m\n' "$1"; }

# check <description> <expected> <actual>
check() {
  if [[ "$2" == "$3" ]]; then pass "$1"; else fail "$1 (expected '$2', got '$3')"; fi
}

if (( build )); then
  group "Building images"
  docker build -q -f "$REPO_ROOT/deploy/docker/api.Dockerfile" -t "$API_IMAGE" "$REPO_ROOT" >/dev/null
  pass "api image builds"
  docker build -q -f "$REPO_ROOT/deploy/docker/engine.Dockerfile" -t "$ENGINE_IMAGE" "$REPO_ROOT" >/dev/null
  pass "engine image builds"
fi

# ── Both roles run unprivileged ───────────────────────────────────────────────
# A container that runs as root turns any RCE in a connector or a template into
# root in the container, and root in the container is the first half of most
# escapes.
group "Non-root runtime"
check "api runs as uid 10001" "10001" "$(docker run --rm "$API_IMAGE" id -u)"
check "engine runs as uid 10001" "10001" "$(docker run --rm "$ENGINE_IMAGE" id -u)"

# ── ADR 0002: the engine cannot reach the database ────────────────────────────
group "Engine database isolation (ADR 0002)"
# Deliberately an import, not importlib.util.find_spec. iceberg_core ships db.py
# and models/ to both roles — they are the same package — so find_spec locates
# those files in the engine image and reports them present. What actually matters
# is whether they can be *used*, and they cannot: their ORM lives in the
# iceberg-core[db] extra that only apps/api depends on, so importing them raises
# ModuleNotFoundError. Importing is the check that distinguishes the two.
db_probe='
import importlib
usable = []
for name in ("sqlalchemy", "sqlmodel", "psycopg", "asyncpg", "alembic",
             "iceberg_core.db", "iceberg_core.models"):
    try:
        importlib.import_module(name)
    except ImportError:
        continue
    usable.append(name)
print(",".join(usable))
'
usable="$(docker run --rm "$ENGINE_IMAGE" python -c "$db_probe")"
check "no database package is importable in the engine image" "" "$usable"

# The other half of the same boundary: no configuration that would let it try.
engine_env="$(docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$ENGINE_IMAGE" \
  | grep -Ei 'DATABASE|POSTGRES|MASTER_KEY' || true)"
check "no database or master-key variable is baked into the engine image" "" "$engine_env"

# ── Entrypoints actually serve ────────────────────────────────────────────────
# The image's HEALTHCHECK is the contract compose and Kubernetes rely on, so the
# check here is the same request they make.
group "Entrypoints serve"

serves() {
  local name="$1" image="$2" port="$3" path="$4" description="$5"
  shift 5
  docker rm -f "$name" >/dev/null 2>&1 || true
  docker run -d --name "$name" "$@" "$image" >/dev/null
  local ok=0
  for _ in $(seq 1 40); do
    if docker exec "$name" python -c "
import sys, urllib.request
try:
    urllib.request.urlopen('http://127.0.0.1:$port$path', timeout=2).read()
except Exception:
    sys.exit(1)
" >/dev/null 2>&1; then
      ok=1
      break
    fi
    sleep 1
  done
  if (( ok )); then
    pass "$description"
  else
    fail "$description"
    docker logs "$name" 2>&1 | tail -20 | sed 's/^/       /'
  fi
  docker rm -f "$name" >/dev/null 2>&1 || true
}

# The api needs enough configuration to construct its settings; it does not need
# a reachable database to answer /healthz, which is the point of the endpoint.
serves iceberg-verify-api "$API_IMAGE" 8000 /healthz "api serves /healthz" \
  -e ICEBERG_DATABASE_URL="postgresql+psycopg://iceberg:unused@127.0.0.1:5432/iceberg" \
  -e ICEBERG_REDIS_URL="redis://127.0.0.1:6379/0" \
  -e ICEBERG_MASTER_KEY="$(docker run --rm "$API_IMAGE" python -m iceberg_core.secrets generate-master-key)" \
  -e ICEBERG_SESSION_SECRET="verification-only-session-secret-not-a-real-one" \
  -e ICEBERG_FINGERPRINT_PEPPER_REF="env:ICEBERG_VERIFY_PEPPER"

# The engine refuses to boot without a credential (#131), so a token is part of
# the minimum configuration now — an unusable one, since nothing here registers
# with an API. No engine id: without one the engine skips heartbeats, which is
# what keeps this a check of the entrypoint rather than of the control plane.
serves iceberg-verify-engine "$ENGINE_IMAGE" 9191 /metrics "engine serves /metrics" \
  -e ICEBERG_REDIS_URL="redis://127.0.0.1:6379/0" \
  -e ICEBERG_API_BASE_URL="http://127.0.0.1:8000" \
  -e ICEBERG_ENGINE_TOKEN="verification-only-engine-token-not-a-real-one"

# ── The api can find its migrations ───────────────────────────────────────────
# The runtime stage copies only the venv, so alembic.ini and the revision scripts
# have to be inside the installed package. `heads` reads the script directory
# without touching a database, which is exactly the part that could be missing.
group "Migrations are packaged"
if docker run --rm \
    -e ICEBERG_DATABASE_URL="postgresql+psycopg://iceberg:unused@127.0.0.1:5432/iceberg" \
    -e ICEBERG_REDIS_URL="redis://127.0.0.1:6379/0" \
    -e ICEBERG_MASTER_KEY="unused" \
    -e ICEBERG_SESSION_SECRET="unused" \
    "$API_IMAGE" python -c "
from alembic import command
from iceberg_api.cli import alembic_config
command.heads(alembic_config())
" >/dev/null 2>&1; then
  pass "api image resolves its alembic config and revision scripts"
else
  fail "api image resolves its alembic config and revision scripts"
fi

group "Result"
if (( failures )); then
  printf '\033[31m%d check(s) failed\033[0m\n' "$failures"
  exit 1
fi
printf '\033[32mall checks passed\033[0m\n'
