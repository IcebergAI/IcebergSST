#!/usr/bin/env bash
#
# Mint an engine token for the compose stack, record it in .env, and start the
# engine.
#
#   make up                            # postgres, redis, api — and migrate
#   ./deploy/compose/engine-token.sh   # this
#   make scale N=3                     # more replicas, later
#
# Why this is a step of its own rather than something `make init-env` generates:
# an engine refuses to start without a token, and the only thing that can mint
# one is the api, against a schema that does not exist until `make up` has
# migrated. Nor can the value be invented ahead of time — the API stores only the
# token's hash, so anything written into .env by hand would authenticate with
# something the API never issued. The ordering is real, so it is made explicit
# here instead of being papered over with a token that cannot work.
#
# Re-running rotates: the previous token stops working the moment this returns.
# Pass a name to register a second engine (`./engine-token.sh engine-2`).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ENV_FILE="${ENV_FILE:-$REPO_ROOT/.env}"
ENGINE_NAME="${1:-engine-1}"
COMPOSE=(docker compose -f "$REPO_ROOT/deploy/compose/docker-compose.yml" --env-file "$ENV_FILE")

if [[ ! -f "$ENV_FILE" ]]; then
  printf 'no %s — run `make init-env` first\n' "$ENV_FILE" >&2
  exit 1
fi

# Set NAME=VALUE in .env, replacing the existing assignment or appending one.
# Written through `cat` rather than `mv` so the file keeps the 0600 mode
# init-env.py created it with: this file holds the master key.
write_var() {
  local name="$1" value="$2" scratch
  scratch="$(mktemp)"
  awk -v name="$name" -v value="$value" '
    BEGIN { replaced = 0 }
    index($0, name "=") == 1 { print name "=" value; replaced = 1; next }
    { print }
    END { if (!replaced) print name "=" value }
  ' "$ENV_FILE" >"$scratch"
  cat "$scratch" >"$ENV_FILE"
  rm -f "$scratch"
}

# `-T` matters: with a TTY the two streams are merged, and this reads them
# separately — the CLI prints the token alone on stdout so a redirect captures
# exactly it, and everything else, the id included, on stderr.
details="$(mktemp)"
trap 'rm -f "$details"' EXIT

token="$("${COMPOSE[@]}" run --rm -T api \
  python -m iceberg_api mint-engine-token --name "$ENGINE_NAME" 2>"$details")"
engine_id="$(sed -n 's/^[[:space:]]*ICEBERG_ENGINE_ID=\(.*\)$/\1/p' "$details" | head -1)"

if [[ -z "$token" || -z "$engine_id" ]]; then
  printf 'mint-engine-token produced no credential:\n' >&2
  cat "$details" >&2
  exit 1
fi

# Never echoed. A token in a terminal ends up in shell history and scrollback,
# and this one is enough to lease tasks and receive decrypted source credentials.
write_var ICEBERG_ENGINE_ID "$engine_id"
write_var ICEBERG_ENGINE_TOKEN "$token"
# Activates the engine profile for every later compose command, so `make up`,
# `make ps` and `make logs` all include engines from now on.
write_var COMPOSE_PROFILES engine

printf 'registered %s as %s; token written to %s\n' "$ENGINE_NAME" "$engine_id" "$ENV_FILE" >&2

"${COMPOSE[@]}" up -d --wait engine
