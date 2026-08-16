#!/usr/bin/env bash
# Rehearse the two things a release promises can be done: upgrading to it, and
# recovering from a backup taken before it (#147, docs/releases.md).
#
# Runs against a real Postgres, because the failures worth catching are the ones
# SQLite cannot have. `apps/api/tests/test_migrations.py` proves the ops execute
# and the shape matches the models; this proves the *sequence* works on the
# database production uses.
#
# Four rehearsals, each for a failure the others do not cover:
#
#   1. Stepwise upgrade. Every revision applied one at a time rather than in one
#      `head` jump — a migration that only works when the whole schema is created
#      at once passes the jump and fails the upgrade an operator actually runs.
#   2. Stepwise downgrade, then re-apply. Reversibility is what makes a rollback
#      mechanically possible, and re-applying is the assertion: a downgrade that
#      leaves a table, an index or a type behind fails the second upgrade on a
#      name that already exists.
#   3. Upgrade from the previous release. The supported path (docs/releases.md),
#      rehearsed by applying that tag's migrations and then upgrading this tree
#      onto them. Skipped, loudly, until a release tag exists.
#   4. Backup and restore. The recovery documented in
#      runbooks/backup-restore.md, with data written before the dump and asserted
#      after the restore — a backup nobody has restored is a plan, not a backup.
#
# Usage:
#   ICEBERG_DATABASE_URL=postgresql+psycopg://iceberg@localhost:5432/iceberg \
#     scripts/rehearse_release.sh
set -euo pipefail

: "${ICEBERG_DATABASE_URL:?set ICEBERG_DATABASE_URL to a scratch Postgres}"

ALEMBIC="uv run alembic -c apps/api/src/iceberg_api/alembic.ini"
MIGRATE="uv run python -m iceberg_api migrate"

# psql/pg_dump want a libpq URL; the application's carries a driver in the scheme.
PSQL_URL="${ICEBERG_DATABASE_URL/postgresql+psycopg:\/\//postgresql://}"

step() { printf '\n\033[1m▸ %s\033[0m\n' "$1"; }

reset_database() {
  # `downgrade base` would only remove what the migrations know about; a rehearsal
  # has to start from nothing, or a leftover from an earlier step masks the very
  # failure the next one is looking for.
  psql "$PSQL_URL" -v ON_ERROR_STOP=1 -q -c 'DROP SCHEMA public CASCADE; CREATE SCHEMA public;'
}

revisions() {
  # Oldest first. `alembic history` prints newest first, and applying them in that
  # order would fail on the first foreign key.
  $ALEMBIC history --indicate-current 2>/dev/null \
    | awk '/->/ {print $3}' | tr -d ',' | tac
}

# ─── 1. Stepwise upgrade ──────────────────────────────────────────────────────

step "Applying every revision one at a time"
reset_database
for revision in $(revisions); do
  printf '  → %s\n' "$revision"
  $MIGRATE --revision "$revision"
done

# ─── 2. Stepwise downgrade, then re-apply ─────────────────────────────────────

step "Reversing one revision at a time, then re-applying"
for _ in $(revisions); do
  $ALEMBIC downgrade -1
done
$MIGRATE

# ─── 3. Upgrade from the previous release ─────────────────────────────────────

previous="$(git tag --list 'v*.*.*' --sort=-version:refname | head -n 1)"
if [ -z "$previous" ]; then
  # Loudly, not silently: a rehearsal that reports success without having run is
  # worse than one that says it could not.
  step "SKIPPED: no release tag exists yet, so there is no supported upgrade to rehearse"
else
  step "Upgrading from $previous"
  reset_database
  worktree="$(mktemp -d)"
  # A worktree rather than a checkout: the migrations have to come from the tag
  # while `uv run` still resolves this tree's environment, and swapping the branch
  # underneath a running rehearsal is how you end up testing neither version.
  git worktree add --detach "$worktree" "$previous" >/dev/null
  uv run alembic -c "$worktree/apps/api/src/iceberg_api/alembic.ini" upgrade head
  git worktree remove --force "$worktree"
  $MIGRATE
fi

# ─── 4. Backup and restore ────────────────────────────────────────────────────

step "Backing up, destroying, and restoring"
reset_database
$MIGRATE
# A row whose survival is the assertion. `source` is the simplest table with no
# foreign keys into it, so restoring it proves the dump carried data rather than
# only DDL.
psql "$PSQL_URL" -v ON_ERROR_STOP=1 -q -c "
  INSERT INTO source (id, created_at, updated_at, name, type, connection, tags, enabled,
                      full_scan_interval_days)
  VALUES (gen_random_uuid(), now(), now(), 'rehearsal', 'confluence', '{}', '[]', true, 7);"

dump="$(mktemp -t icebergsst-rehearsal-XXXXXX.sql)"
trap 'rm -f "$dump"' EXIT
pg_dump --format=plain --no-owner --no-privileges "$PSQL_URL" > "$dump"
reset_database
# Through stdin rather than `-f`: the restore path an operator uses is a pipe
# (`psql < dump.sql`), and it is the one that works when the client is not on the
# same filesystem as the file — a container, or a bastion.
psql "$PSQL_URL" -v ON_ERROR_STOP=1 -q < "$dump" > /dev/null

restored="$(psql "$PSQL_URL" -tAc "SELECT count(*) FROM source WHERE name = 'rehearsal';")"
if [ "$restored" != "1" ]; then
  echo "restore did not bring the row back (found $restored)" >&2
  exit 1
fi

# The restored schema must still satisfy the models, not merely load. A dump taken
# mid-migration would restore cleanly and be wrong.
step "Asserting the restored schema still matches the models"
$MIGRATE
uv run python -c "
from alembic.migration import MigrationContext
from alembic.autogenerate import compare_metadata
from iceberg_core.db import create_db_engine
from iceberg_core.models import metadata
import os

engine = create_db_engine(os.environ['ICEBERG_DATABASE_URL'])
with engine.connect() as connection:
    diff = compare_metadata(MigrationContext.configure(connection), metadata)
raise SystemExit(0 if not diff else f'restored schema differs from the models: {diff}')
"

printf '\n\033[1m✓ upgrade, rollback, and recovery rehearsed\033[0m\n'
