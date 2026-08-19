"""Operator commands: ``python -m iceberg_api <command>``.

The bootstrap problem these solve is the same one the first admin has: the API-side
way to mint an engine token is an admin-authenticated route, and at deploy time there
is no admin session yet — nor should there need to be one to bring up a worker. So
the first token is minted here, against the database, by whoever can already run
commands in the API container (docs/security.md § Bootstrap).

`reclaim` and `scheduler-tick` exist for the same reason a cron entry does: the API
runs both on a loop, but an operator sometimes needs to force one and see what it
did.
"""

import argparse
import sys
import uuid
from collections.abc import Sequence
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

import structlog
from alembic import command
from alembic.config import Config
from iceberg_core.config import get_api_settings
from iceberg_core.db import session_scope
from iceberg_core.logging import configure_logging
from iceberg_core.models import (
    AUDIT_CORRELATION_REINDEXED,
    AUDIT_ENGINE_REGISTERED,
    AUDIT_ENGINE_TOKEN_ROTATED,
    AUDIT_TARGET_CORRELATION,
    AUDIT_TARGET_ENGINE,
    Engine,
)
from iceberg_core.secrets import build_secret_store
from sqlmodel import col, select

from iceberg_api import audit, retention
from iceberg_api.correlation import reindex
from iceberg_api.dispatch import build_dispatcher
from iceberg_api.engines.auth import mint_token
from iceberg_api.scans import service
from iceberg_api.scheduler import postgres_advisory_lock, tick
from iceberg_api.scheduler_launcher import build_launcher

logger = structlog.get_logger()


def _positive_int(raw: str) -> int:
    """An argparse type that refuses zero and negatives with a usage error."""
    value = int(raw)
    if value < 1:
        raise argparse.ArgumentTypeError(f"must be 1 or greater, got {value}")
    return value


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m iceberg_api",
        description="IcebergSST operator commands.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    mint = commands.add_parser(
        "mint-engine-token",
        help="register an engine (or rotate its token) and print the token once",
    )
    mint.add_argument("--name", required=True, help="engine name, e.g. engine-1")
    mint.add_argument("--version", default=None, help="engine version, if known")

    commands.add_parser("reclaim", help="return expired-lease tasks to the queue")
    commands.add_parser("scheduler-tick", help="run one scheduler round now")
    commands.add_parser(
        "retention-purge",
        help="apply the configured retention windows now (see docs/retention.md)",
    )

    reindex_parser = commands.add_parser(
        "reindex-correlation",
        help="re-derive every finding's correlation id under the configured key (ADR 0011)",
    )
    reindex_parser.add_argument(
        "--batch",
        # Positive, and refused by the parser rather than the loop: `--batch 0`
        # would walk with LIMIT 0, touch nothing, and exit reporting
        # `updated=0` — the very signal the runbook reads as "rotation
        # complete". A completion result has to mean the table was scanned.
        type=_positive_int,
        default=1000,
        help="rows walked per batch (default: 1000)",
    )

    migrate_parser = commands.add_parser("migrate", help="apply migrations up to a revision")
    migrate_parser.add_argument(
        "--revision",
        default="head",
        help="target revision (default: head; accepts e.g. -1 to step back)",
    )
    return parser


#: The packaged alembic config, resolved against this module rather than the
#: working directory. The api image installs the package and copies no source
#: tree, so a repo-relative path would be correct in a checkout and wrong in
#: every container.
ALEMBIC_INI = Path(__file__).resolve().parent / "alembic.ini"


def alembic_config() -> Config:
    """The alembic config as every role should reach it.

    One loader for the compose `make migrate`, the Helm pre-upgrade Job, and the
    migration tests, so none of them can drift onto a different script location.
    """
    return Config(str(ALEMBIC_INI))


def migrate(revision: str = "head") -> None:
    """Apply migrations. The api role owns the schema; nothing else runs this."""
    command.upgrade(alembic_config(), revision)


def mint_engine_token(name: str, version: str | None) -> tuple[uuid.UUID, str]:
    """Register or rotate ``name``; return its id and new token.

    The id is as much a part of the credential as the token: an engine names
    itself in its heartbeat path, and the API checks the two agree (#51).
    """
    with session_scope() as db:
        engine = db.exec(select(Engine).where(col(Engine.name) == name)).first()
        rotating = engine is not None
        if engine is None:
            engine = Engine(name=name, token_hash="", version=version)
        elif version:
            engine.version = version
        minted = mint_token(engine)
        db.add(minted.engine)
        # The same durable trail the admin route writes: minting a credential
        # that will later receive decrypted source credentials belongs in
        # audit_event whichever door it came through. No actor — this runs as
        # whoever can already execute commands in the API container.
        audit.record(
            db,
            actor_id=None,
            action=AUDIT_ENGINE_TOKEN_ROTATED if rotating else AUDIT_ENGINE_REGISTERED,
            target_type=AUDIT_TARGET_ENGINE,
            target_id=minted.engine.id,
            detail={"name": minted.engine.name, "via": "cli"},
        )
        engine_id = minted.engine.id
    return engine_id, minted.token


def reindex_correlation(key: bytes, *, batch: int = 1000) -> reindex.ReindexOutcome:
    """Re-derive every finding's correlation id under ``key`` and audit it.

    The rotation's whole migration path (ADR 0011): no rescan, no engine, one
    idempotent walk of the table. Audited like the other CLI door — recomputing
    every cluster in the deployment is an administrative act worth a trail row.
    """
    with session_scope() as db:
        outcome = reindex.reindex_all(db, key, batch=batch)
        audit.record(
            db,
            actor_id=None,
            action=AUDIT_CORRELATION_REINDEXED,
            target_type=AUDIT_TARGET_CORRELATION,
            target_id=None,
            detail={
                "scanned": str(outcome.scanned),
                "updated": str(outcome.updated),
                "via": "cli",
            },
        )
    return outcome


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    settings = get_api_settings()
    configure_logging(role="api", level=settings.log_level)

    match args.command:
        case "mint-engine-token":
            engine_id, token = mint_engine_token(args.name, args.version)
            # Printed to stdout alone, so `... > token.txt` captures exactly the
            # token and the surrounding advice goes to the terminal.
            print(token)
            print(
                f"Registered engine {args.name!r} as {engine_id}.\n"
                f"Store this token now — only its hash is kept, so it cannot be shown "
                f"again. The engine needs both:\n"
                f"  ICEBERG_ENGINE_ID={engine_id}\n"
                f"  ICEBERG_ENGINE_TOKEN=<the token above>",
                file=sys.stderr,
            )
        case "reclaim":
            dispatcher = build_dispatcher(settings)
            with session_scope() as db:
                reclaimed = service.reclaim_expired_leases(db, dispatcher=dispatcher)
            print(f"reclaimed {len(reclaimed)} task(s)", file=sys.stderr)
        case "scheduler-tick":
            dispatcher = build_dispatcher(settings)
            with session_scope() as db:
                result = tick(
                    db,
                    now=datetime.now(UTC),
                    launcher=build_launcher(dispatcher, build_secret_store(settings)),
                    lock=postgres_advisory_lock,
                )
            print(
                f"leader={result.was_leader} fired={len(result.fired)} "
                f"skipped={len(result.skipped)}",
                file=sys.stderr,
            )
        case "migrate":
            migrate(args.revision)
            print(f"migrated to {args.revision}", file=sys.stderr)
        case "retention-purge":
            # The maintenance loop runs this on its own cadence; this exists for
            # the first purge after a window is configured, when an operator wants
            # to see the number rather than discover it in the audit log.
            with session_scope() as db:
                purged = retention.purge(db, settings)
            # Every counter the result carries, built from the dataclass rather
            # than a hand-written list: a run that only scrubbed remediation
            # evidence — irreversibly removing URLs and notes — reported three
            # zeroes while the audit row recorded the work.
            print(
                " ".join(f"{field}={value}" for field, value in asdict(purged).items()),
                file=sys.stderr,
            )
        case "reindex-correlation":
            # The key-rotation migration path (docs/runbooks/key-rotation.md
            # § Correlation key): after swapping ICEBERG_CORRELATION_KEY_REF,
            # re-derive every stored id. Idempotent — run it again and
            # `updated=0` is the signal the rotation is complete.
            key = build_secret_store(settings).get_correlation_key()
            if key is None:
                print(
                    "error: ICEBERG_CORRELATION_KEY_REF is not set; "
                    "generate one with: python -m iceberg_core.secrets generate-correlation-key",
                    file=sys.stderr,
                )
                return 2
            outcome = reindex_correlation(key, batch=args.batch)
            print(f"scanned={outcome.scanned} updated={outcome.updated}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
