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
from collections.abc import Sequence
from datetime import UTC, datetime

import structlog
from iceberg_core.config import get_api_settings
from iceberg_core.db import session_scope
from iceberg_core.logging import configure_logging
from iceberg_core.models import Engine
from sqlmodel import col, select

from iceberg_api.dispatch import build_dispatcher
from iceberg_api.engines.auth import mint_token
from iceberg_api.scans import service
from iceberg_api.scheduler import postgres_advisory_lock, tick
from iceberg_api.scheduler_launcher import build_launcher

logger = structlog.get_logger()


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
    return parser


def mint_engine_token(name: str, version: str | None) -> str:
    """Register or rotate ``name`` and return its new token."""
    with session_scope() as db:
        engine = db.exec(select(Engine).where(col(Engine.name) == name)).first()
        if engine is None:
            engine = Engine(name=name, token_hash="", version=version)
        elif version:
            engine.version = version
        minted = mint_token(engine)
        db.add(minted.engine)
    return minted.token


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    configure_logging(role="api")
    settings = get_api_settings()

    match args.command:
        case "mint-engine-token":
            token = mint_engine_token(args.name, args.version)
            # Printed to stdout alone, so `... > token.txt` captures exactly the
            # token and the surrounding advice goes to the terminal.
            print(token)
            print(
                f"Registered engine {args.name!r}. Store this token now — only its "
                "hash is kept, so it cannot be shown again.",
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
                    launcher=build_launcher(dispatcher),
                    lock=postgres_advisory_lock,
                )
            print(
                f"leader={result.was_leader} fired={len(result.fired)} "
                f"skipped={len(result.skipped)}",
                file=sys.stderr,
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
