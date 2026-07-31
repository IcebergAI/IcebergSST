"""Fleet health: noticing that an engine has stopped talking (#58, #70).

An engine's status is written by the API, never by the engine: a worker that died
cannot report that it died. So the only evidence available is silence, and this
sweep is what reads it — engines whose last heartbeat is older than the threshold
go ``offline``, and :func:`iceberg_api.engines.auth.record_heartbeat` brings them
back the moment one speaks again.

Without it every engine ever registered stays ``active`` forever: the admin fleet
view shows a worker that died months ago as live, and ``GET /rules`` reports its
rule pack as part of the detection surface currently in force, which is precisely
the thing that endpoint exists to answer honestly.

An engine that never heartbeat at all is left alone. It was minted by an operator
who has not started it yet, and calling that "offline" would raise an alarm about
a machine nobody has run.
"""

import uuid
from datetime import UTC, datetime, timedelta

import structlog
from iceberg_core.enums import EngineStatus
from iceberg_core.models import Engine
from sqlmodel import Session, col, select, update

logger = structlog.get_logger()


def mark_stale_engines_offline(
    db: Session,
    *,
    stale_after_seconds: int,
    now: datetime | None = None,
) -> list[uuid.UUID]:
    """Flip engines that have gone quiet to ``offline``. Commits.

    ``draining`` engines are swept too: draining is an operator's intent to retire
    one, and an engine that stopped answering during it has retired itself.
    """
    at = now or datetime.now(UTC)
    cutoff = at - timedelta(seconds=stale_after_seconds)

    stale = list(
        db.exec(
            select(col(Engine.id))
            .where(col(Engine.status) != EngineStatus.OFFLINE)
            .where(col(Engine.last_heartbeat_at).is_not(None))
            .where(col(Engine.last_heartbeat_at) < cutoff)
        )
    )
    if not stale:
        db.rollback()
        return []

    # Conditional per engine, like every other status transition: a heartbeat
    # landing between the select and this write must win, or the engine that just
    # proved it is alive would be reported dead until its next beat.
    marked: list[uuid.UUID] = []
    for engine_id in stale:
        result = db.exec(
            update(Engine)
            .where(
                col(Engine.id) == engine_id,
                col(Engine.status) != EngineStatus.OFFLINE,
                col(Engine.last_heartbeat_at).is_not(None),
                col(Engine.last_heartbeat_at) < cutoff,
            )
            .values(status=EngineStatus.OFFLINE)
            # The datetime predicate cannot be evaluated against in-session objects
            # (SQLite hands back naive datetimes), so sync by re-select.
            .execution_options(synchronize_session="fetch")
        )
        if result.rowcount == 1:
            marked.append(engine_id)

    db.commit()
    for engine_id in marked:
        logger.info("engine_marked_offline", engine_id=str(engine_id))
    return marked


__all__ = ["mark_stale_engines_offline"]
