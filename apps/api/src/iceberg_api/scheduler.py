"""The cron scheduler: one tick, leader-elected (#33).

Every API replica runs this loop, and a due schedule must fire **once** — not once
per replica. The guard is a Postgres advisory lock taken for the duration of the
tick's transaction: whoever gets it does the round, everyone else returns
immediately and tries again next tick. No extra infrastructure, no leader lease to
expire, and the lock is released even if the process dies mid-tick because it is
scoped to the transaction (docs/deployment.md § Scaling model).

Launching the scan itself is *not* here. Scan and ScanTask, and the fan-out into a
discovery task, belong to #34; the tick calls an injected launcher so that work can
land without reopening this file. Until then a launcher can be a no-op, and the
schedule bookkeeping — `last_run_at`, `next_run_at` — is already correct.

Time is a parameter, never `now()` read inside: a scheduler you cannot run at an
arbitrary instant is a scheduler you cannot test.
"""

import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime

import structlog
from croniter import croniter
from iceberg_core.enums import ScanMode
from iceberg_core.models import Schedule
from sqlalchemy import text
from sqlmodel import Session, select

#: Advisory-lock key for the scheduler tick. Arbitrary but fixed — two different
#: constants would mean two leaders.
SCHEDULER_LOCK_KEY = 0x1CEB_0001

#: Something has to launch the scan. Returns the launched scan's id, or None if it
#: declined (for example: this source already has an active scan — ADR 0009).
#: A source id and the mode its schedule asked for. The launcher is free to
#: promote it — a schedule requests, the API decides (#143).
ScanLauncher = Callable[[Session, uuid.UUID, ScanMode], uuid.UUID | None]

#: Takes the tick lock. Returns True if this replica is the leader for this round.
LeaderLock = Callable[[Session], bool]

logger = structlog.get_logger()


@dataclass(frozen=True, slots=True)
class TickResult:
    """What one tick did, for logging, metrics, and tests."""

    #: False when another replica held the lock — this tick did nothing, by design.
    was_leader: bool
    fired: list[uuid.UUID] = field(default_factory=list)
    skipped: list[uuid.UUID] = field(default_factory=list)


def postgres_advisory_lock(session: Session) -> bool:
    """Try to take the scheduler lock for this transaction.

    ``pg_try_advisory_xact_lock`` never waits: a replica that loses the race gets
    ``False`` immediately rather than queuing up to run a redundant tick.

    On SQLite (tests, local runs) there is nothing to serialise and no such
    function, so this reports leadership. Single-process by definition — but it
    does mean the real lock is only exercised against Postgres, so the
    leader-election test drives the seam instead.
    """
    if session.get_bind().dialect.name != "postgresql":
        return True
    acquired = session.exec(  # type: ignore[call-overload]
        text("SELECT pg_try_advisory_xact_lock(:key)").bindparams(key=SCHEDULER_LOCK_KEY)
    ).one()
    return bool(acquired[0])


def next_fire_time(cron: str, after: datetime) -> datetime:
    """The first time ``cron`` fires strictly after ``after``, in UTC."""
    base = after if after.tzinfo else after.replace(tzinfo=UTC)
    fires_at: datetime = croniter(cron, base).get_next(datetime)
    return fires_at if fires_at.tzinfo else fires_at.replace(tzinfo=UTC)


def due_schedules(db: Session, now: datetime) -> list[Schedule]:
    """Enabled schedules whose next run has arrived.

    A schedule with no ``next_run_at`` is treated as due so that a schedule created
    while the scheduler was down still gets a first run, rather than waiting for
    someone to notice it never started.
    """
    statement = select(Schedule).where(Schedule.enabled == True)  # noqa: E712  # SQL, not Python
    return [
        schedule
        for schedule in db.exec(statement)
        if schedule.next_run_at is None or _as_utc(schedule.next_run_at) <= now
    ]


def tick(
    db: Session,
    *,
    now: datetime,
    launcher: ScanLauncher,
    lock: LeaderLock = postgres_advisory_lock,
) -> TickResult:
    """Run one scheduler round. Commits.

    A launcher that raises does not take the rest of the round down with it: the
    failure is logged, that schedule keeps its `next_run_at` so the next tick tries
    again, and the other due schedules still fire.
    """
    if not lock(db):
        logger.debug("scheduler_tick_not_leader")
        return TickResult(was_leader=False)

    fired: list[uuid.UUID] = []
    skipped: list[uuid.UUID] = []

    for schedule in due_schedules(db, now):
        try:
            scan_id = launcher(db, schedule.source_id, schedule.mode)
        except Exception:  # one bad source must not stop the round
            logger.exception("scheduled_scan_launch_failed", schedule_id=str(schedule.id))
            skipped.append(schedule.id)
            continue

        schedule.last_run_at = now
        schedule.next_run_at = next_fire_time(schedule.cron, now)
        db.add(schedule)
        fired.append(schedule.id)
        logger.info(
            "scheduled_scan_launched",
            schedule_id=str(schedule.id),
            source_id=str(schedule.source_id),
            scan_id=str(scan_id) if scan_id else None,
            next_run_at=schedule.next_run_at.isoformat(),
        )

    db.commit()
    return TickResult(was_leader=True, fired=fired, skipped=skipped)


@contextmanager
def no_launcher() -> Iterator[ScanLauncher]:
    """A launcher that records nothing and launches nothing.

    The honest placeholder until #34 lands: schedules advance and the bookkeeping
    is exercised, without pretending a scan happened.
    """

    def launcher(db: Session, source_id: uuid.UUID, mode: ScanMode) -> uuid.UUID | None:
        logger.warning("scan_launch_not_implemented", source_id=str(source_id))
        return None

    yield launcher


def _as_utc(value: datetime) -> datetime:
    # SQLite hands back naive datetimes even for TIMESTAMPTZ columns.
    return value if value.tzinfo else value.replace(tzinfo=UTC)
