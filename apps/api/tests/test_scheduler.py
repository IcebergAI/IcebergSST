"""The scheduler tick: cadence, leader election, and bookkeeping (#33)."""

import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from conftest import RecordingDispatcher
from iceberg_api.scans import service
from iceberg_api.scheduler import (
    SCHEDULER_LOCK_KEY,
    TickResult,
    due_schedules,
    next_fire_time,
    postgres_advisory_lock,
    tick,
)
from iceberg_api.scheduler_launcher import build_launcher
from iceberg_core.enums import ScanTrigger, SourceType
from iceberg_core.models import Scan, Schedule, Source
from sqlmodel import Session, select

NIGHTLY = "0 3 * * *"
MONDAYS = "0 4 * * 1"


def _utc(value: datetime) -> datetime:
    """SQLite drops the offset on the way out; Postgres keeps it (TIMESTAMPTZ)."""
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def _source(session: Session, name: str = "confluence-prod") -> Source:
    source = Source(
        name=name,
        type=SourceType.CONFLUENCE,
        connection={"base_url": "https://example.atlassian.net/wiki"},
    )
    session.add(source)
    session.commit()
    return source


def _schedule(
    session: Session,
    source: Source,
    *,
    cron: str = NIGHTLY,
    enabled: bool = True,
    next_run_at: datetime | None = None,
) -> Schedule:
    schedule = Schedule(source_id=source.id, cron=cron, enabled=enabled, next_run_at=next_run_at)
    session.add(schedule)
    session.commit()
    return schedule


def _recording_launcher() -> tuple[
    Callable[[Session, uuid.UUID], uuid.UUID | None], list[uuid.UUID]
]:
    launched: list[uuid.UUID] = []

    def launcher(db: Session, source_id: uuid.UUID) -> uuid.UUID | None:
        launched.append(source_id)
        return uuid.uuid4()

    return launcher, launched


def test_next_fire_time_is_the_next_beat_after_the_given_instant() -> None:
    """Time is a parameter, so this is answerable without waiting until 03:00."""
    before = datetime(2026, 7, 29, 2, 59, tzinfo=UTC)
    after = datetime(2026, 7, 29, 3, 1, tzinfo=UTC)

    assert next_fire_time(NIGHTLY, before) == datetime(2026, 7, 29, 3, 0, tzinfo=UTC)
    assert next_fire_time(NIGHTLY, after) == datetime(2026, 7, 30, 3, 0, tzinfo=UTC)
    assert next_fire_time(MONDAYS, after).weekday() == 0


def test_a_due_schedule_fires_and_its_bookkeeping_advances(session: Session) -> None:
    source = _source(session)
    now = datetime(2026, 7, 29, 3, 0, tzinfo=UTC)
    schedule = _schedule(session, source, next_run_at=now - timedelta(minutes=1))
    launcher, launched = _recording_launcher()

    result = tick(session, now=now, launcher=launcher, lock=lambda _: True)

    assert result == TickResult(was_leader=True, fired=[schedule.id], skipped=[])
    assert launched == [source.id]
    session.refresh(schedule)
    assert schedule.last_run_at is not None
    assert schedule.next_run_at is not None
    assert _utc(schedule.next_run_at) == datetime(2026, 7, 30, 3, 0, tzinfo=UTC)


def test_a_schedule_that_is_not_due_does_not_fire(session: Session) -> None:
    source = _source(session)
    now = datetime(2026, 7, 29, 3, 0, tzinfo=UTC)
    _schedule(session, source, next_run_at=now + timedelta(hours=1))
    launcher, launched = _recording_launcher()

    result = tick(session, now=now, launcher=launcher, lock=lambda _: True)

    assert result.fired == []
    assert launched == []


def test_a_disabled_schedule_never_fires(session: Session) -> None:
    source = _source(session)
    now = datetime(2026, 7, 29, 3, 0, tzinfo=UTC)
    _schedule(session, source, enabled=False, next_run_at=now - timedelta(days=1))
    launcher, launched = _recording_launcher()

    assert tick(session, now=now, launcher=launcher, lock=lambda _: True).fired == []
    assert launched == []


def test_a_schedule_with_no_next_run_is_treated_as_due(session: Session) -> None:
    """Created while the scheduler was down; it should still get a first run."""
    source = _source(session)
    schedule = _schedule(session, source, next_run_at=None)

    due = due_schedules(session, datetime(2026, 7, 29, 12, 0, tzinfo=UTC))

    assert [item.id for item in due] == [schedule.id]


def test_only_the_leader_does_the_round(session: Session) -> None:
    """N replicas, one due schedule, exactly one firing (ADR 0009 rationale)."""
    source = _source(session)
    now = datetime(2026, 7, 29, 3, 0, tzinfo=UTC)
    _schedule(session, source, next_run_at=now - timedelta(minutes=1))
    launcher, launched = _recording_launcher()

    # A lock that admits the first caller only, as Postgres would across replicas.
    holders: list[str] = []

    def contended_lock(db: Session) -> bool:
        if holders:
            return False
        holders.append("leader")
        return True

    first = tick(session, now=now, launcher=launcher, lock=contended_lock)
    second = tick(session, now=now, launcher=launcher, lock=contended_lock)
    third = tick(session, now=now, launcher=launcher, lock=contended_lock)

    assert first.was_leader is True
    assert (second.was_leader, third.was_leader) == (False, False)
    assert len(launched) == 1


def test_a_failing_launcher_does_not_take_the_round_down(session: Session) -> None:
    """One unreachable source must not stop every other schedule for the night."""
    first_source = _source(session, "breaks")
    second_source = _source(session, "works")
    now = datetime(2026, 7, 29, 3, 0, tzinfo=UTC)
    broken = _schedule(session, first_source, next_run_at=now - timedelta(minutes=5))
    healthy = _schedule(session, second_source, next_run_at=now - timedelta(minutes=5))

    def launcher(db: Session, source_id: uuid.UUID) -> uuid.UUID | None:
        if source_id == first_source.id:
            raise RuntimeError("broker unreachable")
        return uuid.uuid4()

    result = tick(session, now=now, launcher=launcher, lock=lambda _: True)

    assert result.fired == [healthy.id]
    assert result.skipped == [broken.id]
    # The failed one keeps its due time, so the next tick tries again.
    session.refresh(broken)
    assert broken.last_run_at is None


def test_a_refused_launch_keeps_an_earlier_schedules_bookkeeping(
    session: Session, dispatcher: RecordingDispatcher
) -> None:
    """The real launcher shares this session, and a source already scanning is
    refused by the one-active-scan index (ADR 0009 §3).

    That refusal has to cost only the schedule that hit it. Rolled back to the
    start of the round, the schedules that already fired would keep their old
    `next_run_at`, be due again on the very next beat, and — for a small source
    that finished in the meantime — start a second scan of work just done.
    """
    idle = _source(session, "idle")
    busy = _source(session, "busy")
    service.launch_scan(session, busy, trigger=ScanTrigger.MANUAL, dispatcher=dispatcher)
    now = datetime(2026, 7, 29, 3, 0, tzinfo=UTC)
    first = _schedule(session, idle, next_run_at=now - timedelta(minutes=1))
    second = _schedule(session, busy, next_run_at=now - timedelta(minutes=1))

    result = tick(session, now=now, launcher=build_launcher(dispatcher), lock=lambda _: True)

    assert result.fired == [first.id, second.id]
    session.refresh(first)
    assert first.last_run_at is not None
    assert first.next_run_at is not None
    assert _utc(first.next_run_at) == datetime(2026, 7, 30, 3, 0, tzinfo=UTC)
    # The busy source got no second scan, which is the refusal working.
    assert len(session.exec(select(Scan).where(Scan.source_id == busy.id)).all()) == 1


def test_a_missed_beat_fires_once_not_once_per_beat_missed(session: Session) -> None:
    """A scheduler down for a week owes one scan, not seven."""
    source = _source(session)
    week_ago = datetime(2026, 7, 22, 3, 0, tzinfo=UTC)
    now = datetime(2026, 7, 29, 3, 0, tzinfo=UTC)
    schedule = _schedule(session, source, next_run_at=week_ago)
    launcher, launched = _recording_launcher()

    tick(session, now=now, launcher=launcher, lock=lambda _: True)

    assert len(launched) == 1
    session.refresh(schedule)
    assert schedule.next_run_at is not None
    assert _utc(schedule.next_run_at) == datetime(2026, 7, 30, 3, 0, tzinfo=UTC)


def test_sqlite_reports_leadership_because_there_is_nothing_to_serialise(
    session: Session,
) -> None:
    """The real advisory lock only exists on Postgres; see the module docstring."""
    assert postgres_advisory_lock(session) is True
    assert SCHEDULER_LOCK_KEY > 0
