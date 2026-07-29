"""The in-process maintenance round (#33 → #34, #35)."""

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import pytest
from conftest import RecordingDispatcher
from iceberg_api import maintenance
from iceberg_api.scans import service
from iceberg_core.db import set_db_engine
from iceberg_core.enums import ScanTaskStatus, ScanTrigger, SourceType
from iceberg_core.models import Engine, Scan, ScanTask, Schedule, Source
from sqlalchemy import Engine as SAEngine
from sqlmodel import Session, select


@pytest.fixture(name="process_engine", autouse=True)
def process_engine_fixture(db_engine: SAEngine) -> Iterator[None]:
    """`run_once` opens its own session, so point the process engine at the test DB."""
    set_db_engine(db_engine)
    yield
    set_db_engine(None)


def _source(session: Session, name: str = "confluence-prod") -> Source:
    source = Source(
        name=name,
        type=SourceType.CONFLUENCE,
        connection={"base_url": "https://example.atlassian.net/wiki"},
    )
    session.add(source)
    session.commit()
    return source


def test_a_round_launches_due_scans_and_advances_the_schedule(
    session: Session, dispatcher: RecordingDispatcher
) -> None:
    source = _source(session)
    schedule = Schedule(
        source_id=source.id,
        cron="*/5 * * * *",
        next_run_at=datetime.now(UTC) - timedelta(minutes=1),
    )
    session.add(schedule)
    session.commit()

    maintenance.run_once(dispatcher)

    scans = session.exec(select(Scan)).all()
    assert len(scans) == 1
    assert scans[0].trigger.value == "scheduled"
    assert dispatcher.enqueued  # its discovery task was dispatched
    session.refresh(schedule)
    assert schedule.last_run_at is not None


def test_a_round_reclaims_expired_leases(session: Session, dispatcher: RecordingDispatcher) -> None:
    source = _source(session)
    scan = service.launch_scan(session, source, trigger=ScanTrigger.MANUAL, dispatcher=dispatcher)
    task = session.exec(select(ScanTask).where(ScanTask.scan_id == scan.id)).one()
    engine = Engine(name="dead", token_hash="unused")
    session.add(engine)
    session.commit()
    service.claim_task(session, task.id, engine.id, lease_seconds=1)
    dispatcher.enqueued.clear()

    maintenance.run_once(dispatcher, now=datetime.now(UTC) + timedelta(minutes=10))

    session.refresh(task)
    assert task.status is ScanTaskStatus.QUEUED
    assert dispatcher.enqueued == [task.id]


def test_a_source_with_an_active_scan_is_skipped_not_double_scanned(
    session: Session, dispatcher: RecordingDispatcher
) -> None:
    """The cadence said "scan now" and one is already running; the next beat will do."""
    source = _source(session)
    service.launch_scan(session, source, trigger=ScanTrigger.MANUAL, dispatcher=dispatcher)
    schedule = Schedule(
        source_id=source.id,
        cron="*/5 * * * *",
        next_run_at=datetime.now(UTC) - timedelta(minutes=1),
    )
    session.add(schedule)
    session.commit()

    maintenance.run_once(dispatcher)

    assert len(session.exec(select(Scan)).all()) == 1
    session.refresh(schedule)
    # Still advanced: the beat was handled, just not with a new scan.
    assert schedule.last_run_at is not None


def test_a_disabled_source_is_not_scanned_on_its_cadence(
    session: Session, dispatcher: RecordingDispatcher
) -> None:
    source = _source(session)
    source.enabled = False
    schedule = Schedule(
        source_id=source.id,
        cron="*/5 * * * *",
        next_run_at=datetime.now(UTC) - timedelta(minutes=1),
    )
    session.add(schedule)
    session.commit()

    maintenance.run_once(dispatcher)

    assert session.exec(select(Scan)).all() == []
