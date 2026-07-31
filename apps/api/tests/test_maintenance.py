"""The in-process maintenance round (#33 → #34, #35)."""

from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta

import pytest
from conftest import RecordingDispatcher
from iceberg_api import maintenance
from iceberg_api.engines.auth import record_heartbeat
from iceberg_api.scans import service
from iceberg_core.config import ApiSettings
from iceberg_core.db import set_db_engine
from iceberg_core.enums import (
    EngineStatus,
    ScanStatus,
    ScanTaskStatus,
    ScanTrigger,
    SourceType,
    SuppressionScope,
)
from iceberg_core.models import (
    Engine,
    Finding,
    Scan,
    ScanTask,
    Schedule,
    Source,
    Suppression,
)
from iceberg_core.secrets import SecretStore
from iceberg_core.tasks import SCAN_TASK_QUEUE
from prometheus_client import REGISTRY
from pydantic import SecretStr
from sqlalchemy import Engine as SAEngine
from sqlmodel import Session, select


@pytest.fixture(name="process_engine", autouse=True)
def process_engine_fixture(db_engine: SAEngine) -> Iterator[None]:
    """`run_once` opens its own session, so point the process engine at the test DB."""
    set_db_engine(db_engine)
    yield
    set_db_engine(None)


@pytest.fixture(name="run_round")
def run_round_fixture(secret_store: SecretStore) -> Callable[..., None]:
    """One maintenance round with settings supplied rather than read from the env.

    A round delivers queued notifications (#60) and applies retention (#73), so
    it needs settings and a secret store. Injecting them keeps these tests from
    depending on a configured deployment — no SMTP relay is needed to prove the
    scheduler fires, and the retention windows default to off, so none of these
    rounds can delete anything.
    """
    settings = ApiSettings(
        database_url="postgresql+psycopg://unused/unused",
        master_key=SecretStr("unused"),
    )

    def run(dispatcher: RecordingDispatcher, **kwargs: object) -> None:
        maintenance.run_once(dispatcher, settings=settings, store=secret_store, **kwargs)  # type: ignore[arg-type]

    return run


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
    session: Session,
    dispatcher: RecordingDispatcher,
    run_round: Callable[..., None],
) -> None:
    source = _source(session)
    schedule = Schedule(
        source_id=source.id,
        cron="*/5 * * * *",
        next_run_at=datetime.now(UTC) - timedelta(minutes=1),
    )
    session.add(schedule)
    session.commit()

    run_round(dispatcher)

    scans = session.exec(select(Scan)).all()
    assert len(scans) == 1
    assert scans[0].trigger.value == "scheduled"
    assert dispatcher.enqueued  # its discovery task was dispatched
    session.refresh(schedule)
    assert schedule.last_run_at is not None


def test_a_round_reclaims_expired_leases(
    session: Session,
    dispatcher: RecordingDispatcher,
    run_round: Callable[..., None],
) -> None:
    source = _source(session)
    scan = service.launch_scan(session, source, trigger=ScanTrigger.MANUAL, dispatcher=dispatcher)
    task = session.exec(select(ScanTask).where(ScanTask.scan_id == scan.id)).one()
    engine = Engine(name="dead", token_hash="unused")
    session.add(engine)
    session.commit()
    service.claim_task(session, task.id, engine.id, lease_seconds=1)
    dispatcher.enqueued.clear()

    run_round(dispatcher, now=datetime.now(UTC) + timedelta(minutes=10))

    session.refresh(task)
    assert task.status is ScanTaskStatus.QUEUED
    assert dispatcher.enqueued == [task.id]


def test_a_source_with_an_active_scan_is_skipped_not_double_scanned(
    session: Session,
    dispatcher: RecordingDispatcher,
    run_round: Callable[..., None],
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

    run_round(dispatcher)

    assert len(session.exec(select(Scan)).all()) == 1
    session.refresh(schedule)
    # Still advanced: the beat was handled, just not with a new scan.
    assert schedule.last_run_at is not None


def test_a_disabled_source_is_not_scanned_on_its_cadence(
    session: Session,
    dispatcher: RecordingDispatcher,
    run_round: Callable[..., None],
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

    run_round(dispatcher)

    assert session.exec(select(Scan)).all() == []


def test_a_round_redispatches_a_queued_task_whose_message_was_lost(
    session: Session,
    dispatcher: RecordingDispatcher,
    run_round: Callable[..., None],
) -> None:
    """A crash between commit and enqueue leaves a queued row with no message;
    the sweep is the only thing that will ever deliver it."""
    source = _source(session)
    scan = service.launch_scan(session, source, trigger=ScanTrigger.MANUAL, dispatcher=dispatcher)
    task = session.exec(select(ScanTask).where(ScanTask.scan_id == scan.id)).one()
    dispatcher.enqueued.clear()  # the launch enqueue is the message that "got lost"

    later = datetime.now(UTC) + timedelta(minutes=10)
    run_round(dispatcher, now=later)

    assert dispatcher.enqueued == [task.id]
    # Paced: the same round does not spam the queue on the next beat.
    dispatcher.enqueued.clear()
    run_round(dispatcher, now=later + timedelta(seconds=30))
    assert dispatcher.enqueued == []


def test_a_round_finalizes_a_scan_stranded_by_a_crash(
    session: Session,
    dispatcher: RecordingDispatcher,
    run_round: Callable[..., None],
) -> None:
    """All tasks terminal but the scan still active: the finalize sweep settles it,
    so the source is not blocked forever by the one-active-scan index."""
    source = _source(session)
    scan = service.launch_scan(session, source, trigger=ScanTrigger.MANUAL, dispatcher=dispatcher)
    task = session.exec(select(ScanTask).where(ScanTask.scan_id == scan.id)).one()
    service.complete_task(session, task, status=ScanTaskStatus.FAILED, error="engine died")
    session.commit()  # ...and the follow-up finalisation never ran

    run_round(dispatcher)

    session.refresh(scan)
    assert scan.status is ScanStatus.FAILED
    assert scan.finished_at is not None


def test_a_round_marks_an_engine_that_stopped_heartbeating_offline(
    session: Session,
    dispatcher: RecordingDispatcher,
    run_round: Callable[..., None],
) -> None:
    """An engine cannot report that it died, so silence is the only evidence.

    Without this every engine ever registered stays active forever: the fleet view
    shows a worker that died months ago as live, and `GET /rules` counts its rule
    pack as part of the detection surface currently in force (#58, #70).
    """
    now = datetime.now(UTC)
    dead = Engine(name="dead", token_hash="dead", last_heartbeat_at=now - timedelta(hours=4))
    live = Engine(name="live", token_hash="live", last_heartbeat_at=now - timedelta(seconds=30))
    never_started = Engine(name="minted", token_hash="minted")
    session.add_all([dead, live, never_started])
    session.commit()

    run_round(dispatcher, now=now)

    for engine in (dead, live, never_started):
        session.refresh(engine)
    assert dead.status is EngineStatus.OFFLINE
    assert live.status is EngineStatus.ACTIVE
    # Minted but never run: an operator has not started it, which is not a death.
    assert never_started.status is EngineStatus.ACTIVE


def test_an_engine_that_comes_back_is_active_again(
    session: Session,
    dispatcher: RecordingDispatcher,
    run_round: Callable[..., None],
) -> None:
    """The recovery branch in `record_heartbeat` only means something once
    something marks an engine offline in the first place."""
    now = datetime.now(UTC)
    engine = Engine(name="flaky", token_hash="flaky", last_heartbeat_at=now - timedelta(hours=4))
    session.add(engine)
    session.commit()
    run_round(dispatcher, now=now)

    record_heartbeat(session, engine, now=now)

    assert engine.status is EngineStatus.ACTIVE


def test_a_round_publishes_the_broker_backlog(
    session: Session,
    dispatcher: RecordingDispatcher,
    run_round: Callable[..., None],
) -> None:
    """`iceberg_queue_depth` is the one series an operator watches to tell "the
    fleet is busy" from "the fleet is gone", so something has to set it."""
    dispatcher.depth = 7

    run_round(dispatcher)

    assert REGISTRY.get_sample_value("iceberg_queue_depth", {"queue": SCAN_TASK_QUEUE}) == 7


def test_a_round_releases_findings_whose_suppression_expired(
    session: Session,
    dispatcher: RecordingDispatcher,
    run_round: Callable[..., None],
    make_finding: Callable[..., Finding],
) -> None:
    """Expiry is a property of the clock, so it cannot wait for the next scan.

    A source on a weekly cadence would otherwise keep a lapsed suppression in
    force for six days after the analyst said it should end (ADR 0008).
    """
    finding = make_finding(rule_id="generic-high-entropy")
    lapsed = Suppression(
        scope=SuppressionScope.RULE,
        pattern="generic-high-entropy",
        reason="silenced for a sprint",
        expires_at=datetime.now(UTC) - timedelta(hours=1),
    )
    session.add(lapsed)
    session.commit()
    finding.suppressed_at = datetime.now(UTC) - timedelta(days=14)
    finding.suppressed_by_id = lapsed.id
    session.add(finding)
    session.commit()

    run_round(dispatcher)

    session.refresh(finding)
    released = session.get(Finding, finding.id)
    assert released is not None
    assert released.suppressed_at is None
    assert released.suppressed_by_id is None


def test_a_lapsed_suppression_hands_over_to_another_that_still_covers_the_finding(
    session: Session,
    dispatcher: RecordingDispatcher,
    run_round: Callable[..., None],
    make_finding: Callable[..., Finding],
) -> None:
    """A finding covered by both an expiring rule and a permanent one must stay
    hidden when the first lapses — handed over, not popped into the active view
    until the next scan re-suppresses it (the courtesy the delete path extends)."""
    finding = make_finding(rule_id="generic-high-entropy")
    lapsed = Suppression(
        scope=SuppressionScope.RULE,
        pattern="generic-high-entropy",
        reason="silenced for a sprint",
        expires_at=datetime.now(UTC) - timedelta(hours=1),
    )
    permanent = Suppression(
        scope=SuppressionScope.PATH_GLOB,
        pattern="/space/DOCS/*",
        reason="known-benign space",
    )
    session.add_all([lapsed, permanent])
    session.commit()
    finding.suppressed_at = datetime.now(UTC) - timedelta(days=14)
    finding.suppressed_by_id = lapsed.id
    session.add(finding)
    session.commit()

    run_round(dispatcher)

    session.refresh(finding)
    assert finding.suppressed_at is not None  # still hidden
    assert finding.suppressed_by_id == permanent.id  # by the rule that still covers it
