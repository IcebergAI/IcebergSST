"""The schema, exercised through the shared session fixture."""

from datetime import UTC, datetime, timedelta

import pytest
from iceberg_core.enums import (
    FindingEventKind,
    FindingState,
    ScanStatus,
    ScanTaskKind,
    ScanTrigger,
    Severity,
    SourceType,
    SuppressionScope,
    UserRole,
)
from iceberg_core.models import (
    Engine,
    Finding,
    FindingEvent,
    NotificationChannel,
    Scan,
    ScanTask,
    Schedule,
    Source,
    Suppression,
    User,
)
from sqlalchemy.exc import IntegrityError, StatementError
from sqlmodel import Session, select


def _source(session: Session, name: str = "confluence-prod") -> Source:
    source = Source(
        name=name,
        type=SourceType.CONFLUENCE,
        connection={"base_url": "https://example.atlassian.net", "spaces": ["ENG", "OPS"]},
        credential_ref="envkey:1:credential:abcdef",
    )
    session.add(source)
    session.commit()
    return source


def _scan(session: Session, source: Source, status: ScanStatus = ScanStatus.COMPLETED) -> Scan:
    scan = Scan(source_id=source.id, trigger=ScanTrigger.MANUAL, status=status)
    session.add(scan)
    session.commit()
    return scan


def _finding(session: Session, source: Source, scan: Scan, fingerprint: str) -> Finding:
    finding = Finding(
        source_id=source.id,
        fingerprint=fingerprint,
        rule_id="aws-access-key-id",
        rulepack_version="2026.07.1",
        resource_locator={"page_id": "12345", "line": 42},
        redacted_snippet="aws_access_key_id = AKIA…[16 chars redacted]",
        secret_hash="f" * 64,
        severity=Severity.HIGH,
        first_seen_scan_id=scan.id,
        last_seen_scan_id=scan.id,
    )
    session.add(finding)
    session.commit()
    return finding


def test_a_source_round_trips_including_its_json_connection(session: Session) -> None:
    source = _source(session)
    session.expire_all()

    stored = session.exec(select(Source)).one()

    assert stored.id == source.id
    assert stored.type is SourceType.CONFLUENCE
    assert stored.connection["spaces"] == ["ENG", "OPS"]
    assert stored.enabled is True
    # SQLite has no timezone-aware storage, so a round trip here comes back naive
    # even though the column is TIMESTAMPTZ on Postgres. What matters for the test
    # is that the value survives; the aware-UTC default is covered in test_models_base.
    assert stored.created_at is not None


def test_enum_columns_reject_values_outside_the_vocabulary(session: Session) -> None:
    """VARCHAR-backed enums still validate — the value never reaches the table."""
    session.add(Source(name="bad", type="dropbox"))  # a value no rule pack knows

    with pytest.raises(StatementError, match="not among the defined enum values"):
        session.commit()


def test_a_fingerprint_is_unique_within_a_source_but_not_across_sources(
    session: Session,
) -> None:
    """Identity is per source (ADR 0006): the same key in two systems is two findings."""
    first_source = _source(session, "confluence-prod")
    second_source = _source(session, "jira-prod")
    first_scan = _scan(session, first_source)
    second_scan = _scan(session, second_source)

    _finding(session, first_source, first_scan, "a" * 64)
    _finding(session, second_source, second_scan, "a" * 64)  # same fingerprint, other source

    with pytest.raises(IntegrityError):
        _finding(session, first_source, first_scan, "a" * 64)


def test_triage_state_and_audit_events_hang_off_a_finding(session: Session) -> None:
    source = _source(session)
    scan = _scan(session, source)
    finding = _finding(session, source, scan, "b" * 64)
    analyst = User(
        oidc_subject="oidc|1", email="a@example.test", display_name="A", role=UserRole.ANALYST
    )
    session.add(analyst)
    session.commit()

    finding.state = FindingState.FALSE_POSITIVE
    session.add(
        FindingEvent(
            finding_id=finding.id,
            actor_id=analyst.id,
            kind=FindingEventKind.STATE_CHANGE,
            from_value=FindingState.OPEN.value,
            to_value=FindingState.FALSE_POSITIVE.value,
            comment="example in a runbook",
        )
    )
    session.commit()

    events = session.exec(select(FindingEvent)).all()
    assert len(events) == 1
    assert events[0].kind is FindingEventKind.STATE_CHANGE
    assert session.exec(select(Finding)).one().state is FindingState.FALSE_POSITIVE


def test_updated_at_advances_on_change_and_created_at_does_not(session: Session) -> None:
    source = _source(session)
    created_at, first_updated_at = source.created_at, source.updated_at

    source.enabled = False
    session.commit()

    assert source.created_at == created_at
    assert source.updated_at >= first_updated_at


def test_scan_tasks_and_engines_wire_up(session: Session) -> None:
    source = _source(session)
    scan = _scan(session, source, ScanStatus.RUNNING)
    engine = Engine(name="engine-1", token_hash="c" * 64, version="0.1.0")
    session.add(engine)
    session.commit()

    task = ScanTask(
        scan_id=scan.id,
        kind=ScanTaskKind.FETCH,
        spec={"page_ids": ["1", "2"]},
        engine_id=engine.id,
        lease_expires_at=datetime.now(UTC) + timedelta(minutes=5),
        attempts=1,
    )
    session.add(task)
    session.commit()

    stored = session.exec(select(ScanTask)).one()
    assert stored.kind is ScanTaskKind.FETCH
    assert stored.spec["page_ids"] == ["1", "2"]
    assert stored.engine_id == engine.id


def test_schedules_suppressions_and_channels_persist(session: Session) -> None:
    source = _source(session)
    session.add(Schedule(source_id=source.id, cron="0 3 * * *"))
    session.add(
        Suppression(
            scope=SuppressionScope.PATH_GLOB,
            pattern="ENG/test-fixtures/**",
            source_id=source.id,
            reason="deliberate fixtures",
            expires_at=datetime.now(UTC) + timedelta(days=30),
        )
    )
    session.add(
        NotificationChannel(
            name="secops-webhook",
            type="webhook",  # a StrEnum accepts its own value
            config={"url": "https://hooks.example.test/iceberg"},
            event_filter={"min_severity": "high"},
        )
    )
    session.commit()

    assert session.exec(select(Schedule)).one().cron == "0 3 * * *"
    assert session.exec(select(Suppression)).one().scope is SuppressionScope.PATH_GLOB
    assert session.exec(select(NotificationChannel)).one().enabled is True


def test_a_finding_event_has_no_updated_at_because_it_is_append_only() -> None:
    assert "updated_at" not in FindingEvent.model_fields
