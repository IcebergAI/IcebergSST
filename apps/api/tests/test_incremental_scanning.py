"""Scan modes, cursor lifecycle, and the reconciliation gate (#143, ADR 0013).

One property holds this together: **an incremental scan never auto-resolves.** It
deliberately did not look at unchanged content, so a finding it did not see is not
evidence of anything. Everything else here exists to make that safe to live with —
a cursor that only advances on complete evidence, a promotion rule that forces a
full scan whenever the watermark cannot be trusted, and an operator lever that
forces one on demand.

The promotion rule is what turns "incremental never resolves" from a hazard into a
guarantee: a schedule left on incremental forever still produces full scans, so
remediated findings still close.
"""

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from conftest import RecordingDispatcher
from fastapi.testclient import TestClient
from iceberg_api.scans import cursors, service
from iceberg_core.enums import (
    CursorInvalidationReason,
    EngineStatus,
    FindingResolution,
    FindingState,
    ScanMode,
    ScanStatus,
    ScanTaskKind,
    ScanTaskStatus,
    ScanTrigger,
    SourceType,
    UserRole,
)
from iceberg_core.models import (
    Engine,
    Finding,
    Scan,
    ScanTask,
    Source,
    SourceCursor,
)
from sqlmodel import Session, select

RULEPACK = "2026.07.1"


def _source(session: Session, **overrides: Any) -> Source:
    source = Source(
        name=overrides.pop("name", "confluence-prod"),
        type=SourceType.CONFLUENCE,
        connection={"base_url": "https://example.atlassian.net/wiki"},
        **overrides,
    )
    session.add(source)
    session.commit()
    session.refresh(source)
    return source


def _scan(session: Session, source: Source, **overrides: Any) -> Scan:
    scan = Scan(
        source_id=source.id,
        trigger=ScanTrigger.MANUAL,
        status=overrides.pop("status", ScanStatus.COMPLETED),
        rulepack_version=RULEPACK,
        source_configuration_version=source.updated_at,
        **overrides,
    )
    session.add(scan)
    session.commit()
    session.refresh(scan)
    return scan


def _cursor(session: Session, source: Source, scan: Scan, **overrides: Any) -> SourceCursor:
    cursor = SourceCursor(
        source_id=source.id,
        scope=overrides.pop("scope", "DOCS"),
        position=overrides.pop("position", {"version": "1", "modified": "2024-01-01"}),
        rulepack_version=overrides.pop("rulepack_version", RULEPACK),
        source_configuration_version=overrides.pop(
            "source_configuration_version", source.updated_at
        ),
        minted_by_scan_id=scan.id,
        minted_at=overrides.pop("minted_at", datetime.now(UTC)),
        **overrides,
    )
    session.add(cursor)
    session.commit()
    session.refresh(cursor)
    return cursor


def _engine(session: Session, version: str | None = RULEPACK) -> Engine:
    engine = Engine(
        name=f"engine-{uuid.uuid4().hex[:6]}",
        token_hash=uuid.uuid4().hex,
        status=EngineStatus.ACTIVE,
        rulepack={"version": version} if version else {},
    )
    session.add(engine)
    session.commit()
    return engine


def _launch(
    session: Session,
    source: Source,
    dispatcher: RecordingDispatcher,
    **kwargs: Any,
) -> Scan:
    defaults: dict[str, Any] = {
        "trigger": ScanTrigger.SCHEDULED,
        "dispatcher": dispatcher,
        "mode": ScanMode.INCREMENTAL,
        "rulepack_version": RULEPACK,
        "pepper_rotating": False,
    }
    return service.launch_scan(session, source, **(defaults | kwargs))


# ─── Promotion: when an incremental scan cannot be trusted ────────────────────


def test_an_incremental_request_with_a_valid_cursor_stays_incremental(
    session: Session, dispatcher: RecordingDispatcher
) -> None:
    source = _source(session)
    _cursor(session, source, _scan(session, source))

    scan = _launch(session, source, dispatcher)

    assert scan.mode is ScanMode.INCREMENTAL
    assert scan.promoted_from is None
    assert scan.incremental_baseline_at is not None


def test_a_source_with_no_cursor_is_promoted_to_full(
    session: Session, dispatcher: RecordingDispatcher
) -> None:
    """Nothing has been read, so nothing may be skipped."""
    scan = _launch(session, _source(session), dispatcher)

    assert scan.mode is ScanMode.FULL
    assert scan.promoted_from is ScanMode.INCREMENTAL
    assert scan.promotion_reason is CursorInvalidationReason.NO_CURSOR


def test_a_rulepack_change_promotes_to_full(
    session: Session, dispatcher: RecordingDispatcher
) -> None:
    """New rules must see content the old rules passed over."""
    source = _source(session)
    _cursor(session, source, _scan(session, source), rulepack_version="2026.06.1")

    scan = _launch(session, source, dispatcher)

    assert scan.mode is ScanMode.FULL
    assert scan.promotion_reason is CursorInvalidationReason.RULEPACK_CHANGED


def test_an_unknown_fleet_rulepack_promotes_to_full(
    session: Session, dispatcher: RecordingDispatcher
) -> None:
    """Unverifiable is not the same as equal — a rolling deploy is two answers."""
    source = _source(session)
    _cursor(session, source, _scan(session, source))

    scan = _launch(session, source, dispatcher, rulepack_version=None)

    assert scan.mode is ScanMode.FULL
    assert scan.promotion_reason is CursorInvalidationReason.RULEPACK_CHANGED


def test_a_source_configuration_change_promotes_to_full(
    session: Session, dispatcher: RecordingDispatcher
) -> None:
    """Scope filters moved, so the watermark covers different content."""
    source = _source(session)
    _cursor(
        session,
        source,
        _scan(session, source),
        source_configuration_version=datetime(2020, 1, 1, tzinfo=UTC),
    )

    scan = _launch(session, source, dispatcher)

    assert scan.promotion_reason is CursorInvalidationReason.SOURCE_CONFIGURATION_CHANGED


def test_a_pepper_rotation_promotes_to_full(
    session: Session, dispatcher: RecordingDispatcher
) -> None:
    """Every fingerprint moves, so nothing incremental reported would match."""
    source = _source(session)
    _cursor(session, source, _scan(session, source))

    scan = _launch(session, source, dispatcher, pepper_rotating=True)

    assert scan.promotion_reason is CursorInvalidationReason.PEPPER_ROTATING


def test_a_stale_cursor_forces_the_periodic_full_reconciliation(
    session: Session, dispatcher: RecordingDispatcher
) -> None:
    """The guarantee behind AC 4.

    An incremental scan never auto-resolves, so without this ceiling a source
    scheduled incrementally forever would never close a remediated finding.
    """
    source = _source(session, full_scan_interval_days=7)
    _cursor(
        session,
        source,
        _scan(session, source),
        minted_at=datetime.now(UTC) - timedelta(days=8),
    )

    scan = _launch(session, source, dispatcher)

    assert scan.mode is ScanMode.FULL
    assert scan.promotion_reason is CursorInvalidationReason.INTERVAL_ELAPSED


def test_a_promotion_retires_the_cursor_that_caused_it(
    session: Session, dispatcher: RecordingDispatcher
) -> None:
    """So the next scan does not re-evaluate the same doomed watermark."""
    source = _source(session)
    _cursor(session, source, _scan(session, source), rulepack_version="old")

    _launch(session, source, dispatcher)

    row = session.exec(select(SourceCursor)).one()
    assert row.invalidated_at is not None
    assert row.invalidation_reason is CursorInvalidationReason.RULEPACK_CHANGED


def test_a_full_request_is_never_examined_at_all(
    session: Session, dispatcher: RecordingDispatcher
) -> None:
    source = _source(session)
    _cursor(session, source, _scan(session, source))

    scan = _launch(session, source, dispatcher, mode=ScanMode.FULL)

    assert scan.mode is ScanMode.FULL
    assert scan.promoted_from is None
    assert scan.promotion_reason is None


# ─── The reconciliation gate (AC 4) ───────────────────────────────────────────


def _completed_scan_with_a_stale_finding(
    session: Session,
    dispatcher: RecordingDispatcher,
    *,
    mode: ScanMode,
) -> tuple[Scan, Finding]:
    """A source with an open finding from an earlier scan, plus a fresh scan of it
    that completed cleanly and did not see that finding."""
    source = _source(session)
    earlier = _scan(session, source)
    finding = Finding(
        source_id=source.id,
        fingerprint="a" * 64,
        rule_id="aws-access-key-id",
        rulepack_version=RULEPACK,
        resource_locator={"page_id": "1"},
        redacted_snippet="…",
        secret_hash="f" * 64,
        severity="high",
        state=FindingState.OPEN,
        first_seen_scan_id=earlier.id,
        last_seen_scan_id=earlier.id,
    )
    session.add(finding)

    scan = Scan(
        source_id=source.id,
        trigger=ScanTrigger.SCHEDULED,
        status=ScanStatus.RUNNING,
        mode=mode,
        rulepack_version=RULEPACK,
        source_configuration_version=source.updated_at,
    )
    session.add(scan)
    session.commit()

    task = ScanTask(
        scan_id=scan.id,
        kind=ScanTaskKind.FETCH,
        spec={"space_key": "DOCS"},
        status=ScanTaskStatus.COMPLETED,
        coverage={
            "version": "1",
            "phase": "fetch",
            "counts": {
                "requested": 1,
                "discovered": 1,
                "scanned": 1,
                "skipped": 0,
                "failed": 0,
            },
            "scope": {"requested": None, "discovered": 0, "gaps": 0},
            "reasons": [],
            "gaps": [],
            "gaps_omitted": 0,
        },
        cursor_proposal={"scope": "DOCS", "version": "1", "position": {"modified": "2024-06"}},
        finished_at=datetime.now(UTC),
    )
    session.add(task)
    session.commit()
    session.refresh(scan)
    session.refresh(finding)
    return scan, finding


def test_a_full_scan_auto_resolves_what_it_did_not_see(
    session: Session, dispatcher: RecordingDispatcher
) -> None:
    """The behaviour that must survive the change, unaltered."""
    scan, finding = _completed_scan_with_a_stale_finding(session, dispatcher, mode=ScanMode.FULL)

    service.finalize_and_reconcile(session, scan.id)

    session.refresh(finding)
    assert finding.state is FindingState.RESOLVED
    assert finding.resolution is FindingResolution.AUTO


def test_an_incremental_scan_resolves_nothing(
    session: Session, dispatcher: RecordingDispatcher
) -> None:
    """The single most important assertion in #143.

    Without this an incremental scan mass-resolves every finding outside its
    window on the first run, and the operator sees a source that "cleaned itself
    up" overnight.
    """
    scan, finding = _completed_scan_with_a_stale_finding(
        session, dispatcher, mode=ScanMode.INCREMENTAL
    )

    service.finalize_and_reconcile(session, scan.id)

    session.refresh(finding)
    assert finding.state is FindingState.OPEN
    assert finding.resolution is None


def test_an_incremental_scan_still_advances_its_cursor(
    session: Session, dispatcher: RecordingDispatcher
) -> None:
    scan, _finding = _completed_scan_with_a_stale_finding(
        session, dispatcher, mode=ScanMode.INCREMENTAL
    )

    service.finalize_and_reconcile(session, scan.id)

    row = session.exec(select(SourceCursor)).one()
    assert row.scope == "DOCS"
    assert row.position == {"version": "1", "modified": "2024-06"}
    assert row.rulepack_version == RULEPACK


def test_a_partial_scan_advances_no_cursor(
    session: Session, dispatcher: RecordingDispatcher
) -> None:
    """A scan that cannot be trusted to have read everything cannot say where the
    next one starts."""
    scan, _finding = _completed_scan_with_a_stale_finding(
        session, dispatcher, mode=ScanMode.INCREMENTAL
    )
    task = session.exec(select(ScanTask).where(ScanTask.scan_id == scan.id)).one()
    task.status = ScanTaskStatus.FAILED
    session.add(task)
    session.commit()

    service.finalize_and_reconcile(session, scan.id)

    assert session.exec(select(SourceCursor)).all() == []


# ─── Operator recovery (AC 3) ─────────────────────────────────────────────────


def test_an_analyst_can_see_which_scopes_have_a_watermark(
    client: TestClient, session: Session, login_as: Any, make_user: Any
) -> None:
    source = _source(session)
    _cursor(session, source, _scan(session, source))
    login_as(make_user(UserRole.ANALYST))

    response = client.get(f"/api/v1/sources/{source.id}/cursors")

    assert response.status_code == 200
    body = response.json()
    assert body["full_scan_interval_days"] == 7
    assert [row["scope"] for row in body["cursors"]] == ["DOCS"]


def test_the_position_itself_never_leaves_the_api(
    client: TestClient, session: Session, login_as: Any, make_user: Any
) -> None:
    """A position may hold a provider change token, which is bearer-ish for a place
    in a result set."""
    source = _source(session)
    _cursor(session, source, _scan(session, source), position={"token": "cursor-secret"})
    login_as(make_user(UserRole.ANALYST))

    response = client.get(f"/api/v1/sources/{source.id}/cursors")

    assert "cursor-secret" not in response.text


def test_an_admin_can_force_the_next_scan_to_be_full(
    client: TestClient, session: Session, login_as: Any, make_user: Any
) -> None:
    source = _source(session)
    _cursor(session, source, _scan(session, source))
    headers = login_as(make_user(UserRole.ADMIN))

    response = client.delete(f"/api/v1/sources/{source.id}/cursors", headers=headers)

    assert response.status_code == 200
    assert response.json()["invalidated"] == 1
    row = session.exec(select(SourceCursor)).one()
    assert row.invalidation_reason is CursorInvalidationReason.OPERATOR_REQUESTED


def test_an_analyst_cannot_drop_cursors(
    client: TestClient, session: Session, login_as: Any, make_user: Any
) -> None:
    source = _source(session)
    headers = login_as(make_user(UserRole.ANALYST))

    response = client.delete(f"/api/v1/sources/{source.id}/cursors", headers=headers)

    assert response.status_code == 403


@pytest.mark.parametrize("method", ["get", "delete"])
def test_an_unknown_source_is_a_404(
    client: TestClient, login_as: Any, make_user: Any, method: str
) -> None:
    headers = login_as(make_user(UserRole.ADMIN))

    response = getattr(client, method)(f"/api/v1/sources/{uuid.uuid4()}/cursors", headers=headers)

    assert response.status_code == 404


# ─── The fleet's rule pack ────────────────────────────────────────────────────


def test_one_agreeing_fleet_reports_its_version(session: Session) -> None:
    _engine(session)
    _engine(session)

    assert cursors.fleet_rulepack_version(session) == RULEPACK


def test_a_rolling_deploy_reports_nothing(session: Session) -> None:
    """Two correct answers at once, so no watermark can be validated against one."""
    _engine(session)
    _engine(session, version="2026.08.1")

    assert cursors.fleet_rulepack_version(session) is None


def test_a_silent_fleet_reports_nothing(session: Session) -> None:
    _engine(session, version=None)

    assert cursors.fleet_rulepack_version(session) is None
