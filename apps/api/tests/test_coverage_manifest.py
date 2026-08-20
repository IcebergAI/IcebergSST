"""Coverage manifests are complete, deterministic, and privacy-bounded (#148)."""

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from conftest import RecordingDispatcher
from fastapi.testclient import TestClient
from iceberg_api.scans import coverage as coverage_service
from iceberg_api.scans import service
from iceberg_api.scans.coverage import failure_report
from iceberg_core.enums import (
    CoverageReason,
    CursorInvalidationReason,
    ScanMode,
    ScanStatus,
    ScanTaskKind,
    ScanTaskStatus,
    ScanTrigger,
    SourceType,
    UserRole,
)
from iceberg_core.models import Scan, ScanTask, Source, User
from sqlmodel import Session, select


def _source(session: Session, *, marker: str = "ordinary") -> Source:
    source = Source(
        name=f"confluence-{marker}",
        type=SourceType.CONFLUENCE,
        connection={
            "base_url": f"https://{marker}.example.test",
            "spaces": [marker],
        },
    )
    session.add(source)
    session.commit()
    session.refresh(source)
    return source


def _coverage(
    phase: ScanTaskKind,
    *,
    scanned: int = 0,
    skipped: int = 0,
    failed: int = 0,
    scope_requested: int | None = None,
    scope_discovered: int = 0,
    scope_gaps: int = 0,
    reason: CoverageReason = CoverageReason.UNSUPPORTED_TYPE,
    reference: str | None = None,
) -> dict[str, Any]:
    total = scanned + skipped + failed
    reasons: list[dict[str, Any]] = []
    gaps: list[dict[str, Any]] = []
    if skipped:
        reasons.append({"outcome": "skipped", "reason": reason.value, "count": skipped})
    if failed:
        reasons.append({"outcome": "failed", "reason": reason.value, "count": failed})
    if scope_gaps:
        reasons.append({"outcome": "scope_gap", "reason": reason.value, "count": scope_gaps})
    if reference is not None:
        outcome = "scope_gap" if scope_gaps else ("failed" if failed else "skipped")
        kind = "scope" if scope_gaps else "attachment"
        gaps.append(
            {
                "kind": kind,
                "outcome": outcome,
                "reason": reason.value,
                "reference": reference,
            }
        )
    return {
        "version": "1",
        "phase": phase.value,
        "counts": {
            "requested": total,
            "discovered": total,
            "scanned": scanned,
            "skipped": skipped,
            "failed": failed,
        },
        "scope": {
            "requested": scope_requested,
            "discovered": scope_discovered,
            "gaps": scope_gaps,
        },
        "reasons": reasons,
        "gaps": gaps,
        "gaps_omitted": skipped + failed + scope_gaps - len(gaps),
    }


def _terminal_scan(
    session: Session,
    source: Source,
    status: ScanStatus,
    coverage: dict[str, Any],
    *,
    finished_at: datetime | None = None,
) -> Scan:
    finished = finished_at or datetime.now(UTC)
    scan = Scan(
        source_id=source.id,
        trigger=ScanTrigger.MANUAL,
        status=status,
        started_at=finished - timedelta(minutes=1),
        finished_at=finished,
        source_configuration_version=source.updated_at,
    )
    session.add(scan)
    session.flush()
    session.add(
        ScanTask(
            scan_id=scan.id,
            kind=ScanTaskKind.FETCH,
            status={
                ScanStatus.COMPLETED: ScanTaskStatus.COMPLETED,
                ScanStatus.PARTIAL: ScanTaskStatus.FAILED,
                ScanStatus.FAILED: ScanTaskStatus.FAILED,
                ScanStatus.CANCELLED: ScanTaskStatus.CANCELLED,
            }[status],
            coverage=coverage,
            finished_at=finished,
            spec={"private": "must-not-export"},
            error="private-task-error-must-not-export",
        )
    )
    session.commit()
    session.refresh(scan)
    return scan


@pytest.mark.parametrize(
    ("scan_status", "report", "coverage_state"),
    [
        (ScanStatus.COMPLETED, _coverage(ScanTaskKind.FETCH, scanned=2), "complete"),
        (
            ScanStatus.COMPLETED,
            _coverage(ScanTaskKind.FETCH, scanned=1, skipped=1),
            "partial",
        ),
        (
            ScanStatus.PARTIAL,
            _coverage(
                ScanTaskKind.FETCH,
                scanned=1,
                failed=1,
                reason=CoverageReason.PERMISSION_DENIED,
            ),
            "partial",
        ),
        (
            ScanStatus.FAILED,
            failure_report(ScanTaskKind.FETCH, CoverageReason.RATE_LIMITED),
            "failed",
        ),
        (
            ScanStatus.CANCELLED,
            failure_report(ScanTaskKind.FETCH, CoverageReason.CANCELLED),
            "cancelled",
        ),
    ],
)
def test_every_terminal_state_has_an_explicit_manifest(
    client: TestClient,
    session: Session,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
    scan_status: ScanStatus,
    report: dict[str, Any],
    coverage_state: str,
) -> None:
    login_as(make_user(UserRole.VIEWER))
    scan = _terminal_scan(session, _source(session, marker=scan_status.value), scan_status, report)

    response = client.get(f"/api/v1/scans/{scan.id}/coverage")

    assert response.status_code == 200
    body = response.json()
    assert body["manifest_version"] == "2"
    assert body["scan_status"] == scan_status.value
    assert body["coverage_state"] == coverage_state
    assert body["task_counts"]["total"] == 1
    assert body["task_counts"]["unreported"] == 0


def test_terminal_manifest_is_frozen_in_the_lifecycle_transaction(
    session: Session,
    dispatcher: RecordingDispatcher,
) -> None:
    source = _source(session, marker="frozen")
    scan = service.launch_scan(
        session,
        source,
        trigger=ScanTrigger.MANUAL,
        dispatcher=dispatcher,
    )
    task = session.exec(select(ScanTask).where(ScanTask.scan_id == scan.id)).one()
    service.complete_task(
        session,
        task,
        status=ScanTaskStatus.COMPLETED,
        coverage=_coverage(
            ScanTaskKind.DISCOVERY,
            scope_requested=0,
            scope_discovered=0,
        ),
    )
    session.commit()

    assert service.finalize_and_reconcile(session, scan.id) is ScanStatus.COMPLETED
    session.refresh(scan)
    frozen = dict(scan.coverage_manifest)

    assert frozen["coverage_state"] == "complete"
    assert service.finalize_and_reconcile(session, scan.id) is None
    session.refresh(scan)
    assert scan.coverage_manifest == frozen


def test_export_is_byte_stable_and_contains_no_source_or_task_content(
    client: TestClient,
    session: Session,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    marker = "AKIA0123456789ABCDEF-private-page-path-and-filename"
    login_as(make_user(UserRole.VIEWER))
    source = _source(session, marker=marker)
    report = _coverage(
        ScanTaskKind.FETCH,
        failed=1,
        reason=CoverageReason.PARSE_ERROR,
        reference="a" * 64,
    )
    scan = _terminal_scan(session, source, ScanStatus.PARTIAL, report)
    scan.error = f"scan-error-{marker}"
    session.commit()
    url = f"/api/v1/scans/{scan.id}/coverage/export"

    first = client.get(url)
    second = client.get(url)

    assert first.status_code == 200
    assert first.content == second.content
    assert first.headers["cache-control"] == "no-store"
    assert str(scan.id) in first.headers["content-disposition"]
    text = first.text
    assert marker not in text
    assert "private-task-error-must-not-export" not in text
    assert "must-not-export" not in text
    assert "a" * 64 in text  # opaque HMAC references are the only drill-down id


def test_scan_manifest_bounds_references_without_losing_exact_counts(
    client: TestClient,
    session: Session,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    login_as(make_user(UserRole.VIEWER))
    source = _source(session, marker="bounded")
    first = _coverage(
        ScanTaskKind.FETCH,
        failed=1,
        reason=CoverageReason.SIZE_LIMIT,
        reference="a" * 64,
    )
    scan = _terminal_scan(session, source, ScanStatus.PARTIAL, first)
    session.add(
        ScanTask(
            scan_id=scan.id,
            kind=ScanTaskKind.FETCH,
            status=ScanTaskStatus.FAILED,
            coverage=_coverage(
                ScanTaskKind.FETCH,
                failed=1,
                reason=CoverageReason.SIZE_LIMIT,
                reference="b" * 64,
            ),
        )
    )
    session.commit()
    monkeypatch.setattr(coverage_service, "MAX_COVERAGE_GAP_REFERENCES", 1)

    body = client.get(f"/api/v1/scans/{scan.id}/coverage").json()

    assert body["counts"]["failed"] == 2
    assert body["reasons"] == [{"outcome": "failed", "reason": "size_limit", "count": 2}]
    assert len(body["gaps"]) == 1
    assert body["gaps_omitted"] == 1


def test_missing_old_engine_report_is_never_presented_as_clean(
    client: TestClient,
    session: Session,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    login_as(make_user(UserRole.VIEWER))
    scan = _terminal_scan(
        session,
        _source(session, marker="legacy"),
        ScanStatus.COMPLETED,
        {},
    )

    body = client.get(f"/api/v1/scans/{scan.id}/coverage").json()

    assert body["coverage_state"] == "partial"
    assert body["task_counts"]["unreported"] == 1
    assert body["reasons"] == [{"outcome": "scope_gap", "reason": "unreported", "count": 1}]


def test_source_coverage_uses_latest_terminal_scan_and_ignores_newer_active_scan(
    client: TestClient,
    session: Session,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    login_as(make_user(UserRole.VIEWER))
    source = _source(session, marker="latest")
    terminal = _terminal_scan(
        session,
        source,
        ScanStatus.COMPLETED,
        _coverage(ScanTaskKind.FETCH, scanned=3),
        finished_at=datetime.now(UTC) - timedelta(minutes=2),
    )
    active = Scan(
        source_id=source.id,
        trigger=ScanTrigger.MANUAL,
        status=ScanStatus.RUNNING,
        source_configuration_version=source.updated_at,
    )
    session.add(active)
    session.commit()

    response = client.get(f"/api/v1/sources/{source.id}/coverage")

    assert response.status_code == 200
    assert response.json()["scan_id"] == str(terminal.id)
    assert response.json()["counts"]["scanned"] == 3


def test_active_scan_has_no_manifest_yet_and_coverage_requires_authentication(
    client: TestClient,
    session: Session,
    dispatcher: RecordingDispatcher,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    scan = service.launch_scan(
        session,
        _source(session, marker="active"),
        trigger=ScanTrigger.MANUAL,
        dispatcher=dispatcher,
    )
    url = f"/api/v1/scans/{scan.id}/coverage"

    assert client.get(url).status_code == 401
    login_as(make_user(UserRole.VIEWER))
    assert client.get(url).status_code == 409


def test_source_configuration_is_versioned_and_edits_are_refused_while_active(
    client: TestClient,
    session: Session,
    dispatcher: RecordingDispatcher,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    headers = login_as(make_user(UserRole.ADMIN))
    source = _source(session, marker="versioned")
    original_connection = dict(source.connection)
    scan = service.launch_scan(
        session,
        source,
        trigger=ScanTrigger.MANUAL,
        dispatcher=dispatcher,
    )

    response = client.patch(
        f"/api/v1/sources/{source.id}",
        json={"connection": {"base_url": "https://changed.example.test"}},
        headers=headers,
    )

    assert response.status_code == 409
    session.refresh(source)
    session.refresh(scan)
    assert source.connection == original_connection
    assert scan.source_configuration_version == source.updated_at


def test_cancel_freezes_cancelled_evidence_for_unfinished_tasks(
    session: Session,
    dispatcher: RecordingDispatcher,
) -> None:
    scan = service.launch_scan(
        session,
        _source(session, marker="cancel"),
        trigger=ScanTrigger.MANUAL,
        dispatcher=dispatcher,
    )

    service.cancel_scan(session, scan)
    task = session.exec(select(ScanTask).where(ScanTask.scan_id == scan.id)).one()
    session.refresh(scan)

    assert task.coverage["reasons"][0]["reason"] == "cancelled"
    assert scan.coverage_manifest["coverage_state"] == "cancelled"
    assert scan.coverage_manifest["task_counts"]["cancelled"] == 1


def test_cancelling_keeps_the_coverage_a_task_had_already_reported(
    session: Session,
    dispatcher: RecordingDispatcher,
) -> None:
    """A batching fetch task has coverage describing objects the API demonstrably
    ingested findings for. Cancellation used to overwrite it with a zero-count
    failure report, so a cancelled scan's manifest said the task read nothing
    (#197). The gap is merged on instead: what was read stays read, and the
    blind spot is added beside it."""
    scan = service.launch_scan(
        session,
        _source(session, marker="cancel-merge"),
        trigger=ScanTrigger.MANUAL,
        dispatcher=dispatcher,
    )
    # A fetch task partway through: seven objects read and reported in batches,
    # which is exactly the coverage a cancellation must not throw away.
    task = ScanTask(
        scan_id=scan.id,
        kind=ScanTaskKind.FETCH,
        status=ScanTaskStatus.RUNNING,
        spec={"label": "space DOCS"},
        coverage=_coverage(ScanTaskKind.FETCH, scanned=7),
    )
    session.add(task)
    session.commit()

    service.cancel_scan(session, scan)
    session.refresh(task)

    assert task.coverage["counts"]["scanned"] == 7
    assert task.coverage["scope"]["gaps"] == 1
    assert [entry["reason"] for entry in task.coverage["reasons"]] == ["cancelled"]


def test_a_manifest_says_which_mode_the_scan_ran_in(
    client: TestClient, session: Session, login_as: Any, make_user: Any
) -> None:
    """A `complete` incremental manifest means "everything that changed", not
    "everything" — so an exporter has to be able to tell the two apart (#143)."""
    login_as(make_user(UserRole.VIEWER))
    scan = _terminal_scan(
        session,
        _source(session, marker="mode"),
        ScanStatus.COMPLETED,
        _coverage(ScanTaskKind.FETCH, scanned=1),
    )
    scan.mode = ScanMode.INCREMENTAL
    scan.incremental_baseline_at = datetime(2026, 8, 1, tzinfo=UTC)
    session.add(scan)
    session.commit()

    body = client.get(f"/api/v1/scans/{scan.id}/coverage").json()

    assert body["scan_mode"] == "incremental"
    assert body["incremental_baseline"].startswith("2026-08-01")


def test_a_promoted_scan_explains_itself_from_its_own_manifest(
    client: TestClient, session: Session, login_as: Any, make_user: Any
) -> None:
    login_as(make_user(UserRole.VIEWER))
    scan = _terminal_scan(
        session,
        _source(session, marker="promo"),
        ScanStatus.COMPLETED,
        _coverage(ScanTaskKind.FETCH, scanned=1),
    )
    scan.promoted_from = ScanMode.INCREMENTAL
    scan.promotion_reason = CursorInvalidationReason.INTERVAL_ELAPSED
    session.add(scan)
    session.commit()

    body = client.get(f"/api/v1/scans/{scan.id}/coverage").json()

    assert body["scan_mode"] == "full"
    assert body["promoted_from"] == "incremental"
    assert body["promotion_reason"] == "interval_elapsed"
