"""Reading and cancelling scans (#68)."""

from collections.abc import Callable

import pytest
from conftest import RecordingDispatcher
from fastapi.testclient import TestClient
from iceberg_api.scans import service
from iceberg_api.scans.reconcile import reconcile_scan
from iceberg_core.enums import (
    ScanStatus,
    ScanTaskStatus,
    ScanTrigger,
    SourceType,
    UserRole,
)
from iceberg_core.models import Scan, ScanTask, Source, User
from sqlmodel import Session, select

SCANS = "/api/v1/scans"


def _source(session: Session, name: str = "confluence-prod") -> Source:
    source = Source(
        name=name,
        type=SourceType.CONFLUENCE,
        connection={"base_url": "https://example.atlassian.net/wiki"},
    )
    session.add(source)
    session.commit()
    return source


def _launch(session: Session, dispatcher: RecordingDispatcher, source: Source) -> Scan:
    return service.launch_scan(session, source, trigger=ScanTrigger.MANUAL, dispatcher=dispatcher)


def test_any_role_can_list_and_read_scans(
    client: TestClient,
    session: Session,
    dispatcher: RecordingDispatcher,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """ "Why does this finding exist" is answered by the scan that found it."""
    login_as(make_user(UserRole.VIEWER))
    scan = _launch(session, dispatcher, _source(session))

    listed = client.get(SCANS)
    detail = client.get(f"{SCANS}/{scan.id}")

    assert listed.status_code == 200
    assert [item["id"] for item in listed.json()["items"]] == [str(scan.id)]
    assert detail.json()["trigger"] == "manual"
    assert detail.json()["status"] == "queued"


def test_reading_scans_requires_a_session(client: TestClient) -> None:
    assert client.get(SCANS).status_code == 401


def test_scans_can_be_filtered_by_source_status_and_liveness(
    client: TestClient,
    session: Session,
    dispatcher: RecordingDispatcher,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    login_as(make_user(UserRole.ANALYST))
    first, second = _source(session, "one"), _source(session, "two")
    running = _launch(session, dispatcher, first)
    finished = _launch(session, dispatcher, second)
    finished.status = ScanStatus.COMPLETED
    session.commit()

    by_source = client.get(SCANS, params={"source_id": str(first.id)}).json()
    by_status = client.get(SCANS, params={"status": "completed"}).json()
    live = client.get(SCANS, params={"active": True}).json()

    assert [item["id"] for item in by_source["items"]] == [str(running.id)]
    assert [item["id"] for item in by_status["items"]] == [str(finished.id)]
    assert [item["id"] for item in live["items"]] == [str(running.id)]


def test_scan_tasks_are_visible_without_their_specs(
    client: TestClient,
    session: Session,
    dispatcher: RecordingDispatcher,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """A spec names the resources being fetched — more than a status view needs."""
    login_as(make_user(UserRole.VIEWER))
    scan = _launch(session, dispatcher, _source(session))
    task = session.exec(select(ScanTask)).one()
    task.spec = {"page_ids": ["secret-page-id"]}
    session.commit()

    body = client.get(f"{SCANS}/{scan.id}/tasks").json()

    assert [item["kind"] for item in body] == ["discovery"]
    assert "secret-page-id" not in str(body)
    assert "spec" not in body[0]


def test_scans_paginate_with_a_stable_cursor(
    client: TestClient,
    session: Session,
    dispatcher: RecordingDispatcher,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    login_as(make_user(UserRole.ANALYST))
    for index in range(5):
        source = _source(session, f"source-{index}")
        _launch(session, dispatcher, source)

    seen: list[str] = []
    cursor: str | None = None
    for _ in range(10):
        params = {"limit": 2} | ({"cursor": cursor} if cursor else {})
        body = client.get(SCANS, params=params).json()
        seen.extend(item["id"] for item in body["items"])
        cursor = body["next_cursor"]
        if cursor is None:
            break

    assert len(seen) == len(set(seen)) == 5


def test_cancelling_a_scan_stops_its_queued_tasks_from_being_leased(
    client: TestClient,
    session: Session,
    dispatcher: RecordingDispatcher,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
    engine_credential: tuple[object, dict[str, str]],
) -> None:
    headers = login_as(make_user(UserRole.ANALYST))
    scan = _launch(session, dispatcher, _source(session))
    task = session.exec(select(ScanTask)).one()
    _, engine_headers = engine_credential

    response = client.post(f"{SCANS}/{scan.id}/cancel", headers=headers)

    assert response.status_code == 200
    assert response.json()["status"] == "cancelled"
    session.refresh(task)
    assert task.status is ScanTaskStatus.CANCELLED
    # An engine discovers the cancellation when its lease is refused (ADR 0009).
    lease = client.post(f"/api/v1/scan-tasks/{task.id}/lease", headers=engine_headers)
    assert lease.status_code == 409


def test_a_viewer_cannot_cancel_a_scan(
    client: TestClient,
    session: Session,
    dispatcher: RecordingDispatcher,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    headers = login_as(make_user(UserRole.VIEWER))
    scan = _launch(session, dispatcher, _source(session))

    assert client.post(f"{SCANS}/{scan.id}/cancel", headers=headers).status_code == 403


def test_cancelling_requires_a_csrf_token(
    client: TestClient,
    session: Session,
    dispatcher: RecordingDispatcher,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    login_as(make_user(UserRole.ANALYST))
    scan = _launch(session, dispatcher, _source(session))

    assert client.post(f"{SCANS}/{scan.id}/cancel").status_code == 403
    session.refresh(scan)
    assert scan.status is ScanStatus.QUEUED


def test_cancelling_a_finished_scan_is_a_conflict(
    client: TestClient,
    session: Session,
    dispatcher: RecordingDispatcher,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """The caller believes something is running; telling them beats pretending."""
    headers = login_as(make_user(UserRole.ANALYST))
    scan = _launch(session, dispatcher, _source(session))
    scan.status = ScanStatus.COMPLETED
    session.commit()

    assert client.post(f"{SCANS}/{scan.id}/cancel", headers=headers).status_code == 409


def test_a_cancelled_scan_never_reconciles(
    session: Session, dispatcher: RecordingDispatcher
) -> None:
    """It did not see the whole source, so it may not resolve anything (ADR 0009 §4)."""
    scan = _launch(session, dispatcher, _source(session))
    service.cancel_scan(session, scan)

    assert reconcile_scan(session, scan) is None


@pytest.mark.parametrize("status", [ScanStatus.PARTIAL, ScanStatus.FAILED])
def test_only_a_completed_scan_may_reconcile(
    session: Session, dispatcher: RecordingDispatcher, status: ScanStatus
) -> None:
    scan = _launch(session, dispatcher, _source(session))
    scan.status = status
    session.commit()

    assert reconcile_scan(session, scan) is None


def test_an_unknown_scan_is_a_404(
    client: TestClient,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    headers = login_as(make_user(UserRole.ANALYST))
    missing = "00000000-0000-4000-8000-000000000000"

    assert client.get(f"{SCANS}/{missing}").status_code == 404
    assert client.get(f"{SCANS}/{missing}/tasks").status_code == 404
    assert client.post(f"{SCANS}/{missing}/cancel", headers=headers).status_code == 404
