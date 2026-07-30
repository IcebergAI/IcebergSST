"""Launching scans and fanning them out (#34 — ADR 0009)."""

from collections.abc import Callable

import pytest
from conftest import RecordingDispatcher
from fastapi.testclient import TestClient
from iceberg_api.scans import service
from iceberg_core.enums import (
    ScanStatus,
    ScanTaskKind,
    ScanTaskStatus,
    ScanTrigger,
    SourceType,
    UserRole,
)
from iceberg_core.models import Scan, ScanTask, Source, User
from sqlmodel import Session, select

SOURCES = "/api/v1/sources"


def _source(session: Session, name: str = "confluence-prod", *, enabled: bool = True) -> Source:
    source = Source(
        name=name,
        type=SourceType.CONFLUENCE,
        connection={"base_url": "https://example.atlassian.net/wiki"},
        enabled=enabled,
    )
    session.add(source)
    session.commit()
    return source


def test_triggering_a_scan_creates_one_discovery_task_and_dispatches_it(
    client: TestClient,
    session: Session,
    dispatcher: RecordingDispatcher,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """Two-phase scans: the API never enumerates anything itself (ADR 0009 §1)."""
    headers = login_as(make_user(UserRole.ANALYST))
    source = _source(session)

    response = client.post(f"{SOURCES}/{source.id}/scan", headers=headers)

    assert response.status_code == 202
    assert response.json()["status"] == "queued"
    tasks = session.exec(select(ScanTask)).all()
    assert len(tasks) == 1
    assert tasks[0].kind is ScanTaskKind.DISCOVERY
    assert tasks[0].spec == {}
    # The message carries the id only; the payload comes from the lease.
    assert dispatcher.enqueued == [tasks[0].id]


def test_a_second_scan_of_the_same_source_is_refused(
    client: TestClient,
    session: Session,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """The partial unique index decides, so racing replicas get the same answer."""
    headers = login_as(make_user(UserRole.ANALYST))
    source = _source(session)
    client.post(f"{SOURCES}/{source.id}/scan", headers=headers)

    response = client.post(f"{SOURCES}/{source.id}/scan", headers=headers)

    assert response.status_code == 409
    assert "active scan" in response.text
    assert len(session.exec(select(Scan)).all()) == 1


def test_a_finished_scan_frees_the_source_for_another(
    client: TestClient,
    session: Session,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    headers = login_as(make_user(UserRole.ANALYST))
    source = _source(session)
    client.post(f"{SOURCES}/{source.id}/scan", headers=headers)
    first = session.exec(select(Scan)).one()
    first.status = ScanStatus.COMPLETED
    session.commit()

    assert client.post(f"{SOURCES}/{source.id}/scan", headers=headers).status_code == 202


def test_a_disabled_source_cannot_be_scanned(
    client: TestClient,
    session: Session,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    headers = login_as(make_user(UserRole.ANALYST))
    source = _source(session, enabled=False)

    assert client.post(f"{SOURCES}/{source.id}/scan", headers=headers).status_code == 409


def test_a_viewer_cannot_launch_a_scan(
    client: TestClient,
    session: Session,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """Running a scan is analyst work (ADR 0005)."""
    headers = login_as(make_user(UserRole.VIEWER))
    source = _source(session)

    assert client.post(f"{SOURCES}/{source.id}/scan", headers=headers).status_code == 403


def test_launching_a_scan_requires_a_csrf_token(
    client: TestClient,
    session: Session,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    login_as(make_user(UserRole.ANALYST))
    source = _source(session)

    assert client.post(f"{SOURCES}/{source.id}/scan").status_code == 403
    assert session.exec(select(Scan)).all() == []


def test_discovery_output_becomes_fetch_tasks(
    session: Session, dispatcher: RecordingDispatcher
) -> None:
    source = _source(session)
    scan = service.launch_scan(session, source, trigger=ScanTrigger.MANUAL, dispatcher=dispatcher)
    dispatcher.enqueued.clear()

    specs = [{"page_ids": ["1", "2"]}, {"page_ids": ["3"]}]
    tasks = service.create_fetch_tasks(session, scan, specs)
    session.commit()

    assert [task.kind for task in tasks] == [ScanTaskKind.FETCH, ScanTaskKind.FETCH]
    session.refresh(scan)
    assert scan.status is ScanStatus.RUNNING


def test_a_discovery_that_found_nothing_is_not_an_error(
    session: Session, dispatcher: RecordingDispatcher
) -> None:
    """An empty space, or a scope filter that matches nothing."""
    source = _source(session)
    scan = service.launch_scan(session, source, trigger=ScanTrigger.MANUAL, dispatcher=dispatcher)

    assert service.create_fetch_tasks(session, scan, []) == []


def test_fan_out_refuses_to_resurrect_a_cancelled_scan(
    session: Session, dispatcher: RecordingDispatcher
) -> None:
    """A scan cancelled while discovery results were in flight stays cancelled."""
    source = _source(session)
    scan = service.launch_scan(session, source, trigger=ScanTrigger.MANUAL, dispatcher=dispatcher)
    service.cancel_scan(session, scan)

    tasks = service.create_fetch_tasks(session, scan, [{"page_ids": ["1"]}])
    session.commit()

    assert tasks == []
    session.refresh(scan)
    assert scan.status is ScanStatus.CANCELLED


@pytest.mark.parametrize(
    ("task_statuses", "expected"),
    [
        ([ScanTaskStatus.COMPLETED, ScanTaskStatus.COMPLETED], ScanStatus.COMPLETED),
        ([ScanTaskStatus.COMPLETED, ScanTaskStatus.FAILED], ScanStatus.PARTIAL),
        ([ScanTaskStatus.FAILED, ScanTaskStatus.FAILED], ScanStatus.FAILED),
        ([ScanTaskStatus.COMPLETED, ScanTaskStatus.CANCELLED], ScanStatus.CANCELLED),
    ],
)
def test_final_status_distinguishes_complete_from_partial(
    task_statuses: list[ScanTaskStatus], expected: ScanStatus
) -> None:
    """Not cosmetic: only `completed` lets reconciliation auto-resolve (ADR 0009 §4)."""
    assert service._final_status(task_statuses) is expected
