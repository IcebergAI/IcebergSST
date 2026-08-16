"""Schedule CRUD (#33)."""

from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from iceberg_api import audit
from iceberg_core.enums import SourceType, UserRole
from iceberg_core.models import AUDIT_TARGET_SCHEDULE, Schedule, Source, User
from sqlmodel import Session, select

SCHEDULES = "/api/v1/schedules"


def _source(session: Session, name: str = "confluence-prod") -> Source:
    source = Source(
        name=name,
        type=SourceType.CONFLUENCE,
        connection={"base_url": "https://example.atlassian.net/wiki"},
    )
    session.add(source)
    session.commit()
    return source


def test_an_admin_can_schedule_a_source(
    client: TestClient,
    session: Session,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    headers = login_as(make_user(UserRole.ADMIN))
    source = _source(session)

    response = client.post(
        SCHEDULES, json={"source_id": str(source.id), "cron": "0 3 * * *"}, headers=headers
    )

    assert response.status_code == 201
    body = response.json()
    assert body["cron"] == "0 3 * * *"
    assert body["enabled"] is True
    # Computed on write, so "when does this fire next?" is answerable from the row.
    assert datetime.fromisoformat(body["next_run_at"]) > datetime.now(UTC)

    events = audit.events_for(
        session, AUDIT_TARGET_SCHEDULE, session.exec(select(Schedule)).one().id
    )
    assert [event.action for event in events] == ["schedule.created"]


def test_a_disabled_schedule_has_no_next_run(
    client: TestClient,
    session: Session,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    headers = login_as(make_user(UserRole.ADMIN))
    source = _source(session)

    body = client.post(
        SCHEDULES,
        json={"source_id": str(source.id), "cron": "0 3 * * *", "enabled": False},
        headers=headers,
    ).json()

    assert body["next_run_at"] is None


@pytest.mark.parametrize("cron", ["not a cron", "0 3 * *", "99 * * * *", ""])
def test_an_invalid_cron_expression_is_refused(
    client: TestClient,
    session: Session,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
    cron: str,
) -> None:
    headers = login_as(make_user(UserRole.ADMIN))
    source = _source(session)

    response = client.post(
        SCHEDULES, json={"source_id": str(source.id), "cron": cron}, headers=headers
    )

    assert response.status_code == 422


def test_scheduling_an_unknown_source_is_refused(
    client: TestClient,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    headers = login_as(make_user(UserRole.ADMIN))

    response = client.post(
        SCHEDULES,
        json={"source_id": "00000000-0000-4000-8000-000000000000", "cron": "0 3 * * *"},
        headers=headers,
    )

    assert response.status_code == 422


@pytest.mark.parametrize("role", [UserRole.ANALYST, UserRole.VIEWER])
def test_only_an_admin_can_write_schedules(
    client: TestClient,
    session: Session,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
    role: UserRole,
) -> None:
    source = _source(session)
    headers = login_as(make_user(role))

    response = client.post(
        SCHEDULES, json={"source_id": str(source.id), "cron": "0 3 * * *"}, headers=headers
    )

    assert response.status_code == 403


def test_any_role_can_read_schedules(
    client: TestClient,
    session: Session,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """An analyst should be able to see why a scan ran."""
    admin_headers = login_as(make_user(UserRole.ADMIN))
    source = _source(session)
    created = client.post(
        SCHEDULES, json={"source_id": str(source.id), "cron": "0 3 * * *"}, headers=admin_headers
    ).json()

    login_as(make_user(UserRole.VIEWER))

    assert client.get(SCHEDULES).status_code == 200
    assert client.get(f"{SCHEDULES}/{created['id']}").status_code == 200


def test_schedules_can_be_filtered_by_source(
    client: TestClient,
    session: Session,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    headers = login_as(make_user(UserRole.ADMIN))
    first, second = _source(session, "one"), _source(session, "two")
    for source in (first, second):
        client.post(
            SCHEDULES, json={"source_id": str(source.id), "cron": "0 3 * * *"}, headers=headers
        )

    body = client.get(SCHEDULES, params={"source_id": str(first.id)}).json()

    assert [item["source_id"] for item in body["items"]] == [str(first.id)]


def test_changing_the_cron_recomputes_the_next_run_and_is_audited(
    client: TestClient,
    session: Session,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    headers = login_as(make_user(UserRole.ADMIN))
    source = _source(session)
    created = client.post(
        SCHEDULES, json={"source_id": str(source.id), "cron": "0 3 * * *"}, headers=headers
    ).json()

    updated = client.patch(
        f"{SCHEDULES}/{created['id']}", json={"cron": "*/15 * * * *"}, headers=headers
    ).json()

    assert updated["cron"] == "*/15 * * * *"
    # Asserted against the *new* cron rather than against the old schedule's time.
    # "Sooner than 03:00" is true for `*/15` all day and false for the fifteen
    # minutes before it, so a suite run at 02:47 failed on the clock rather than
    # on the code. The next quarter-hour is what recomputation should produce, and
    # saying so is both deterministic and a stronger claim.
    next_run = datetime.fromisoformat(updated["next_run_at"])
    assert (next_run.minute % 15, next_run.second, next_run.microsecond) == (0, 0, 0)
    assert next_run <= datetime.now(UTC) + timedelta(minutes=15)
    actions = [
        event.action
        for event in audit.events_for(
            session, AUDIT_TARGET_SCHEDULE, session.exec(select(Schedule)).one().id
        )
    ]
    assert actions == ["schedule.created", "schedule.updated"]


def test_disabling_a_schedule_clears_its_next_run(
    client: TestClient,
    session: Session,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    headers = login_as(make_user(UserRole.ADMIN))
    source = _source(session)
    created = client.post(
        SCHEDULES, json={"source_id": str(source.id), "cron": "0 3 * * *"}, headers=headers
    ).json()

    disabled = client.patch(
        f"{SCHEDULES}/{created['id']}", json={"enabled": False}, headers=headers
    ).json()
    re_enabled = client.patch(
        f"{SCHEDULES}/{created['id']}", json={"enabled": True}, headers=headers
    ).json()

    assert disabled["next_run_at"] is None
    # Re-enabled from now, so a week off does not owe a week of scans.
    assert datetime.fromisoformat(re_enabled["next_run_at"]) > datetime.now(UTC)


def test_deleting_a_schedule_is_audited(
    client: TestClient,
    session: Session,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    headers = login_as(make_user(UserRole.ADMIN))
    source = _source(session)
    created = client.post(
        SCHEDULES, json={"source_id": str(source.id), "cron": "0 3 * * *"}, headers=headers
    ).json()
    schedule_id = session.exec(select(Schedule)).one().id

    response = client.delete(f"{SCHEDULES}/{created['id']}", headers=headers)

    assert response.status_code == 204
    assert session.exec(select(Schedule)).all() == []
    actions = [
        event.action for event in audit.events_for(session, AUDIT_TARGET_SCHEDULE, schedule_id)
    ]
    assert actions[-1] == "schedule.deleted"


def test_writing_a_schedule_requires_a_csrf_token(
    client: TestClient,
    session: Session,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    login_as(make_user(UserRole.ADMIN))
    source = _source(session)

    response = client.post(SCHEDULES, json={"source_id": str(source.id), "cron": "0 3 * * *"})

    assert response.status_code == 403
    assert session.exec(select(Schedule)).all() == []


def test_deleting_a_source_takes_its_schedules_with_it(
    client: TestClient,
    session: Session,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """The FK cascades, so a schedule cannot outlive the source it scans."""
    headers = login_as(make_user(UserRole.ADMIN))
    source = _source(session)
    client.post(SCHEDULES, json={"source_id": str(source.id), "cron": "0 3 * * *"}, headers=headers)

    client.delete(f"/api/v1/sources/{source.id}", headers=headers)

    assert session.exec(select(Schedule)).all() == []
