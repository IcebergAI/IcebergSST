"""Admin user and role management (#69)."""

from collections.abc import Callable

import pytest
from fastapi.testclient import TestClient
from iceberg_api.users.routes import audit_events_for
from iceberg_core.enums import UserRole
from iceberg_core.models import AuditEvent, User
from sqlmodel import Session, select

USERS = "/api/v1/users"


def test_an_admin_can_list_users(
    client: TestClient,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    admin = make_user(UserRole.ADMIN)
    make_user(UserRole.ANALYST)
    make_user(UserRole.VIEWER)
    login_as(admin)

    body = client.get(USERS).json()

    assert len(body["items"]) == 3
    assert {item["role"] for item in body["items"]} == {"admin", "analyst", "viewer"}
    assert body["next_cursor"] is None


@pytest.mark.parametrize("role", [UserRole.ANALYST, UserRole.VIEWER])
def test_listing_users_is_admin_only(
    client: TestClient,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
    role: UserRole,
) -> None:
    login_as(make_user(role))

    assert client.get(USERS).status_code == 403


def test_listing_users_requires_a_session(client: TestClient) -> None:
    assert client.get(USERS).status_code == 401


def test_pagination_walks_every_user_once_in_a_stable_order(
    client: TestClient,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """Cursor pagination: no row skipped, none repeated."""
    admin = make_user(UserRole.ADMIN)
    for _ in range(6):
        make_user(UserRole.VIEWER)
    login_as(admin)

    seen: list[str] = []
    cursor: str | None = None
    for _ in range(10):  # bounded so a broken cursor cannot loop forever
        params = {"limit": 2} | ({"cursor": cursor} if cursor else {})
        body = client.get(USERS, params=params).json()
        seen.extend(item["id"] for item in body["items"])
        cursor = body["next_cursor"]
        if cursor is None:
            break

    assert cursor is None
    assert len(seen) == 7
    assert len(set(seen)) == 7


def test_a_forged_cursor_is_a_bad_request_not_a_wrong_page(
    client: TestClient,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    login_as(make_user(UserRole.ADMIN))

    assert client.get(USERS, params={"cursor": "not-a-cursor"}).status_code == 400


def test_an_admin_can_promote_someone_and_the_change_is_audited(
    client: TestClient,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
    session: Session,
) -> None:
    admin = make_user(UserRole.ADMIN)
    target = make_user(UserRole.VIEWER)
    headers = login_as(admin)

    response = client.patch(f"{USERS}/{target.id}", json={"role": "analyst"}, headers=headers)

    assert response.status_code == 200
    assert response.json()["role"] == "analyst"
    session.refresh(target)
    assert target.role is UserRole.ANALYST

    events = audit_events_for(session, target.id)
    assert [event.action for event in events] == ["user.role_changed"]
    assert (events[0].from_value, events[0].to_value) == ("viewer", "analyst")
    assert events[0].actor_id == admin.id


def test_disabling_and_re_enabling_are_both_audited(
    client: TestClient,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
    session: Session,
) -> None:
    admin = make_user(UserRole.ADMIN)
    target = make_user(UserRole.ANALYST)
    headers = login_as(admin)

    client.patch(f"{USERS}/{target.id}", json={"disabled": True}, headers=headers)
    client.patch(f"{USERS}/{target.id}", json={"disabled": False}, headers=headers)

    assert [event.action for event in audit_events_for(session, target.id)] == [
        "user.disabled",
        "user.enabled",
    ]


def test_a_no_op_change_records_nothing(
    client: TestClient,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
    session: Session,
) -> None:
    """An audit log full of "changed viewer to viewer" is an audit log nobody reads."""
    admin = make_user(UserRole.ADMIN)
    target = make_user(UserRole.VIEWER)
    headers = login_as(admin)

    response = client.patch(f"{USERS}/{target.id}", json={"role": "viewer"}, headers=headers)

    assert response.status_code == 200
    assert audit_events_for(session, target.id) == []


def test_nobody_can_change_their_own_role(
    client: TestClient,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
    session: Session,
) -> None:
    """Including an admin: it also removes any way to lock out the last one."""
    admin = make_user(UserRole.ADMIN)
    headers = login_as(admin)

    response = client.patch(f"{USERS}/{admin.id}", json={"role": "viewer"}, headers=headers)

    assert response.status_code == 403
    session.refresh(admin)
    assert admin.role is UserRole.ADMIN
    assert session.exec(select(AuditEvent)).all() == []


def test_an_analyst_cannot_promote_themselves(
    client: TestClient,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
    session: Session,
) -> None:
    analyst = make_user(UserRole.ANALYST)
    other = make_user(UserRole.VIEWER)
    headers = login_as(analyst)

    assert (
        client.patch(f"{USERS}/{analyst.id}", json={"role": "admin"}, headers=headers).status_code
        == 403
    )
    assert (
        client.patch(f"{USERS}/{other.id}", json={"role": "admin"}, headers=headers).status_code
        == 403
    )
    session.refresh(analyst)
    assert analyst.role is UserRole.ANALYST


def test_a_role_change_without_a_csrf_token_is_refused(
    client: TestClient,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
    session: Session,
) -> None:
    admin = make_user(UserRole.ADMIN)
    target = make_user(UserRole.VIEWER)
    login_as(admin)

    response = client.patch(f"{USERS}/{target.id}", json={"role": "admin"})

    assert response.status_code == 403
    session.refresh(target)
    assert target.role is UserRole.VIEWER


def test_patching_an_unknown_user_is_a_404(
    client: TestClient,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    headers = login_as(make_user(UserRole.ADMIN))

    missing = "00000000-0000-4000-8000-000000000000"
    assert (
        client.patch(f"{USERS}/{missing}", json={"role": "admin"}, headers=headers).status_code
        == 404
    )


def test_unknown_fields_are_rejected_rather_than_ignored(
    client: TestClient,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """A typo'd field name silently doing nothing is worse than a 422."""
    admin = make_user(UserRole.ADMIN)
    target = make_user(UserRole.VIEWER)
    headers = login_as(admin)

    response = client.patch(
        f"{USERS}/{target.id}", json={"rolee": "admin", "oidc_subject": "x"}, headers=headers
    )

    assert response.status_code == 422


def test_disabling_an_admin_locks_them_out_on_their_next_request(
    client: TestClient,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """Revocation is immediate because the session carries no authorization state."""
    admin = make_user(UserRole.ADMIN)
    victim = make_user(UserRole.ADMIN)

    login_as(victim)
    assert client.get(USERS).status_code == 200

    client.patch(f"{USERS}/{victim.id}", json={"disabled": True}, headers=login_as(admin))

    login_as(victim)
    assert client.get(USERS).status_code == 401
