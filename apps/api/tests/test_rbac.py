"""Role-based access control (#29).

The dependency is the enforcement point, so it is tested directly against a small
app whose only content is one route per role. The matrix is the acceptance
criterion: every role reaches exactly what it should and nothing above it.
"""

from collections.abc import Callable, Iterator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from iceberg_api.auth.dependencies import get_db_session, get_settings
from iceberg_api.auth.rbac import ROLE_RANK, AdminUser, AnalystUser, ViewerUser
from iceberg_core.config import ApiSettings
from iceberg_core.enums import UserRole
from iceberg_core.models import User
from sqlmodel import Session

ROUTES = {
    UserRole.VIEWER: "/viewer-only",
    UserRole.ANALYST: "/analyst-only",
    UserRole.ADMIN: "/admin-only",
}


@pytest.fixture(name="rbac_client")
def rbac_client_fixture(api_settings: ApiSettings, session: Session) -> Iterator[TestClient]:
    app = FastAPI()

    @app.get(ROUTES[UserRole.VIEWER])
    async def viewer_route(user: ViewerUser) -> dict[str, str]:
        return {"role": user.role.value}

    @app.get(ROUTES[UserRole.ANALYST])
    async def analyst_route(user: AnalystUser) -> dict[str, str]:
        return {"role": user.role.value}

    @app.get(ROUTES[UserRole.ADMIN])
    async def admin_route(user: AdminUser) -> dict[str, str]:
        return {"role": user.role.value}

    def _db() -> Iterator[Session]:
        yield session

    app.dependency_overrides[get_settings] = lambda: api_settings
    app.dependency_overrides[get_db_session] = _db
    with TestClient(app) as client:
        yield client


@pytest.fixture(name="rbac_login")
def rbac_login_fixture(
    rbac_client: TestClient, api_settings: ApiSettings
) -> Callable[[User], None]:
    from iceberg_api.auth.session import SESSION_COOKIE, issue_session

    def login(user: User) -> None:
        rbac_client.cookies.set(SESSION_COOKIE, issue_session(user.id, api_settings))

    return login


def test_roles_are_ranked_not_compared_for_equality() -> None:
    """An admin can do anything an analyst can; equality checks would forget one."""
    assert ROLE_RANK[UserRole.ADMIN] > ROLE_RANK[UserRole.ANALYST] > ROLE_RANK[UserRole.VIEWER]


@pytest.mark.parametrize("route", list(ROUTES.values()))
def test_unauthenticated_requests_are_rejected(rbac_client: TestClient, route: str) -> None:
    assert rbac_client.get(route).status_code == 401


@pytest.mark.parametrize(
    ("role", "allowed"),
    [
        (UserRole.VIEWER, {UserRole.VIEWER}),
        (UserRole.ANALYST, {UserRole.VIEWER, UserRole.ANALYST}),
        (UserRole.ADMIN, {UserRole.VIEWER, UserRole.ANALYST, UserRole.ADMIN}),
    ],
)
def test_each_role_reaches_exactly_what_it_should(
    rbac_client: TestClient,
    rbac_login: Callable[[User], None],
    make_user: Callable[..., User],
    role: UserRole,
    allowed: set[UserRole],
) -> None:
    rbac_login(make_user(role))

    for required, route in ROUTES.items():
        expected = 200 if required in allowed else 403
        assert rbac_client.get(route).status_code == expected, f"{role.value} → {route}"


def test_a_disabled_user_loses_access_immediately(
    rbac_client: TestClient,
    rbac_login: Callable[[User], None],
    make_user: Callable[..., User],
    session: Session,
) -> None:
    """Revocation must not wait for the session cookie to expire (#69)."""
    user = make_user(UserRole.ADMIN)
    rbac_login(user)
    assert rbac_client.get(ROUTES[UserRole.ADMIN]).status_code == 200

    user.disabled = True
    session.commit()

    assert rbac_client.get(ROUTES[UserRole.ADMIN]).status_code == 401


def test_a_demotion_takes_effect_on_the_next_request(
    rbac_client: TestClient,
    rbac_login: Callable[[User], None],
    make_user: Callable[..., User],
    session: Session,
) -> None:
    """The session carries no role, which is what makes this true."""
    user = make_user(UserRole.ADMIN)
    rbac_login(user)
    assert rbac_client.get(ROUTES[UserRole.ADMIN]).status_code == 200

    user.role = UserRole.VIEWER
    session.commit()

    assert rbac_client.get(ROUTES[UserRole.ADMIN]).status_code == 403
    assert rbac_client.get(ROUTES[UserRole.VIEWER]).status_code == 200


def test_a_session_for_a_deleted_user_is_not_a_session(
    rbac_client: TestClient,
    rbac_login: Callable[[User], None],
    make_user: Callable[..., User],
    session: Session,
) -> None:
    user = make_user(UserRole.ANALYST)
    rbac_login(user)
    session.delete(user)
    session.commit()

    assert rbac_client.get(ROUTES[UserRole.VIEWER]).status_code == 401
