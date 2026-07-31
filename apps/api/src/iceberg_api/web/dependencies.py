"""Who is asking, on the browser surface.

Authentication and authorization are **not reimplemented here**. The session is
verified by :func:`iceberg_api.auth.dependencies.current_session`, the user is
loaded by :func:`~iceberg_api.auth.dependencies.current_user`, and roles are
ranked by :func:`iceberg_api.auth.rbac.require_role` — the same functions the
JSON API depends on, so a demotion takes effect on the browser's next request
exactly as it does on the API's, and there is no second place for a permission
rule to drift.

What differs is only the *failure shape*. An API client that presents no session
should get a 401 with a JSON body. A browser should get sent to the login page,
with the page it was trying to reach remembered. So the dependencies below wrap
the shared ones and convert that one status into :class:`LoginRequired`, which
:mod:`iceberg_api.web.errors` turns into a redirect.
"""

from collections.abc import Callable
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from iceberg_core.enums import UserRole
from iceberg_core.models import User

from iceberg_api.auth import rbac
from iceberg_api.auth.dependencies import (
    SessionDep,
    SettingsDep,
    current_session,
    current_user,
)
from iceberg_api.auth.session import SessionData


class LoginRequired(Exception):
    """No usable session. Carries where the browser was heading."""

    def __init__(self, return_path: str) -> None:
        super().__init__("authentication required")
        self.return_path = return_path


def _return_path(request: Request) -> str:
    """The path the browser wanted, query string included.

    Reduced to a local path by ``safe_return_path`` before it is ever used as a
    redirect target, so a crafted ``?next=`` cannot ride out of this origin.
    """
    query = request.url.query
    return f"{request.url.path}?{query}" if query else request.url.path


def web_session_data(request: Request, settings: SettingsDep) -> SessionData:
    """The verified session, or a redirect to the login page."""
    try:
        return current_session(request, settings)
    except HTTPException as exc:
        if exc.status_code == status.HTTP_401_UNAUTHORIZED:
            raise LoginRequired(_return_path(request)) from exc
        # 503: authentication is misconfigured. That is an operator's problem and
        # bouncing them to a login page that cannot work would hide it.
        raise


WebSessionData = Annotated[SessionData, Depends(web_session_data)]


def web_user(request: Request, session_data: WebSessionData, db: SessionDep) -> User:
    """The signed-in user, or a redirect. Deleted and disabled accounts included."""
    try:
        return current_user(session_data, db)
    except HTTPException as exc:
        if exc.status_code == status.HTTP_401_UNAUTHORIZED:
            raise LoginRequired(_return_path(request)) from exc
        raise


WebUser = Annotated[User, Depends(web_user)]


@dataclass(frozen=True, slots=True)
class Viewer:
    """The signed-in user plus this session's CSRF token.

    Bundled because every rendered page needs both: the user to shape the
    navigation, the token to put on every form and ``hx-`` request.
    """

    user: User
    csrf_token: str


def _viewer(user: WebUser, session_data: WebSessionData) -> Viewer:
    return Viewer(user=user, csrf_token=session_data.csrf_token)


CurrentViewer = Annotated[Viewer, Depends(_viewer)]


def web_require_role(minimum: UserRole) -> Callable[[User], User]:
    """A role gate for a browser route, built on the API's one implementation.

    ``rbac.require_role`` is called rather than re-derived: same ranking, same
    403, same ``authorization_denied`` audit line. This wrapper exists only so the
    dependency behind it is :data:`WebUser` — which redirects an anonymous visitor
    instead of handing them JSON.
    """
    check = rbac.require_role(minimum)

    def dependency(user: WebUser) -> User:
        return check(user)

    return dependency


#: Mirrors ``rbac.AdminUser`` / ``AnalystUser`` / ``ViewerUser``. A web route that
#: delegates to an API handler must declare the gate that handler declares — the
#: handler's own dependency does not run when it is called as a function.
WebAdmin = Annotated[User, Depends(web_require_role(UserRole.ADMIN))]
WebAnalyst = Annotated[User, Depends(web_require_role(UserRole.ANALYST))]
WebViewer = Annotated[User, Depends(web_require_role(UserRole.VIEWER))]
