"""Who is making this request: session, user, and CSRF dependencies (ADR 0005).

Authentication only — role checks live in :mod:`iceberg_api.auth.rbac`, which
builds on :data:`CurrentUser` from here.

The session cookie carries no authorization state, so every request loads the user
from the database. That is what makes demoting or disabling someone take effect on
their next request rather than whenever their cookie happens to expire (#69).
"""

from collections.abc import Iterator
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from iceberg_core.config import ApiSettings, get_api_settings
from iceberg_core.db import session_dependency
from iceberg_core.models import User
from sqlmodel import Session

from iceberg_api.auth import csrf
from iceberg_api.auth.session import (
    SESSION_COOKIE,
    AuthConfigError,
    SessionData,
    SessionError,
    read_session,
)


def get_settings() -> ApiSettings:
    """Settings as a dependency, so tests can override them per app."""
    return get_api_settings()


def get_db_session() -> Iterator[Session]:
    """Request-scoped database session, as an overridable seam."""
    yield from session_dependency()


SettingsDep = Annotated[ApiSettings, Depends(get_settings)]
SessionDep = Annotated[Session, Depends(get_db_session)]


def current_session(request: Request, settings: SettingsDep) -> SessionData:
    """Read and verify the session cookie, or reject with 401."""
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "authentication required")
    try:
        return read_session(token, settings)
    except AuthConfigError as exc:
        # Misconfiguration, not a bad request: say so rather than returning 401.
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc)) from exc
    except SessionError as exc:
        # No detail: which part of the cookie failed is the attacker's problem.
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "authentication required") from exc


SessionDataDep = Annotated[SessionData, Depends(current_session)]


def current_user(session_data: SessionDataDep, db: SessionDep) -> User:
    """Load the session's user, rejecting deleted and disabled accounts."""
    user = db.get(User, session_data.user_id)
    if user is None or user.disabled:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "authentication required")
    return user


CurrentUser = Annotated[User, Depends(current_user)]


async def require_csrf(request: Request, session_data: SessionDataDep) -> None:
    """Enforce the CSRF token on a session-authenticated mutation."""
    if request.method in csrf.SAFE_METHODS:
        return
    try:
        csrf.verify(session_data.csrf_token, await csrf.presented_token(request))
    except csrf.CsrfError as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "missing or invalid CSRF token") from exc


#: Declare on every mutating, session-authenticated route.
CsrfProtected = Depends(require_csrf)
