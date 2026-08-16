"""Login, logout, and the overview (#53).

The overview is deliberately a *queue*, not a report: what is open, what is
running, and what needs a decision. Its numbers come from the same list
endpoints the screens use, so a count here and the table it links to can never
disagree — and where a list is capped by the API's page limit the tile says so
rather than quietly rounding down.
"""

from typing import Annotated

from fastapi import APIRouter, Form, HTTPException, Query, Request, Response, status
from fastapi.responses import RedirectResponse
from iceberg_core.config import ApiSettings
from iceberg_core.enums import FindingState, Severity, UserRole

from iceberg_api.auth import routes as auth_routes
from iceberg_api.auth.dependencies import (
    CsrfProtected,
    SessionDep,
    SettingsDep,
    current_session,
)
from iceberg_api.auth.session import safe_return_path
from iceberg_api.engines.routes import list_engines
from iceberg_api.findings.routes import list_findings
from iceberg_api.pagination import MAX_LIMIT
from iceberg_api.scans.routes import list_scans
from iceberg_api.sources.routes import list_sources
from iceberg_api.web.dependencies import CurrentViewer, WebViewer
from iceberg_api.web.templating import render, render_page

router = APIRouter(include_in_schema=False)

#: How many rows the overview asks each list endpoint for. The API caps a page
#: at this, so a full page means "at least this many" — which the tiles say.
OVERVIEW_LIMIT = MAX_LIMIT


def _has_session(request: Request, settings: ApiSettings) -> bool:
    """Whether this visitor already holds a usable session.

    Every failure mode means the same thing on this page — show the sign-in
    button — so they collapse to ``False`` rather than being distinguished:
    no cookie, an expired one, a forged one, and an authentication backend that
    is not configured all leave the visitor needing to sign in, and telling them
    which would only tell an attacker which.
    """
    try:
        current_session(request, settings)
    except HTTPException:
        return False
    return True


def _tally(page: object) -> tuple[int, bool]:
    """``(count, capped)`` for a page of results.

    ``capped`` is true when the API said there is another page, so the template
    can render "200+" instead of a number that is simply wrong. A security
    console that under-reports open findings is worse than one that admits the
    limit.
    """
    items = getattr(page, "items", [])
    return len(items), getattr(page, "next_cursor", None) is not None


@router.get("/login")
async def login_page(
    request: Request,
    settings: SettingsDep,
    next_path: Annotated[str | None, Query(alias="next")] = None,
    error: Annotated[str | None, Query()] = None,
) -> Response:
    """The sign-in page. A visitor who already has a session is sent onward."""
    if _has_session(request, settings):
        return RedirectResponse(safe_return_path(next_path), status_code=status.HTTP_303_SEE_OTHER)

    return render(
        request,
        "login.html",
        {
            # Reduced to a local path here as well as in /auth/login: this value
            # is round-tripped through a form and must not become an open redirect.
            "next_path": safe_return_path(next_path) if next_path else None,
            "error": error,
        },
    )


@router.post("/logout", dependencies=[CsrfProtected])
async def logout(
    settings: SettingsDep,
    viewer: CurrentViewer,
    csrf_token: Annotated[str, Form()] = "",
) -> Response:
    """End the session and return to the login page.

    Delegates to the API's ``POST /auth/logout`` so the cookie is cleared with
    exactly the attributes it was set with — a hand-rolled clear that missed
    ``path`` or ``secure`` would leave a live session cookie in the browser.
    The ``csrf_token`` form field is declared so Starlette parses the body; the
    check itself is ``CsrfProtected``, the same dependency the API route uses.
    """
    cleared = await auth_routes.logout(settings=settings, user=viewer.user)

    redirect = RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    for name, value in cleared.raw_headers:
        if name.lower() == b"set-cookie":
            redirect.raw_headers.append((name, value))
    return redirect


@router.get("/")
async def overview(
    request: Request,
    viewer: CurrentViewer,
    user: WebViewer,
    db: SessionDep,
) -> Response:
    """The queue: open findings, what is running, and what to look at next."""
    # Every argument is passed explicitly, `cursor` included: an API handler's
    # signature default is a FastAPI `Query(...)` marker, not the value it stands
    # for, and letting one through would reach `resolve_cursor` as a Query object.
    open_findings = await list_findings(
        user=user,
        db=db,
        state=FindingState.OPEN,
        suppressed=False,
        limit=OVERVIEW_LIMIT,
        cursor=None,
    )
    critical = await list_findings(
        user=user,
        db=db,
        state=FindingState.OPEN,
        suppressed=False,
        severity=Severity.CRITICAL,
        limit=OVERVIEW_LIMIT,
        cursor=None,
    )
    unassigned = [finding for finding in open_findings.items if finding.assignee_id is None]
    mine = [finding for finding in open_findings.items if finding.assignee_id == user.id]

    # The two ownership queues (#146). Asked of the API rather than counted from
    # `open_findings` above: both are questions the database answers precisely,
    # and deriving them from one capped page would under-report exactly when the
    # backlog is large enough to matter.
    overdue = await list_findings(user=user, db=db, overdue=True, limit=OVERVIEW_LIMIT, cursor=None)
    unowned = await list_findings(
        user=user,
        db=db,
        state=FindingState.OPEN,
        suppressed=False,
        unowned=True,
        limit=OVERVIEW_LIMIT,
        cursor=None,
    )

    active = await list_scans(
        user=user,
        db=db,
        source_id=None,
        scan_status=None,
        active=True,
        limit=OVERVIEW_LIMIT,
        cursor=None,
    )
    recent = await list_scans(
        user=user, db=db, source_id=None, scan_status=None, active=None, limit=8, cursor=None
    )
    sources = await list_sources(user=user, db=db, limit=OVERVIEW_LIMIT, cursor=None)

    # Fleet health is admin-only at the API, so the tile only exists for admins
    # rather than being rendered empty for everyone else.
    engines = await list_engines(admin=user, db=db) if user.role is UserRole.ADMIN else []
    stale_engines = [engine for engine in engines if engine.status.value != "active"]

    open_count, open_capped = _tally(open_findings)
    critical_count, critical_capped = _tally(critical)
    source_count, source_capped = _tally(sources)
    overdue_count, overdue_capped = _tally(overdue)
    unowned_count, unowned_capped = _tally(unowned)

    return render_page(
        request,
        "overview.html",
        viewer,
        {
            "open_count": open_count,
            "open_capped": open_capped,
            "critical_count": critical_count,
            "critical_capped": critical_capped,
            "unassigned_count": len(unassigned),
            "mine_count": len(mine),
            "source_count": source_count,
            "source_capped": source_capped,
            "overdue_count": overdue_count,
            "overdue_capped": overdue_capped,
            "unowned_count": unowned_count,
            "unowned_capped": unowned_capped,
            "active_scans": active.items,
            "recent_scans": recent.items,
            "recent_findings": open_findings.items[:8],
            "sources": {source.id: source for source in sources.items},
            "engines": engines,
            "stale_engines": stale_engines,
        },
    )
