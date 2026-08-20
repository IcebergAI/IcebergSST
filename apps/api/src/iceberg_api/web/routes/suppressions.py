"""Suppressions — silencing a known-benign match (#58, ADR 0008).

Tuning lives in data, so this screen is where an analyst turns a false positive
off without waiting for a rule-pack release. Two properties of the API show
through in the UI deliberately:

* **A reason is required.** The API refuses a blank one, because a suppression
  without a stated reason is indistinguishable from a mistake six months later.
* **There is no edit.** Editing a live pattern would silently re-scope what it
  hides; the form offers create and delete, and both decisions stay in the trail.
"""

import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Form, HTTPException, Query, Request, Response
from iceberg_core.enums import SuppressionScope
from pydantic import ValidationError

from iceberg_api.auth.dependencies import CsrfProtected, SessionDep, SettingsDep
from iceberg_api.auth.session import read_flash
from iceberg_api.findings import suppression_routes as api
from iceberg_api.findings.schemas import SuppressionCreate
from iceberg_api.pagination import DEFAULT_LIMIT
from iceberg_api.sources.routes import list_sources
from iceberg_api.web.dependencies import CurrentViewer, WebAnalyst, WebViewer
from iceberg_api.web.forms import optional, redirect_with_error
from iceberg_api.web.templating import hx_redirect, id_or_none, render_page

router = APIRouter(include_in_schema=False)


@router.get("/suppressions")
async def suppressions_page(  # filters plus the prefilled draft
    request: Request,
    viewer: CurrentViewer,
    user: WebViewer,
    db: SessionDep,
    settings: SettingsDep,
    source_id: Annotated[str | None, Query()] = None,
    scope: Annotated[str | None, Query()] = None,
    active: Annotated[str | None, Query()] = None,
    pattern: Annotated[str | None, Query()] = None,
    error: Annotated[str | None, Query()] = None,
    cursor: Annotated[str | None, Query()] = None,
) -> Response:
    """The list, plus a create form the finding detail can pre-fill by link."""
    page = await api.list_suppressions(
        user=user,
        db=db,
        source_id=id_or_none(source_id),
        scope=_scope_or_none(scope),
        active=True if active == "true" else (False if active == "false" else None),
        limit=DEFAULT_LIMIT,
        cursor=cursor,
    )
    sources = await list_sources(user=user, db=db, limit=DEFAULT_LIMIT, cursor=None)

    return render_page(
        request,
        "suppressions/list.html",
        viewer,
        {
            "suppressions": page.items,
            "next_cursor": page.next_cursor,
            "sources": sources.items,
            "source_names": {source.id: source.name for source in sources.items},
            "scopes": list(SuppressionScope),
            "selected": {
                "source_id": source_id or "",
                "scope": scope or "",
                "active": active or "",
            },
            # A "suppress this finding" link arrives with the scope and pattern
            # already chosen; the form opens on its own when it does.
            "draft": {"scope": scope or "", "pattern": pattern or "", "source_id": source_id or ""},
            "prefilled": bool(pattern),
            "error": read_flash(error, settings),
        },
    )


@router.post("/suppressions", dependencies=[CsrfProtected])
async def create_suppression(  # one parameter per form field
    viewer: CurrentViewer,
    analyst: WebAnalyst,
    db: SessionDep,
    settings: SettingsDep,
    scope: Annotated[str, Form()],
    pattern: Annotated[str, Form()],
    reason: Annotated[str, Form()],
    source_id: Annotated[str, Form()] = "",
    expires_at: Annotated[str, Form()] = "",
    csrf_token: Annotated[str, Form()] = "",
) -> Response:
    """Create one, then reload the list showing what it now hides."""
    try:
        body = SuppressionCreate(
            scope=SuppressionScope(scope),
            pattern=pattern,
            source_id=id_or_none(optional(source_id)),
            reason=reason,
            expires_at=_expiry(expires_at),
        )
        await api.create_suppression(body=body, analyst=analyst, db=db)
    except (HTTPException, ValidationError, ValueError) as exc:
        # Round-tripped through the URL rather than a swapped fragment: this form
        # is short, and a full reload after a create is what shows the analyst the
        # findings that just disappeared from the queue.
        return redirect_with_error("/suppressions", exc, settings)

    return hx_redirect("/suppressions")


@router.delete("/suppressions/{suppression_id}", dependencies=[CsrfProtected])
async def delete_suppression(
    suppression_id: uuid.UUID,
    analyst: WebAnalyst,
    db: SessionDep,
    settings: SettingsDep,
) -> Response:
    """Delete one, releasing every finding it was hiding."""
    await api.delete_suppression(suppression_id=suppression_id, analyst=analyst, db=db)
    return hx_redirect("/suppressions")


def _scope_or_none(value: str | None) -> SuppressionScope | None:
    if not value:
        return None
    try:
        return SuppressionScope(value)
    except ValueError:
        return None


def _expiry(value: str) -> datetime | None:
    """Parse the ``datetime-local`` field, which posts without an offset.

    Read as UTC, the same assumption every other timestamp in the API makes — and
    the label on the field says so, because a browser will happily show an
    operator their local time next to a value that is not.
    """
    trimmed = value.strip()
    if not trimmed:
        return None
    try:
        parsed = datetime.fromisoformat(trimmed)
    except ValueError as exc:
        raise ValueError("expires_at must be a date and time") from exc
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
