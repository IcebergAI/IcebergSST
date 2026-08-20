"""Schedules — a cron cadence attached to a source (#58).

Admin-only to change, readable by anyone: scheduling a scan of somebody's
Confluence is a configuration decision, but "why did this scan run at 3am" is a
question an analyst has to be able to answer for themselves.

``next_run_at`` comes straight from the row. The API computes it on create, on
enable, and when the expression changes, so the screen never re-derives cron
state — and a schedule re-enabled after a week off shows its *next* beat rather
than implying it owes a scan for every one it missed.
"""

import uuid
from typing import Annotated

from fastapi import APIRouter, Form, HTTPException, Query, Request, Response
from pydantic import ValidationError

from iceberg_api.auth.dependencies import CsrfProtected, SessionDep, SettingsDep
from iceberg_api.auth.session import read_flash
from iceberg_api.pagination import DEFAULT_LIMIT
from iceberg_api.sources import schedule_routes as api
from iceberg_api.sources.routes import list_sources
from iceberg_api.sources.schemas import ScheduleCreate, ScheduleUpdate
from iceberg_api.web.dependencies import CurrentViewer, WebAdmin, WebViewer
from iceberg_api.web.forms import checkbox, redirect_with_error
from iceberg_api.web.templating import hx_redirect, id_or_none, render_page

router = APIRouter(include_in_schema=False)

#: The cadences operators actually ask for. A custom expression still works —
#: the API validates whatever is typed — but these cover the common cases without
#: anyone having to remember field order.
CRON_PRESETS = (
    ("0 * * * *", "Hourly"),
    ("0 3 * * *", "Daily at 03:00 UTC"),
    ("0 3 * * 1", "Weekly, Monday 03:00 UTC"),
    ("0 3 1 * *", "Monthly, 1st at 03:00 UTC"),
)


@router.get("/schedules")
async def schedules_page(
    request: Request,
    viewer: CurrentViewer,
    user: WebViewer,
    db: SessionDep,
    settings: SettingsDep,
    source_id: Annotated[str | None, Query()] = None,
    error: Annotated[str | None, Query()] = None,
    cursor: Annotated[str | None, Query()] = None,
) -> Response:
    """Every schedule, optionally for one source."""
    page = await api.list_schedules(
        user=user,
        db=db,
        source_id=id_or_none(source_id),
        limit=DEFAULT_LIMIT,
        cursor=cursor,
    )
    sources = await list_sources(user=user, db=db, limit=DEFAULT_LIMIT, cursor=None)
    return render_page(
        request,
        "schedules/list.html",
        viewer,
        {
            "schedules": page.items,
            "next_cursor": page.next_cursor,
            "sources": sources.items,
            "source_names": {source.id: source.name for source in sources.items},
            "presets": CRON_PRESETS,
            "selected_source": source_id or "",
            "island": {"cron": CRON_PRESETS[1][0]},
            "error": read_flash(error, settings),
        },
    )


@router.post("/schedules", dependencies=[CsrfProtected])
async def create_schedule(
    admin: WebAdmin,
    db: SessionDep,
    settings: SettingsDep,
    cron: Annotated[str, Form()],
    # Defaulted, as on the suppressions form: FastAPI reads a blank form field as
    # an absent one, and the "Choose…" option posts exactly that. Required here
    # would answer it with the API's JSON 422 instead of the sentence below.
    source_id: Annotated[str, Form()] = "",
    enabled: Annotated[str | None, Form()] = None,
    csrf_token: Annotated[str, Form()] = "",
) -> Response:
    """Attach a cadence to a source."""
    try:
        target = id_or_none(source_id)
        if target is None:
            raise ValueError("choose a source")
        body = ScheduleCreate(source_id=target, cron=cron, enabled=checkbox(enabled))
        await api.create_schedule(body=body, admin=admin, db=db)
    except (HTTPException, ValidationError, ValueError) as exc:
        return redirect_with_error("/schedules", exc, settings)
    return hx_redirect("/schedules")


@router.post("/schedules/{schedule_id}", dependencies=[CsrfProtected])
async def update_schedule(
    schedule_id: uuid.UUID,
    admin: WebAdmin,
    db: SessionDep,
    settings: SettingsDep,
    cron: Annotated[str, Form()],
    enabled: Annotated[str | None, Form()] = None,
    csrf_token: Annotated[str, Form()] = "",
) -> Response:
    """Change the cadence, or turn it on and off."""
    try:
        changes = ScheduleUpdate(cron=cron, enabled=checkbox(enabled))
        await api.update_schedule(schedule_id=schedule_id, changes=changes, admin=admin, db=db)
    except (HTTPException, ValidationError, ValueError) as exc:
        return redirect_with_error("/schedules", exc, settings)
    return hx_redirect("/schedules")


@router.delete("/schedules/{schedule_id}", dependencies=[CsrfProtected])
async def delete_schedule(
    schedule_id: uuid.UUID,
    admin: WebAdmin,
    db: SessionDep,
    settings: SettingsDep,
) -> Response:
    await api.delete_schedule(schedule_id=schedule_id, admin=admin, db=db)
    return hx_redirect("/schedules")
