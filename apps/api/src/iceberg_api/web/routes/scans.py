"""Launching a scan and watching it run (#56).

Live status is HTMX polling, not SSE. A scan's state changes when an engine
reports a task — seconds to minutes apart, a handful of watchers at a time — so
an open connection per viewer would buy latency nobody can perceive at the cost
of a streaming endpoint the API does not otherwise need. Polling also degrades
correctly: a dropped request is retried on the next tick rather than leaving a
half-dead stream that looks live.

The polling stops itself. The status fragment carries its own ``hx-trigger``, and
the terminal version of that fragment does not — so a finished scan's page stops
asking, without the client having to know which statuses are terminal.
"""

import uuid
from collections.abc import Sequence
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, Request, Response
from iceberg_core.enums import ACTIVE_SCAN_STATUSES, ScanStatus, ScanTaskStatus

from iceberg_api.auth.dependencies import CsrfProtected, SessionDep
from iceberg_api.dispatch import DispatcherDep
from iceberg_api.engines.schemas import ScanTaskRead
from iceberg_api.pagination import DEFAULT_LIMIT
from iceberg_api.scans import routes as api
from iceberg_api.scans.schemas import CoverageManifest, ScanRead
from iceberg_api.sources.routes import list_sources, read_source
from iceberg_api.web.dependencies import CurrentViewer, WebAnalyst, WebViewer
from iceberg_api.web.forms import error_text
from iceberg_api.web.templating import (
    hx_redirect,
    id_or_none,
    render_fragment,
    render_page,
)

router = APIRouter(include_in_schema=False)

#: How often the status fragment re-asks while a scan is moving. Slow enough that
#: ten open tabs are not a load problem, fast enough that "is it done?" is
#: answered before anyone reaches for reload.
POLL_INTERVAL_SECONDS = 3

#: A task in one of these is done moving, whatever the scan's own status says.
TERMINAL_TASK_STATUSES = frozenset(
    {ScanTaskStatus.COMPLETED, ScanTaskStatus.FAILED, ScanTaskStatus.CANCELLED}
)


def _is_active(scan: ScanRead) -> bool:
    return scan.status in ACTIVE_SCAN_STATUSES


@router.get("/scans")
async def scans_page(
    request: Request,
    viewer: CurrentViewer,
    user: WebViewer,
    db: SessionDep,
    source_id: Annotated[str | None, Query()] = None,
    scan_status: Annotated[str | None, Query(alias="status")] = None,
    cursor: Annotated[str | None, Query()] = None,
) -> Response:
    """Every scan, filterable by source and status."""
    selected_status = _status_or_none(scan_status)
    page = await api.list_scans(
        user=user,
        db=db,
        source_id=id_or_none(source_id),
        scan_status=selected_status,
        limit=DEFAULT_LIMIT,
        cursor=cursor,
    )
    sources = await list_sources(user=user, db=db, limit=DEFAULT_LIMIT, cursor=None)
    return render_page(
        request,
        "scans/list.html",
        viewer,
        {
            "scans": page.items,
            "next_cursor": page.next_cursor,
            "sources": sources.items,
            "source_names": {source.id: source.name for source in sources.items},
            "statuses": list(ScanStatus),
            "selected_source": source_id or "",
            "selected_status": scan_status or "",
        },
    )


@router.get("/scans/{scan_id}")
async def scan_detail(
    request: Request,
    scan_id: uuid.UUID,
    viewer: CurrentViewer,
    user: WebViewer,
    db: SessionDep,
) -> Response:
    """One scan, with the live status region that polls itself."""
    scan = await api.read_scan(scan_id=scan_id, user=user, db=db)
    source = await read_source(source_id=scan.source_id, user=user, db=db)
    tasks = await api.list_scan_tasks(scan_id=scan_id, user=user, db=db)
    coverage = (
        None
        if _is_active(scan)
        else await api.read_scan_coverage(scan_id=scan_id, user=user, db=db)
    )
    return render_page(
        request,
        "scans/detail.html",
        viewer,
        _status_context(scan, tasks, coverage=coverage) | {"source": source},
    )


@router.get("/scans/{scan_id}/status")
async def scan_status_fragment(
    request: Request,
    scan_id: uuid.UUID,
    viewer: CurrentViewer,
    user: WebViewer,
    db: SessionDep,
) -> Response:
    """The polled fragment: status, tallies, and per-task progress."""
    scan = await api.read_scan(scan_id=scan_id, user=user, db=db)
    tasks = await api.list_scan_tasks(scan_id=scan_id, user=user, db=db)
    coverage = (
        None
        if _is_active(scan)
        else await api.read_scan_coverage(scan_id=scan_id, user=user, db=db)
    )
    return render_fragment(
        request,
        "scan_status.html",
        viewer,
        _status_context(scan, tasks, coverage=coverage),
    )


@router.post("/sources/{source_id}/scan", dependencies=[CsrfProtected])
async def launch_scan(
    source_id: uuid.UUID,
    analyst: WebAnalyst,
    db: SessionDep,
    dispatcher: DispatcherDep,
) -> Response:
    """Start an on-demand scan and go straight to watching it.

    A 409 (the source is disabled, or already has an active scan) is left to the
    error handler: both mean "look at the source page", which is where the
    analyst already is.
    """
    scan = await api.trigger_scan(
        source_id=source_id, analyst=analyst, db=db, dispatcher=dispatcher
    )
    return hx_redirect(f"/scans/{scan.id}")


@router.post("/scans/{scan_id}/cancel", dependencies=[CsrfProtected])
async def cancel_scan(
    request: Request,
    scan_id: uuid.UUID,
    viewer: CurrentViewer,
    analyst: WebAnalyst,
    db: SessionDep,
) -> Response:
    """Ask for a cancellation, then re-render the status region.

    Honest about what it did: queued tasks can never be leased now, but a running
    engine only finds out at its next heartbeat, so the fragment keeps polling
    until the tasks actually settle.
    """
    try:
        scan = await api.cancel_scan(scan_id=scan_id, analyst=analyst, db=db)
        message = None
    except HTTPException as exc:
        # Already finished between render and click. Show the current state
        # rather than an error page — the scan is in the state they wanted.
        scan = await api.read_scan(scan_id=scan_id, user=analyst, db=db)
        message = error_text(exc)

    tasks = await api.list_scan_tasks(scan_id=scan_id, user=analyst, db=db)
    coverage = (
        None
        if _is_active(scan)
        else await api.read_scan_coverage(scan_id=scan_id, user=analyst, db=db)
    )
    return render_fragment(
        request,
        "scan_status.html",
        viewer,
        _status_context(scan, tasks, coverage=coverage) | {"message": message},
    )


def _status_context(
    scan: ScanRead,
    tasks: Sequence[ScanTaskRead],
    *,
    coverage: CoverageManifest | None = None,
) -> dict[str, object]:
    """Everything the status fragment renders, computed in one place.

    Progress is counted from the tasks rather than taken from a field: a scan's
    task set grows when discovery fans out, so "3 of 4" at one moment and "3 of
    40" a second later are both true, and a stored percentage would be neither.
    """
    finished = [task for task in tasks if task.status in TERMINAL_TASK_STATUSES]
    total = len(tasks)
    return {
        "scan": scan,
        "tasks": tasks,
        "active": _is_active(scan),
        "poll_seconds": POLL_INTERVAL_SECONDS,
        "task_total": total,
        "task_finished": len(finished),
        "percent": int(len(finished) * 100 / total) if total else 0,
        "message": None,
        "coverage": coverage,
    }


def _status_or_none(value: str | None) -> ScanStatus | None:
    """A status filter from the query string, ignoring one we do not recognise."""
    if not value:
        return None
    try:
        return ScanStatus(value)
    except ValueError:
        return None
