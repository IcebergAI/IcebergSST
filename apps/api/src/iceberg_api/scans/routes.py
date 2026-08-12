"""Launching, reading, and cancelling scans (#34, #68).

Analysts run and cancel scans; any authenticated role can read them, because "why
does this finding exist" is answered by the scan that found it.

Cancellation is honest about what it can do: it marks the scan and its unfinished
tasks, which stops queued tasks from ever being leased and tells a running engine at
its next heartbeat. There is no way to reach into a worker mid-fetch, and a
cancelled scan never reconciles — it did not see the whole source (ADR 0009 §4).
"""

import uuid
from typing import Annotated

import structlog
from fastapi import APIRouter, HTTPException, Query, Response, status
from iceberg_core.enums import ACTIVE_SCAN_STATUSES, ScanStatus, ScanTrigger
from iceberg_core.models import Scan, ScanTask, Source
from sqlmodel import col, select

from iceberg_api.auth.dependencies import CsrfProtected, SessionDep
from iceberg_api.auth.rbac import AnalystUser, ViewerUser
from iceberg_api.dispatch import DispatcherDep
from iceberg_api.engines.schemas import ScanTaskRead
from iceberg_api.pagination import DEFAULT_LIMIT, MAX_LIMIT, after, build_page, position
from iceberg_api.scans import coverage as coverage_service
from iceberg_api.scans import service
from iceberg_api.scans.schemas import CoverageManifest, ScanRead
from iceberg_api.schemas import Page

router = APIRouter(tags=["scans"])
logger = structlog.get_logger()


def _load(db: SessionDep, scan_id: uuid.UUID) -> Scan:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scan not found")
    return scan


@router.post(
    "/sources/{source_id}/scan",
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[CsrfProtected],
)
async def trigger_scan(
    source_id: uuid.UUID,
    analyst: AnalystUser,
    db: SessionDep,
    dispatcher: DispatcherDep,
) -> ScanRead:
    """Start an on-demand scan: one scan, one discovery task, one dispatch.

    202, not 201: the scan exists but nothing has been scanned yet — an engine has to
    lease the discovery task first.
    """
    source = db.get(Source, source_id)
    if source is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "source not found")
    if not source.enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "source is disabled")

    try:
        scan = service.launch_scan(db, source, trigger=ScanTrigger.MANUAL, dispatcher=dispatcher)
    except service.ScanConflict as exc:
        # The partial unique index refused it. Reporting the scan already running is
        # more useful than reporting a constraint.
        active = service.active_scan_for(db, source.id)
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"source already has an active scan ({active.id if active else 'unknown'})",
        ) from exc

    logger.info("scan_triggered", scan_id=str(scan.id), actor_id=str(analyst.id))
    return ScanRead.model_validate(scan)


@router.get("/scans")
async def list_scans(
    user: ViewerUser,
    db: SessionDep,
    source_id: Annotated[uuid.UUID | None, Query()] = None,
    scan_status: Annotated[ScanStatus | None, Query(alias="status")] = None,
    active: Annotated[bool | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = DEFAULT_LIMIT,
    cursor: Annotated[str | None, Query()] = None,
) -> Page[ScanRead]:
    """List scans, filterable by source, status, or just "still running"."""
    statement = select(Scan)
    if source_id is not None:
        statement = statement.where(col(Scan.source_id) == source_id)
    if scan_status is not None:
        statement = statement.where(col(Scan.status) == scan_status)
    if active is not None:
        in_flight = col(Scan.status).in_(list(ACTIVE_SCAN_STATUSES))
        statement = statement.where(in_flight if active else ~in_flight)

    statement = after(
        statement,
        created_at=Scan.created_at,  # type: ignore[arg-type]
        row_id=Scan.id,  # type: ignore[arg-type]
        cursor=position(cursor),
    )
    rows = list(db.exec(statement.limit(limit + 1)))
    return build_page(rows, limit=limit, read=ScanRead.model_validate)


@router.get("/scans/{scan_id}")
async def read_scan(scan_id: uuid.UUID, user: ViewerUser, db: SessionDep) -> ScanRead:
    return ScanRead.model_validate(_load(db, scan_id))


def _coverage_for(db: SessionDep, scan: Scan) -> CoverageManifest:
    if scan.status in ACTIVE_SCAN_STATUSES:
        raise HTTPException(status.HTTP_409_CONFLICT, "scan coverage is available when it finishes")
    tasks = list(
        db.exec(
            select(ScanTask)
            .where(col(ScanTask.scan_id) == scan.id)
            .order_by(col(ScanTask.created_at), col(ScanTask.id))
        )
    )
    return coverage_service.frozen_or_built_manifest(scan, tasks)


@router.get("/scans/{scan_id}/coverage")
async def read_scan_coverage(
    scan_id: uuid.UUID,
    user: ViewerUser,
    db: SessionDep,
) -> CoverageManifest:
    """The immutable allowlisted coverage evidence for one terminal scan."""
    return _coverage_for(db, _load(db, scan_id))


@router.get("/scans/{scan_id}/coverage/export")
async def export_scan_coverage(
    scan_id: uuid.UUID,
    user: ViewerUser,
    db: SessionDep,
) -> Response:
    """Download byte-stable JSON containing no source content or task details."""
    manifest = _coverage_for(db, _load(db, scan_id))
    return Response(
        content=manifest.model_dump_json(),
        media_type="application/json",
        headers={
            "Cache-Control": "no-store",
            "Content-Disposition": f'attachment; filename="scan-{scan_id}-coverage.json"',
        },
    )


@router.get("/sources/{source_id}/coverage")
async def read_source_coverage(
    source_id: uuid.UUID,
    user: ViewerUser,
    db: SessionDep,
) -> CoverageManifest:
    """Latest terminal assurance for a source, ignoring any newer active run."""
    if db.get(Source, source_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "source not found")
    scan = db.exec(
        select(Scan)
        .where(col(Scan.source_id) == source_id)
        .where(col(Scan.status).not_in(list(ACTIVE_SCAN_STATUSES)))
        .order_by(col(Scan.finished_at).desc(), col(Scan.created_at).desc(), col(Scan.id).desc())
    ).first()
    if scan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "source has no terminal scan coverage")
    return _coverage_for(db, scan)


@router.get("/scans/{scan_id}/tasks")
async def list_scan_tasks(
    scan_id: uuid.UUID,
    user: ViewerUser,
    db: SessionDep,
) -> list[ScanTaskRead]:
    """The scan's tasks, for the live-status view (#56).

    Specs are omitted: they name the resources being fetched, which is more detail
    than a status view needs and more than a viewer should be handed.
    """
    _load(db, scan_id)
    tasks = db.exec(
        select(ScanTask)
        .where(col(ScanTask.scan_id) == scan_id)
        .order_by(col(ScanTask.created_at), col(ScanTask.id))
    )
    return [ScanTaskRead.model_validate(task) for task in tasks]


@router.post("/scans/{scan_id}/cancel", dependencies=[CsrfProtected])
async def cancel_scan(
    scan_id: uuid.UUID,
    analyst: AnalystUser,
    db: SessionDep,
) -> ScanRead:
    """Cancel a running scan.

    Cancelling a finished scan is a conflict rather than a silent success: the caller
    believes something is running that is not, and telling them so is more useful
    than pretending to act.
    """
    scan = _load(db, scan_id)
    if scan.status not in ACTIVE_SCAN_STATUSES:
        raise HTTPException(status.HTTP_409_CONFLICT, f"scan is already {scan.status.value}")

    cancelled = service.cancel_scan(db, scan)
    logger.info("scan_cancel_requested", scan_id=str(scan.id), actor_id=str(analyst.id))
    return ScanRead.model_validate(cancelled)
