"""Schedule CRUD (#33).

A schedule is a cron cadence attached to one source. Writes are admin-only —
scheduling a scan of somebody's Confluence is a configuration change, not triage —
and reads are open to any authenticated role so an analyst can see why a scan ran.

``next_run_at`` is computed here, when a schedule is created, enabled, or its cron
changes. The scheduler only ever reads it, which keeps "when does this fire next?"
answerable from the row itself rather than by re-deriving cron state.
"""

import uuid
from datetime import UTC, datetime
from typing import Annotated

import structlog
from fastapi import APIRouter, HTTPException, Query, Response, status
from iceberg_core.models import (
    AUDIT_SCHEDULE_CREATED,
    AUDIT_SCHEDULE_DELETED,
    AUDIT_SCHEDULE_UPDATED,
    AUDIT_TARGET_SCHEDULE,
    Schedule,
    Source,
)
from sqlmodel import select

from iceberg_api import audit
from iceberg_api.auth.dependencies import CsrfProtected, SessionDep
from iceberg_api.auth.rbac import AdminUser, ViewerUser
from iceberg_api.pagination import DEFAULT_LIMIT, MAX_LIMIT, after, build_page, position
from iceberg_api.scheduler import next_fire_time
from iceberg_api.schemas import Page
from iceberg_api.sources.schemas import ScheduleCreate, ScheduleRead, ScheduleUpdate

router = APIRouter(prefix="/schedules", tags=["schedules"])
logger = structlog.get_logger()


def _load(db: SessionDep, schedule_id: uuid.UUID) -> Schedule:
    schedule = db.get(Schedule, schedule_id)
    if schedule is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "schedule not found")
    return schedule


@router.get("")
async def list_schedules(
    user: ViewerUser,
    db: SessionDep,
    # Annotated form: ruff's B008 exemption for FastAPI defaults does not extend to
    # a UUID-typed query parameter, and this is the style FastAPI documents anyway.
    source_id: Annotated[uuid.UUID | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = DEFAULT_LIMIT,
    cursor: Annotated[str | None, Query()] = None,
) -> Page[ScheduleRead]:
    """List schedules, optionally for one source, in stable order."""
    statement = select(Schedule)
    if source_id is not None:
        statement = statement.where(Schedule.source_id == source_id)
    statement = after(
        statement,
        created_at=Schedule.created_at,  # type: ignore[arg-type]
        row_id=Schedule.id,  # type: ignore[arg-type]
        cursor=position(cursor),
    )
    rows = list(db.exec(statement.limit(limit + 1)))
    return build_page(rows, limit=limit, read=ScheduleRead.model_validate)


@router.get("/{schedule_id}")
async def read_schedule(schedule_id: uuid.UUID, user: ViewerUser, db: SessionDep) -> ScheduleRead:
    return ScheduleRead.model_validate(_load(db, schedule_id))


@router.post("", status_code=status.HTTP_201_CREATED, dependencies=[CsrfProtected])
async def create_schedule(
    body: ScheduleCreate,
    admin: AdminUser,
    db: SessionDep,
) -> ScheduleRead:
    """Attach a cron cadence to a source."""
    if db.get(Source, body.source_id) is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "source not found")

    now = datetime.now(UTC)
    schedule = Schedule(
        source_id=body.source_id,
        cron=body.cron,
        enabled=body.enabled,
        next_run_at=next_fire_time(body.cron, now) if body.enabled else None,
    )
    db.add(schedule)
    db.flush()
    audit.record(
        db,
        actor_id=admin.id,
        action=AUDIT_SCHEDULE_CREATED,
        target_type=AUDIT_TARGET_SCHEDULE,
        target_id=schedule.id,
        to_value=schedule.cron,
        detail={"source_id": str(schedule.source_id)},
    )
    db.commit()
    db.refresh(schedule)
    return ScheduleRead.model_validate(schedule)


@router.patch("/{schedule_id}", dependencies=[CsrfProtected])
async def update_schedule(
    schedule_id: uuid.UUID,
    changes: ScheduleUpdate,
    admin: AdminUser,
    db: SessionDep,
) -> ScheduleRead:
    """Change the cadence, or enable/disable it."""
    schedule = _load(db, schedule_id)
    now = datetime.now(UTC)
    changed: list[str] = []

    if changes.cron is not None and changes.cron.strip() != schedule.cron:
        schedule.cron = changes.cron.strip()
        changed.append("cron")

    if changes.enabled is not None and changes.enabled != schedule.enabled:
        schedule.enabled = changes.enabled
        changed.append("enabled")

    if changed:
        # Recomputed from now, not from the old next_run_at: a schedule re-enabled
        # after a week off should fire on its next cadence, not immediately for
        # every beat it missed.
        schedule.next_run_at = next_fire_time(schedule.cron, now) if schedule.enabled else None
        audit.record(
            db,
            actor_id=admin.id,
            action=AUDIT_SCHEDULE_UPDATED,
            target_type=AUDIT_TARGET_SCHEDULE,
            target_id=schedule.id,
            to_value=",".join(changed),
        )
        db.add(schedule)
        db.commit()
        db.refresh(schedule)

    return ScheduleRead.model_validate(schedule)


@router.delete(
    "/{schedule_id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=[CsrfProtected]
)
async def delete_schedule(
    schedule_id: uuid.UUID,
    admin: AdminUser,
    db: SessionDep,
) -> Response:
    schedule = _load(db, schedule_id)
    audit.record(
        db,
        actor_id=admin.id,
        action=AUDIT_SCHEDULE_DELETED,
        target_type=AUDIT_TARGET_SCHEDULE,
        target_id=schedule.id,
        from_value=schedule.cron,
    )
    db.delete(schedule)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
