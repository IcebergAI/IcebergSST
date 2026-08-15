"""Reading and dropping a source's incremental watermarks (#143, ADR 0013).

The recoverable state the acceptance criteria ask for. An incremental scan that
narrowed too far, or one whose watermark an operator no longer trusts, has to be
fixable without editing the source or waiting for the interval to elapse — so
dropping the cursors is a first-class action, and why a scan became a full one
stays readable afterwards.

Positions never leave the API. They may hold a provider change token, which is
bearer-ish for a place in a result set, so what is exposed is *whether* a scope has
a watermark and how old it is — never the watermark itself.
"""

import uuid
from datetime import UTC, datetime

import structlog
from fastapi import APIRouter, HTTPException, status
from iceberg_core.enums import CursorInvalidationReason
from iceberg_core.models import (
    AUDIT_SOURCE_UPDATED,
    AUDIT_TARGET_SOURCE,
    Source,
    SourceCursor,
)
from pydantic import BaseModel, ConfigDict
from sqlmodel import col, select

from iceberg_api import audit
from iceberg_api.auth.dependencies import CsrfProtected, SessionDep
from iceberg_api.auth.rbac import AdminUser, AnalystUser
from iceberg_api.scans import cursors as cursor_service
from iceberg_api.schemas import UtcDatetime

router = APIRouter(prefix="/sources", tags=["sources"])
logger = structlog.get_logger()


class SourceCursorRead(BaseModel):
    """One scope's watermark state. Never the position itself."""

    model_config = ConfigDict(extra="forbid")

    scope: str
    minted_at: UtcDatetime
    minted_by_scan_id: uuid.UUID
    rulepack_version: str | None
    invalidated_at: UtcDatetime | None
    invalidation_reason: CursorInvalidationReason | None


class SourceCursorsRead(BaseModel):
    """Every watermark a source holds, live and retired."""

    model_config = ConfigDict(extra="forbid")

    source_id: uuid.UUID
    #: How stale a live watermark may get before a scan is promoted to a full one.
    full_scan_interval_days: int
    cursors: list[SourceCursorRead]


class CursorsInvalidated(BaseModel):
    """What dropping them affected."""

    source_id: uuid.UUID
    invalidated: int


@router.get("/{source_id}/cursors")
async def read_source_cursors(
    source_id: uuid.UUID,
    analyst: AnalystUser,
    db: SessionDep,
) -> SourceCursorsRead:
    """What this source has read incrementally, and what it will re-read."""
    source = db.get(Source, source_id)
    if source is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "source not found")

    rows = db.exec(
        select(SourceCursor)
        .where(col(SourceCursor.source_id) == source_id)
        .order_by(col(SourceCursor.scope))
    )
    return SourceCursorsRead(
        source_id=source_id,
        full_scan_interval_days=source.full_scan_interval_days,
        cursors=[SourceCursorRead.model_validate(row, from_attributes=True) for row in rows],
    )


@router.delete("/{source_id}/cursors", dependencies=[CsrfProtected])
async def invalidate_source_cursors(
    source_id: uuid.UUID,
    admin: AdminUser,
    db: SessionDep,
) -> CursorsInvalidated:
    """Force the next scan of this source to be a full one.

    Retires the watermarks rather than deleting them, so the reason the next scan
    took longer stays answerable. Admin-only and audited: it changes what a
    scheduled scan costs, and — because only a full scan auto-resolves — when
    findings this source has stopped seeing are closed.
    """
    source = db.get(Source, source_id)
    if source is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "source not found")

    retired = cursor_service.invalidate(
        db,
        source_id,
        CursorInvalidationReason.OPERATOR_REQUESTED,
        now=datetime.now(UTC),
    )
    audit.record(
        db,
        actor_id=admin.id,
        action=AUDIT_SOURCE_UPDATED,
        target_type=AUDIT_TARGET_SOURCE,
        target_id=source_id,
        to_value="cursors_invalidated",
        detail={"invalidated": str(retired)},
    )
    db.commit()
    logger.info("source_cursors_dropped", source_id=str(source_id), count=retired)
    return CursorsInvalidated(source_id=source_id, invalidated=retired)
