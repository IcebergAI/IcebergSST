"""Suppression CRUD (#40 — ADR 0008).

Tuning lives in data, not code: silencing a known-benign match is an analyst's
call, made in the UI, and it takes effect without a rule-pack release. Writes are
analyst+ rather than admin, because this is triage work; every one is audited,
because a suppression is a decision to stop looking at something.

Create and delete are not just row writes. Creating one suppresses the findings it
already covers, and deleting one releases them — a suppression whose effect only
arrived with the next scan would look broken, and one whose deletion left findings
hidden with a dangling reference would be worse. There is no ``PATCH``: editing the
pattern of a live suppression would silently re-scope what it hides, and creating a
replacement leaves both decisions in the audit trail.
"""

import uuid
from datetime import UTC, datetime
from typing import Annotated

import structlog
from fastapi import APIRouter, HTTPException, Query, Response, status
from iceberg_core.enums import SuppressionScope
from iceberg_core.models import (
    AUDIT_SUPPRESSION_CREATED,
    AUDIT_SUPPRESSION_DELETED,
    AUDIT_TARGET_SUPPRESSION,
    Source,
    Suppression,
)
from sqlmodel import col, or_, select

from iceberg_api import audit, suppressions
from iceberg_api.auth.dependencies import CsrfProtected, SessionDep
from iceberg_api.auth.rbac import AnalystUser, ViewerUser
from iceberg_api.findings.schemas import SuppressionCreate, SuppressionRead
from iceberg_api.pagination import DEFAULT_LIMIT, MAX_LIMIT, after, build_page, position
from iceberg_api.schemas import Page

router = APIRouter(prefix="/suppressions", tags=["suppressions"])
logger = structlog.get_logger()


def _load(db: SessionDep, suppression_id: uuid.UUID) -> Suppression:
    suppression = db.get(Suppression, suppression_id)
    if suppression is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "suppression not found")
    return suppression


@router.get("")
async def list_suppressions(
    user: ViewerUser,
    db: SessionDep,
    source_id: Annotated[uuid.UUID | None, Query()] = None,
    scope: Annotated[SuppressionScope | None, Query()] = None,
    active: Annotated[bool | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = DEFAULT_LIMIT,
    cursor: Annotated[str | None, Query()] = None,
) -> Page[SuppressionRead]:
    """List suppressions, in stable order.

    ``?source_id=`` returns the ones that apply to that source, global entries
    included — "what is being hidden from this source" is the question asked, and
    an answer that omitted the global rules would be wrong.
    """
    statement = select(Suppression)
    if source_id is not None:
        statement = statement.where(
            or_(col(Suppression.source_id) == source_id, col(Suppression.source_id).is_(None))
        )
    if scope is not None:
        statement = statement.where(col(Suppression.scope) == scope)
    if active is not None:
        now = datetime.now(UTC)
        live = or_(col(Suppression.expires_at).is_(None), col(Suppression.expires_at) > now)
        statement = statement.where(live if active else ~live)

    statement = after(
        statement,
        created_at=Suppression.created_at,  # type: ignore[arg-type]  # instrumented attribute
        row_id=Suppression.id,  # type: ignore[arg-type]
        cursor=position(cursor),
    )
    rows = list(db.exec(statement.limit(limit + 1)))
    return build_page(rows, limit=limit, read=SuppressionRead.model_validate)


@router.post("", status_code=status.HTTP_201_CREATED, dependencies=[CsrfProtected])
async def create_suppression(
    body: SuppressionCreate,
    analyst: AnalystUser,
    db: SessionDep,
) -> SuppressionRead:
    """Silence a known-benign match, now and at every future ingest."""
    if body.source_id is not None and db.get(Source, body.source_id) is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "source not found")

    suppression = Suppression(
        scope=body.scope,
        pattern=body.pattern,
        source_id=body.source_id,
        reason=body.reason,
        created_by_id=analyst.id,
        expires_at=body.expires_at,
    )
    db.add(suppression)
    db.flush()

    covered = suppressions.apply_to_existing(db, suppression, actor_id=analyst.id)
    audit.record(
        db,
        actor_id=analyst.id,
        action=AUDIT_SUPPRESSION_CREATED,
        target_type=AUDIT_TARGET_SUPPRESSION,
        target_id=suppression.id,
        to_value=f"{suppression.scope.value}:{suppression.pattern}"[:255],
        detail={
            "source_id": str(suppression.source_id) if suppression.source_id else "global",
            "findings_suppressed": str(covered),
        },
    )
    db.commit()
    db.refresh(suppression)
    return SuppressionRead.model_validate(suppression)


@router.get("/{suppression_id}")
async def read_suppression(
    suppression_id: uuid.UUID, user: ViewerUser, db: SessionDep
) -> SuppressionRead:
    return SuppressionRead.model_validate(_load(db, suppression_id))


@router.delete(
    "/{suppression_id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=[CsrfProtected]
)
async def delete_suppression(
    suppression_id: uuid.UUID,
    analyst: AnalystUser,
    db: SessionDep,
) -> Response:
    """Remove a suppression and return everything it was hiding."""
    suppression = _load(db, suppression_id)
    released = suppressions.release_covered_by(db, suppression, actor_id=analyst.id)
    audit.record(
        db,
        actor_id=analyst.id,
        action=AUDIT_SUPPRESSION_DELETED,
        target_type=AUDIT_TARGET_SUPPRESSION,
        target_id=suppression.id,
        from_value=f"{suppression.scope.value}:{suppression.pattern}"[:255],
        detail={"findings_released": str(released)},
    )
    # After the release: the findings must be detached from the row before it goes,
    # or the FK nulls itself and their explanation goes with it.
    db.delete(suppression)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
