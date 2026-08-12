"""Listing, reading, and triaging findings (#38, #39).

Reads are open to any authenticated role; triage is analyst+. The split matters:
looking at the queue is how an on-call engineer answers "is this mine?", while
deciding a secret is a false positive is a judgement that has to have a name
attached to it.

Filters compose — every one narrows the same statement, so
``?state=open&suppressed=false&severity=critical`` means what it reads like. There
is no implicit filter: the analyst's default view is a query the client sends, not
a rule buried in this module, because a list endpoint that silently drops rows is
one nobody can reconcile a count against.
"""

import uuid
from typing import Annotated

import structlog
from fastapi import APIRouter, HTTPException, Query, status
from iceberg_core.enums import FindingState, Severity, UserRole
from iceberg_core.models import Finding, FindingEvent, User
from sqlalchemy import func
from sqlmodel import col, select

from iceberg_api.auth.dependencies import CsrfProtected, SessionDep
from iceberg_api.auth.rbac import ROLE_RANK, AnalystUser, ViewerUser
from iceberg_api.findings import triage
from iceberg_api.findings.schemas import (
    CorrelationInfo,
    FindingDetail,
    FindingEventRead,
    FindingRead,
    FindingUpdate,
)
from iceberg_api.pagination import DEFAULT_LIMIT, MAX_LIMIT, after, build_page, position
from iceberg_api.schemas import Page

router = APIRouter(prefix="/findings", tags=["findings"])
logger = structlog.get_logger()


def _load(db: SessionDep, finding_id: uuid.UUID) -> Finding:
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "finding not found")
    return finding


def _history(db: SessionDep, finding_id: uuid.UUID) -> list[FindingEvent]:
    """One finding's audit trail, oldest first."""
    return list(
        db.exec(
            select(FindingEvent)
            .where(col(FindingEvent.finding_id) == finding_id)
            .order_by(col(FindingEvent.created_at), col(FindingEvent.id))
        )
    )


@router.get("")
async def list_findings(
    user: ViewerUser,
    db: SessionDep,
    source_id: Annotated[uuid.UUID | None, Query()] = None,
    state: Annotated[FindingState | None, Query()] = None,
    rule_id: Annotated[str | None, Query()] = None,
    severity: Annotated[Severity | None, Query()] = None,
    assignee_id: Annotated[uuid.UUID | None, Query()] = None,
    suppressed: Annotated[bool | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = DEFAULT_LIMIT,
    cursor: Annotated[str | None, Query()] = None,
) -> Page[FindingRead]:
    """The findings queue, filtered and in stable `(created_at, id)` order."""
    statement = select(Finding)
    if source_id is not None:
        statement = statement.where(col(Finding.source_id) == source_id)
    if state is not None:
        statement = statement.where(col(Finding.state) == state)
    if rule_id is not None:
        statement = statement.where(col(Finding.rule_id) == rule_id)
    if severity is not None:
        statement = statement.where(col(Finding.severity) == severity)
    if assignee_id is not None:
        statement = statement.where(col(Finding.assignee_id) == assignee_id)
    if suppressed is not None:
        hidden = col(Finding.suppressed_at).is_not(None)
        statement = statement.where(hidden if suppressed else ~hidden)

    statement = after(
        statement,
        created_at=Finding.created_at,  # type: ignore[arg-type]  # instrumented attribute
        row_id=Finding.id,  # type: ignore[arg-type]
        cursor=position(cursor),
    )
    # One extra row answers "is there another page?" without a second count query.
    rows = list(db.exec(statement.limit(limit + 1)))
    return build_page(rows, limit=limit, read=FindingRead.model_validate)


def _correlation_info(db: SessionDep, finding: Finding, user: User) -> CorrelationInfo | None:
    """The finding's cluster counts — for analysts, on findings that have an id.

    Role-shaped rather than a separate route: viewers get ``null`` in the same
    field, because the comparison oracle is scoped to the roles that remediate
    (ADR 0010; the module docstring in `schemas.py` carries the argument).
    """
    if ROLE_RANK[user.role] < ROLE_RANK[UserRole.ANALYST] or finding.correlation_id is None:
        return None
    findings, sources = db.exec(
        select(
            func.count(col(Finding.id)),
            func.count(col(Finding.source_id).distinct()),
        ).where(col(Finding.correlation_id) == finding.correlation_id)
    ).one()
    return CorrelationInfo(
        correlation_id=finding.correlation_id,
        finding_count=int(findings),
        source_count=int(sources),
    )


@router.get("/{finding_id}")
async def read_finding(finding_id: uuid.UUID, user: ViewerUser, db: SessionDep) -> FindingDetail:
    """One finding and its full history — who changed it, when, and why."""
    finding = _load(db, finding_id)
    return FindingDetail(
        **FindingRead.model_validate(finding).model_dump(),
        events=[FindingEventRead.model_validate(event) for event in _history(db, finding_id)],
        correlation=_correlation_info(db, finding, user),
    )


@router.patch("/{finding_id}", dependencies=[CsrfProtected])
async def update_finding(
    finding_id: uuid.UUID,
    changes: FindingUpdate,
    analyst: AnalystUser,
    db: SessionDep,
) -> FindingDetail:
    """Triage a finding: change its state, assign it, or annotate it.

    Returns the detail shape, history included, because the event this call just
    wrote is the thing the caller most wants to see.
    """
    finding = _load(db, finding_id)

    if changes.assignee_id is not None:
        assignee = db.get(User, changes.assignee_id)
        if assignee is None or assignee.disabled:
            # 422, not 404: the finding was found, the body was wrong. Assigning
            # work to a disabled account is a quiet way to lose a finding.
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_CONTENT, "assignee is not an active user"
            )

    try:
        triage.apply(db, finding, changes, actor_id=analyst.id)
    except triage.IllegalTransition as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc

    db.commit()
    db.refresh(finding)
    return FindingDetail(
        **FindingRead.model_validate(finding).model_dump(),
        events=[FindingEventRead.model_validate(event) for event in _history(db, finding_id)],
        correlation=_correlation_info(db, finding, analyst),
    )
