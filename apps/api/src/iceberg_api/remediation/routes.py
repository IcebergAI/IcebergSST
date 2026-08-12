"""Guidance and remediation-action routes (#142, ADR 0011).

Reads are viewer+ like the findings they hang off — with the *shape* of an
action role-shaped down for viewers (labels, not URLs; no note). Writes are
analyst+ and CSRF-protected like triage, because recording what was done about
a secret is a decision with a name attached.
"""

import uuid

import structlog
from fastapi import APIRouter, HTTPException, status
from iceberg_core.enums import UserRole
from iceberg_core.models import Finding, RemediationAction
from pydantic import BaseModel

from iceberg_api.auth.dependencies import CsrfProtected, SessionDep
from iceberg_api.auth.rbac import ROLE_RANK, AnalystUser, ViewerUser
from iceberg_api.remediation import service
from iceberg_api.remediation.guidance import GuidanceEntry, load_catalog
from iceberg_api.remediation.schemas import (
    RemediationCreate,
    RemediationRead,
    RemediationReadRedacted,
    RemediationRetract,
    RemediationVerify,
)

router = APIRouter(tags=["remediation"])
logger = structlog.get_logger()


class GuidanceRead(BaseModel):
    """One rule's guidance, with the honesty bit: which entry answered."""

    version: str
    rule_id: str
    matched: str
    entry: GuidanceEntry


@router.get("/remediation/guidance/{rule_id}")
async def read_guidance(rule_id: str, user: ViewerUser) -> GuidanceRead:
    """The advice for one rule — its own entry, or the default, and says which."""
    catalog = load_catalog()
    entry, matched = catalog.lookup(rule_id)
    return GuidanceRead(version=catalog.version, rule_id=rule_id, matched=matched, entry=entry)


def _load_finding(db: SessionDep, finding_id: uuid.UUID) -> Finding:
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "finding not found")
    return finding


def _load_action(
    db: SessionDep, finding_id: uuid.UUID, remediation_id: uuid.UUID
) -> RemediationAction:
    action = db.get(RemediationAction, remediation_id)
    if action is None or action.finding_id != finding_id:
        # A mismatched pair is a 404, not a 403: the ids simply do not name a
        # record, and saying more would confirm the other id exists.
        raise HTTPException(status.HTTP_404_NOT_FOUND, "remediation action not found")
    return action


@router.get("/findings/{finding_id}/remediations")
async def list_remediations(
    finding_id: uuid.UUID,
    user: ViewerUser,
    db: SessionDep,
) -> list[RemediationRead | RemediationReadRedacted]:
    """Every action on one finding, oldest first, in the caller's shape."""
    _load_finding(db, finding_id)
    redacted = ROLE_RANK[user.role] < ROLE_RANK[UserRole.ANALYST]
    return [
        service.serialize(action, redacted=redacted)
        for action in service.actions_for(db, finding_id)
    ]


@router.post(
    "/findings/{finding_id}/remediations",
    status_code=status.HTTP_201_CREATED,
    dependencies=[CsrfProtected],
)
async def record_remediation(
    finding_id: uuid.UUID,
    payload: RemediationCreate,
    analyst: AnalystUser,
    db: SessionDep,
) -> RemediationRead:
    """Record a containment action. Stamps the live guidance version."""
    finding = _load_finding(db, finding_id)
    action = service.record(
        db,
        finding,
        payload,
        actor_id=analyst.id,
        guidance_version=load_catalog().version,
    )
    db.commit()
    db.refresh(action)
    return RemediationRead.model_validate(action)


@router.post(
    "/findings/{finding_id}/remediations/{remediation_id}/verify", dependencies=[CsrfProtected]
)
async def verify_remediation(
    finding_id: uuid.UUID,
    remediation_id: uuid.UUID,
    payload: RemediationVerify,
    analyst: AnalystUser,
    db: SessionDep,
) -> RemediationRead:
    """Confirm the action took effect. One-way; repeating it is a 409."""
    action = _load_action(db, finding_id, remediation_id)
    try:
        service.verify(db, action, actor_id=analyst.id, comment=payload.comment)
    except (service.AlreadyVerified, service.AlreadyRetracted) as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    db.commit()
    db.refresh(action)
    return RemediationRead.model_validate(action)


@router.post(
    "/findings/{finding_id}/remediations/{remediation_id}/retract", dependencies=[CsrfProtected]
)
async def retract_remediation(
    finding_id: uuid.UUID,
    remediation_id: uuid.UUID,
    payload: RemediationRetract,
    analyst: AnalystUser,
    db: SessionDep,
) -> RemediationRead:
    """Close a wrong record, with the reason. Set-once; repeating it is a 409."""
    action = _load_action(db, finding_id, remediation_id)
    try:
        service.retract(db, action, actor_id=analyst.id, reason=payload.reason)
    except service.AlreadyRetracted as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    db.commit()
    db.refresh(action)
    return RemediationRead.model_validate(action)
