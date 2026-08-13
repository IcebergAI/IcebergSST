"""Recording, verifying, and retracting remediation actions (#142, ADR 0012).

Every mutation here writes two trail rows — a ``FindingEvent`` (the finding's
history an analyst reads) and an ``AuditEvent`` (the administrative record) —
which is what makes the *rows* safe to keep simple: content is write-once,
verification and retraction are set-once, and the immutable evidence #142
requires is the trail, not a temporal table.

Nothing commits; the route owns the transaction, same contract as ingest.
"""

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

import structlog
from iceberg_core.enums import (
    SEVERITY_RANK,
    FindingEventKind,
    RemediationVerification,
    Severity,
)
from iceberg_core.models import (
    AUDIT_REMEDIATION_RECORDED,
    AUDIT_REMEDIATION_RETRACTED,
    AUDIT_REMEDIATION_VERIFIED,
    AUDIT_TARGET_REMEDIATION,
    Finding,
    FindingEvent,
    RemediationAction,
)
from sqlmodel import Session, col, select, update

from iceberg_api import audit
from iceberg_api.remediation.schemas import (
    RemediationCreate,
    RemediationRead,
    RemediationReadRedacted,
)

logger = structlog.get_logger()


class AlreadyVerified(ValueError):
    """Verification is one-way and idempotence is not silence: say so."""


class AlreadyRetracted(ValueError):
    """A retracted action is closed; record a new action instead."""


@dataclass(frozen=True, slots=True)
class EvidencePolicy:
    """The deployment's bar for resolving a finding (#142).

    ``min_severity`` unset means the policy is off — the shipped default, like
    every optional behaviour here. When set, a finding at or above it cannot
    move to ``resolved`` without a qualifying action recorded first.
    """

    min_severity: Severity | None = None

    def applies_to(self, severity: Severity) -> bool:
        if self.min_severity is None:
            return False
        return SEVERITY_RANK[severity] >= SEVERITY_RANK[self.min_severity]


def record(
    db: Session,
    finding: Finding,
    payload: RemediationCreate,
    *,
    actor_id: uuid.UUID,
    guidance_version: str | None,
) -> RemediationAction:
    """Record one containment action. Content is final from this moment."""
    action = RemediationAction(
        finding_id=finding.id,
        actor_id=actor_id,
        kind=payload.kind,
        occurred_at=payload.occurred_at,
        note=payload.note,
        evidence_links=[link.model_dump() for link in payload.evidence_links],
        guidance_version=guidance_version,
    )
    db.add(action)
    db.flush()  # the event and audit rows below name its id

    # No free text on the event: the trail is viewer-visible, and the note is
    # role-shaped on the action row — the event says what happened, the row
    # (in the caller's shape) says the rest.
    db.add(
        FindingEvent(
            finding_id=finding.id,
            actor_id=actor_id,
            kind=FindingEventKind.REMEDIATION,
            to_value=payload.kind.value,
        )
    )
    audit.record(
        db,
        actor_id=actor_id,
        action=AUDIT_REMEDIATION_RECORDED,
        target_type=AUDIT_TARGET_REMEDIATION,
        target_id=action.id,
        detail={
            "finding_id": str(finding.id),
            "kind": payload.kind.value,
            "evidence_links": str(len(payload.evidence_links)),
        },
    )
    logger.info(
        "remediation_recorded",
        finding_id=str(finding.id),
        kind=payload.kind.value,
        actor_id=str(actor_id),
    )
    return action


def verify(
    db: Session,
    action: RemediationAction,
    *,
    actor_id: uuid.UUID,
    comment: str | None,
    now: datetime | None = None,
) -> RemediationAction:
    """Mark an action verified. One-way; a second verify is a conflict.

    The transition is claimed by a **conditional UPDATE** carrying the same
    predicates, not by the in-memory check alone: two analysts pressing the
    button at once would both pass a check-then-write and both append trail
    rows, leaving two "verified" events for one transition. Whichever statement
    matches zero rows lost the race and raises, exactly as a second sequential
    attempt does.
    """
    if action.retracted_at is not None:
        raise AlreadyRetracted("a retracted action cannot be verified")
    if action.verification is RemediationVerification.VERIFIED:
        raise AlreadyVerified("this action is already verified")

    at = now or datetime.now(UTC)
    claimed = db.exec(
        update(RemediationAction)
        .where(col(RemediationAction.id) == action.id)
        .where(col(RemediationAction.retracted_at).is_(None))
        .where(col(RemediationAction.verification) == RemediationVerification.UNVERIFIED)
        .values(
            verification=RemediationVerification.VERIFIED,
            verified_by_id=actor_id,
            verified_at=at,
        )
        .execution_options(synchronize_session="fetch")
    )
    if int(claimed.rowcount) == 0:
        raise AlreadyVerified("this action is already verified")
    db.refresh(action)

    db.add(
        FindingEvent(
            finding_id=action.finding_id,
            actor_id=actor_id,
            kind=FindingEventKind.REMEDIATION_VERIFIED,
            from_value=RemediationVerification.UNVERIFIED.value,
            to_value=RemediationVerification.VERIFIED.value,
        )
    )
    # The comment goes to the audit row, not the viewer-visible trail: it is
    # analyst free text about internal systems, same rule as the note.
    audit.record(
        db,
        actor_id=actor_id,
        action=AUDIT_REMEDIATION_VERIFIED,
        target_type=AUDIT_TARGET_REMEDIATION,
        target_id=action.id,
        detail={"finding_id": str(action.finding_id), **({"comment": comment} if comment else {})},
    )
    return action


def retract(
    db: Session,
    action: RemediationAction,
    *,
    actor_id: uuid.UUID,
    reason: str,
    now: datetime | None = None,
) -> RemediationAction:
    """Close a wrong record. Set-once; the reason is the story.

    Claimed by a conditional UPDATE for the same reason `verify` is: two
    concurrent retractions with different reasons would otherwise both succeed,
    leaving one stored reason and two audit rows each claiming to be the one
    that closed it.
    """
    if action.retracted_at is not None:
        raise AlreadyRetracted("this action is already retracted")

    at = now or datetime.now(UTC)
    claimed = db.exec(
        update(RemediationAction)
        .where(col(RemediationAction.id) == action.id)
        .where(col(RemediationAction.retracted_at).is_(None))
        .values(retracted_at=at, retracted_by_id=actor_id, retracted_reason=reason)
        .execution_options(synchronize_session="fetch")
    )
    if int(claimed.rowcount) == 0:
        raise AlreadyRetracted("this action is already retracted")
    db.refresh(action)

    db.add(
        FindingEvent(
            finding_id=action.finding_id,
            actor_id=actor_id,
            kind=FindingEventKind.REMEDIATION_RETRACTED,
            from_value=action.kind.value,
        )
    )
    audit.record(
        db,
        actor_id=actor_id,
        action=AUDIT_REMEDIATION_RETRACTED,
        target_type=AUDIT_TARGET_REMEDIATION,
        target_id=action.id,
        detail={"finding_id": str(action.finding_id), "reason": reason},
    )
    return action


def actions_for(db: Session, finding_id: uuid.UUID) -> list[RemediationAction]:
    """Every action on one finding, oldest first. Unpaginated and bounded —
    a finding accrues actions at human speed."""
    return list(
        db.exec(
            select(RemediationAction)
            .where(col(RemediationAction.finding_id) == finding_id)
            .order_by(col(RemediationAction.created_at), col(RemediationAction.id))
        )
    )


def qualifying_action_exists(db: Session, finding_id: uuid.UUID) -> bool:
    """Whether the finding carries an action the evidence policy accepts:
    not retracted, with at least one evidence link."""
    return any(
        action.retracted_at is None and len(action.evidence_links) > 0
        for action in actions_for(db, finding_id)
    )


def serialize(
    action: RemediationAction, *, redacted: bool
) -> RemediationRead | RemediationReadRedacted:
    """One action in the shape the caller's role earns."""
    if not redacted:
        return RemediationRead.model_validate(action)
    return RemediationReadRedacted(
        **RemediationReadRedacted.model_validate(action).model_dump(exclude={"evidence_labels"}),
        evidence_labels=[str(link.get("label", "evidence")) for link in action.evidence_links],
    )
