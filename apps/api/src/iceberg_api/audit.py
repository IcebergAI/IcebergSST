"""Writing and reading the administrative audit trail (#69, #64).

One place that appends to ``audit_event``, so every route records the same shape
and the audit-coverage review in #64 has a single call site to grep for.

Two rules:

* **Only real changes are recorded.** An audit log full of "changed viewer to
  viewer" is one nobody reads.
* **Never a secret.** ``from_value``/``to_value``/``detail`` describe *what*
  changed — a role, a flag, the fact that a credential was rotated — never the
  value of a credential.
"""

import uuid

import structlog
from iceberg_core.models import AuditEvent
from sqlmodel import Session, select

logger = structlog.get_logger()


def record(
    db: Session,
    *,
    actor_id: uuid.UUID | None,
    action: str,
    target_type: str,
    target_id: uuid.UUID | None,
    from_value: str | None = None,
    to_value: str | None = None,
    detail: dict[str, str] | None = None,
) -> AuditEvent:
    """Append one audit row and log it. Does not commit."""
    event = AuditEvent(
        actor_id=actor_id,
        action=action,
        target_type=target_type,
        target_id=target_id,
        from_value=from_value,
        to_value=to_value,
        detail=detail or {},
    )
    db.add(event)
    logger.info(
        "audit_event",
        action=action,
        actor_id=str(actor_id) if actor_id else None,
        target_type=target_type,
        target_id=str(target_id) if target_id else None,
        from_value=from_value,
        to_value=to_value,
    )
    return event


def events_for(db: Session, target_type: str, target_id: uuid.UUID) -> list[AuditEvent]:
    """Every recorded action against one object, oldest first."""
    statement = (
        select(AuditEvent)
        .where(AuditEvent.target_type == target_type)
        .where(AuditEvent.target_id == target_id)
        .order_by(AuditEvent.created_at)  # type: ignore[arg-type]
    )
    return list(db.exec(statement))
