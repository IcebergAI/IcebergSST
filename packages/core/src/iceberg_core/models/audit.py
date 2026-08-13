"""Append-only audit trail for administrative actions.

`FindingEvent` audits a finding's lifecycle. This table covers everything else an
operator needs to be able to reconstruct — starting with who changed whose role
(#69) — because "an admin appeared" should never be an unanswerable question.

``action`` is a plain string rather than an enum on purpose: the vocabulary grows
with every feature that records something, and a checked enum column would turn
each addition into a schema migration for no protection worth having. The
constants below are the vocabulary; a typo shows up as an unmatched filter, not as
a lost row.
"""

import uuid
from typing import Any

from sqlalchemy import Index
from sqlmodel import Field

from iceberg_core.models.base import IcebergModel, json_type

#: Recorded actions. Extend as features land.
AUDIT_USER_ROLE_CHANGED = "user.role_changed"
AUDIT_USER_DISABLED = "user.disabled"
AUDIT_USER_ENABLED = "user.enabled"
AUDIT_SOURCE_CREATED = "source.created"
AUDIT_SOURCE_UPDATED = "source.updated"
AUDIT_SOURCE_DELETED = "source.deleted"
AUDIT_SOURCE_CREDENTIAL_SET = "source.credential_set"
AUDIT_SOURCE_CREDENTIAL_ROTATED = "source.credential_rotated"
AUDIT_SCHEDULE_CREATED = "schedule.created"
AUDIT_SCHEDULE_UPDATED = "schedule.updated"
AUDIT_SCHEDULE_DELETED = "schedule.deleted"
AUDIT_SUPPRESSION_CREATED = "suppression.created"
AUDIT_SUPPRESSION_DELETED = "suppression.deleted"
AUDIT_ENGINE_REGISTERED = "engine.registered"
AUDIT_ENGINE_TOKEN_ROTATED = "engine.token_rotated"  # noqa: S105  # an audit action name
AUDIT_CHANNEL_CREATED = "channel.created"
AUDIT_CHANNEL_UPDATED = "channel.updated"
AUDIT_CHANNEL_DELETED = "channel.deleted"
AUDIT_CHANNEL_SECRET_SET = "channel.secret_set"  # noqa: S105  # an audit action name
#: Retention purges (#73). Deleting evidence is itself an administrative action,
#: so it is recorded — with counts, and with the window that justified it.
AUDIT_RETENTION_PURGED = "retention.purged"
AUDIT_VALIDATION_POLICY_CREATED = "validation_policy.created"
AUDIT_VALIDATION_POLICY_UPDATED = "validation_policy.updated"
AUDIT_VALIDATION_POLICY_DELETED = "validation_policy.deleted"
#: Exposure clusters (ADR 0011, #140): the full recompute after a key rotation,
#: and each analyst download of a cluster's membership.
AUDIT_CORRELATION_REINDEXED = "correlation.reindexed"
AUDIT_CORRELATION_CLUSTER_EXPORTED = "correlation.cluster_exported"
#: Remediation evidence (ADR 0012, #142). Every change to an action is an
#: administrative event; the rows themselves are write-once.
AUDIT_REMEDIATION_RECORDED = "remediation.recorded"
AUDIT_REMEDIATION_VERIFIED = "remediation.verified"
AUDIT_REMEDIATION_RETRACTED = "remediation.retracted"

#: Values for ``target_type``.
AUDIT_TARGET_USER = "user"
AUDIT_TARGET_SOURCE = "source"
AUDIT_TARGET_SCHEDULE = "schedule"
AUDIT_TARGET_SUPPRESSION = "suppression"
AUDIT_TARGET_ENGINE = "engine"
AUDIT_TARGET_CHANNEL = "channel"
#: A purge is about the deployment, not about one row, so it has no target id.
AUDIT_TARGET_RETENTION = "retention"
AUDIT_TARGET_VALIDATION_POLICY = "validation_policy"
#: A reindex is deployment-wide (no target id); an export's target id is not a
#: row id either — the correlation id itself goes in the detail.
AUDIT_TARGET_CORRELATION = "correlation"
AUDIT_TARGET_REMEDIATION = "remediation"


class AuditEvent(IcebergModel, table=True):
    """One recorded administrative action.

    Not a :class:`~iceberg_core.models.base.TimestampedModel`: an audit row that
    can be updated is not an audit row.
    """

    __tablename__ = "audit_event"
    __table_args__ = (
        # "What happened to this user?" and "what did this admin do?" are the two
        # questions asked of this table.
        Index("ix_audit_event_target_type_target_id", "target_type", "target_id"),
    )

    #: Null for system actions (scheduler, reconciliation, lease reclaim).
    actor_id: uuid.UUID | None = Field(
        default=None,
        foreign_key="app_user.id",
        ondelete="SET NULL",
    )
    action: str = Field(max_length=64, index=True)
    target_type: str = Field(max_length=64)
    target_id: uuid.UUID | None = Field(default=None)

    from_value: str | None = Field(default=None, max_length=255)
    to_value: str | None = Field(default=None, max_length=255)

    #: Anything else worth keeping. Never a secret, never a credential.
    detail: dict[str, Any] = Field(default_factory=dict, sa_type=json_type())
