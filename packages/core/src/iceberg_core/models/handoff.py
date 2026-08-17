"""Handing a finding to an external workflow, and knowing what happened (#141).

Two tables and one hard requirement: **repeated delivery must create one external
work item.** Everything about the shape here follows from that.

A handoff is *not* a notification. A notification is fire-and-forget — it says
something happened, and once it is delivered the record is only useful as
history. A handoff creates an object in somebody else's system that then has a
life of its own: an id, a state, a person assigned to it. So it is a row per
(target, finding) with a uniqueness constraint on exactly that pair, rather than
a row per delivery attempt.

The retry machinery is deliberately the same shape as
:class:`~iceberg_core.models.notifications.NotificationDelivery`, because the
failure modes are identical — a receiver that is down, a timeout, a ceiling past
which giving up is more honest than retrying forever.
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Index, UniqueConstraint
from sqlmodel import Field

from iceberg_core.enums import HandoffStatus, HandoffTargetType
from iceberg_core.models.base import (
    TimestampedModel,
    enum_type,
    json_type,
    utc_timestamp_type,
)


class HandoffTarget(TimestampedModel, table=True):
    """An approved external workflow findings may be handed to.

    Admin-only to configure, like a notification channel and for a stronger
    version of the same reason: this carries finding metadata off the deployment
    *and* accepts state back from whatever is on the other end.
    """

    __tablename__ = "handoff_target"

    name: str = Field(max_length=255, unique=True)
    type: HandoffTargetType = Field(
        default=HandoffTargetType.WEBHOOK,
        sa_type=enum_type(HandoffTargetType, name="handoff_target_type"),
    )

    #: The destination URL and the field mapping. May carry a secret ref; never a
    #: raw secret (ADR 0007).
    config: dict[str, Any] = Field(default_factory=dict, sa_type=json_type())

    #: Which findings an operator may hand over: minimum severity, source scope.
    #: The same shape a notification channel uses, so one filter vocabulary
    #: covers both egress paths.
    event_filter: dict[str, Any] = Field(default_factory=dict, sa_type=json_type())

    enabled: bool = Field(default=True)


class FindingHandoff(TimestampedModel, table=True):
    """One finding, handed to one target, once.

    The unique constraint is the whole idempotency story, and it is structural
    rather than a check somebody has to remember: a second hand-over of the same
    finding to the same target cannot be inserted, so it cannot become a second
    ticket no matter how many times a button is pressed or a retry fires.
    """

    __tablename__ = "finding_handoff"
    __table_args__ = (
        # "Repeated delivery creates one external work item", as a constraint.
        UniqueConstraint(
            "target_id",
            "finding_id",
            name="uq_finding_handoff_target_id_finding_id",
        ),
        # The delivery loop's query: what is pending and due.
        Index("ix_finding_handoff_status_next_attempt_at", "status", "next_attempt_at"),
        # The unique constraint leads on target_id, so it cannot serve the per-row
        # lookup Postgres does to enforce the finding CASCADE — and retention
        # deletes findings a thousand at a time (#73).
        Index("ix_finding_handoff_finding_id", "finding_id"),
    )

    target_id: uuid.UUID = Field(foreign_key="handoff_target.id", ondelete="CASCADE")
    finding_id: uuid.UUID = Field(foreign_key="finding.id", ondelete="CASCADE")

    #: Who asked for it. SET NULL rather than CASCADE: the handoff outlives the
    #: account, and "who sent our finding to that system" must stay answerable.
    requested_by_id: uuid.UUID | None = Field(
        default=None,
        foreign_key="app_user.id",
        ondelete="SET NULL",
    )

    #: Sent with every attempt and **never regenerated**. The receiving system is
    #: expected to treat it as its own dedup key, which is what makes a retry
    #: after a lost response safe: our constraint stops a second row, and this
    #: stops a second ticket when the first request did arrive and the reply did
    #: not. Regenerating it on retry would defeat both.
    idempotency_key: str = Field(max_length=128, unique=True)

    status: HandoffStatus = Field(
        default=HandoffStatus.PENDING,
        sa_type=enum_type(HandoffStatus, name="handoff_status"),
    )
    attempts: int = Field(default=0, ge=0)
    #: When this row becomes eligible; pushed out by backoff after each failure.
    next_attempt_at: datetime = Field(sa_type=utc_timestamp_type())
    delivered_at: datetime | None = Field(default=None, sa_type=utc_timestamp_type())

    #: Why the last attempt failed. Truncated, and never a response body: what is
    #: on the other end is somebody else's system and could echo anything back.
    last_error: str | None = Field(default=None, max_length=500)

    #: What the external system called the work item, if it said. Free-form
    #: because every platform names them differently, and a link so an analyst
    #: can get there in one click.
    external_id: str | None = Field(default=None, max_length=255)
    external_url: str | None = Field(default=None, max_length=2048)
