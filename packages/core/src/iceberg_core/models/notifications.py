"""Notification channels — a deliberate egress path for finding metadata."""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Index, UniqueConstraint
from sqlmodel import Field

from iceberg_core.enums import NotificationChannelType, NotificationDeliveryStatus
from iceberg_core.models.base import (
    TimestampedModel,
    enum_type,
    json_type,
    utc_timestamp_type,
)


class NotificationChannel(TimestampedModel, table=True):
    """Where newly-opened findings are announced.

    A webhook channel sends redacted snippets and resource locations to an
    arbitrary URL, so channel configuration is admin-only and audit-logged
    (docs/security.md § Notification egress).
    """

    __tablename__ = "notification_channel"

    name: str = Field(max_length=255, unique=True)
    type: NotificationChannelType = Field(
        sa_type=enum_type(NotificationChannelType, name="notification_channel_type")
    )

    #: SMTP recipients, or the webhook URL and headers. May contain a secret ref;
    #: never a raw secret.
    config: dict[str, Any] = Field(default_factory=dict, sa_type=json_type())

    #: Which findings qualify: minimum severity, source scope.
    event_filter: dict[str, Any] = Field(default_factory=dict, sa_type=json_type())

    enabled: bool = Field(default=True)


class NotificationDelivery(TimestampedModel, table=True):
    """One announcement, to one channel, about one finding (#60).

    A transactional outbox. The row is written in the same transaction that opens
    the finding, so "the finding exists" and "somebody will be told" commit or
    fail together — the alternative is sending inside the request and losing the
    alert to a webhook timeout, which is the "never lost silently" half of the
    acceptance criteria.

    Delivery is then somebody else's problem: the maintenance loop picks up rows
    that are due, attempts them, and either marks them delivered or schedules a
    retry. Because the attempt happens outside the ingest transaction, a slow SMTP
    server delays an alert rather than a scan.
    """

    __tablename__ = "notification_delivery"
    __table_args__ = (
        # At most one announcement per channel per finding per scan. This is what
        # makes the whole path idempotent: the sweep that re-finalizes a stalled
        # scan re-runs enqueueing, and a retried round must not tell an operator
        # twice about one secret.
        UniqueConstraint(
            "channel_id",
            "finding_id",
            "scan_id",
            name="uq_notification_delivery_channel_finding_scan",
        ),
        # The delivery loop's query: what is pending and due.
        Index("ix_notification_delivery_status_next_attempt_at", "status", "next_attempt_at"),
    )

    channel_id: uuid.UUID = Field(foreign_key="notification_channel.id", ondelete="CASCADE")
    finding_id: uuid.UUID = Field(foreign_key="finding.id", ondelete="CASCADE")
    #: The scan that opened the finding. CASCADE rather than the RESTRICT the
    #: finding uses for its own scan references: this row is a delivery record,
    #: not part of the finding's history, so retention pruning old scans (#73)
    #: should take it rather than be blocked by it.
    scan_id: uuid.UUID = Field(foreign_key="scan.id", ondelete="CASCADE")

    status: NotificationDeliveryStatus = Field(
        default=NotificationDeliveryStatus.PENDING,
        sa_type=enum_type(NotificationDeliveryStatus, name="notification_delivery_status"),
    )
    attempts: int = Field(default=0, ge=0)
    #: When this row becomes eligible. Set to the enqueue time, then pushed out by
    #: exponential backoff after each failure.
    next_attempt_at: datetime = Field(sa_type=utc_timestamp_type())
    delivered_at: datetime | None = Field(default=None, sa_type=utc_timestamp_type())

    #: Why the last attempt failed. Truncated, and never carries a response body:
    #: a webhook's reply is somebody else's data and could echo anything back.
    last_error: str | None = Field(default=None, max_length=500)
