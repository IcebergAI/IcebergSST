"""Notification channels — a deliberate egress path for finding metadata."""

from typing import Any

from sqlmodel import Field

from iceberg_core.enums import NotificationChannelType
from iceberg_core.models.base import TimestampedModel, enum_type, json_type


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
