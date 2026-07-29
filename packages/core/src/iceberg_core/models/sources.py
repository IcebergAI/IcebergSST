"""Scan targets and their schedules."""

import uuid
from datetime import datetime
from typing import Any

from sqlmodel import Field

from iceberg_core.enums import SourceType
from iceberg_core.models.base import (
    TimestampedModel,
    enum_type,
    json_type,
    utc_timestamp_type,
)


class Source(TimestampedModel, table=True):
    """A system to scan: a Confluence instance, a Jira project, a file share."""

    __tablename__ = "source"

    name: str = Field(max_length=255, unique=True)
    type: SourceType = Field(sa_type=enum_type(SourceType, name="source_type"))

    #: Base URL plus scope filters (spaces, paths). Never credentials.
    connection: dict[str, Any] = Field(default_factory=dict, sa_type=json_type())

    #: An opaque handle into the secret store (ADR 0007) — never the secret. The
    #: API resolves it to a credential only when handing an engine a task lease.
    credential_ref: str | None = Field(default=None, max_length=4096)

    enabled: bool = Field(default=True)
    created_by_id: uuid.UUID | None = Field(
        default=None,
        foreign_key="app_user.id",
        ondelete="SET NULL",
    )


class Schedule(TimestampedModel, table=True):
    """A cron cadence for scanning one source.

    The scheduler polls on ``next_run_at`` under a Postgres advisory lock so that
    horizontally scaled API replicas fire each due schedule exactly once
    (docs/deployment.md § Scaling model).
    """

    __tablename__ = "schedule"

    source_id: uuid.UUID = Field(foreign_key="source.id", ondelete="CASCADE", index=True)
    cron: str = Field(max_length=128)
    enabled: bool = Field(default=True)
    next_run_at: datetime | None = Field(default=None, sa_type=utc_timestamp_type(), index=True)
    last_run_at: datetime | None = Field(default=None, sa_type=utc_timestamp_type())
