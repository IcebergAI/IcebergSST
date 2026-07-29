"""Engines, scans, and the tasks engines lease (ADR 0009)."""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Index, text
from sqlmodel import Field

from iceberg_core.enums import (
    ACTIVE_SCAN_STATUSES,
    EngineStatus,
    ScanStatus,
    ScanTaskKind,
    ScanTaskStatus,
    ScanTrigger,
)
from iceberg_core.models.base import (
    TimestampedModel,
    enum_type,
    json_type,
    utc_timestamp_type,
)

#: SQL literal list backing the "one active scan per source" partial index. Built
#: from the enum so the index and the code cannot drift apart.
_ACTIVE_SCAN_SQL = ", ".join(f"'{status.value}'" for status in sorted(ACTIVE_SCAN_STATUSES))
_ACTIVE_SCAN_WHERE = text(f"status IN ({_ACTIVE_SCAN_SQL})")


class Engine(TimestampedModel, table=True):
    """A registered worker.

    Only a hash of the engine token is stored: the API can verify a presented
    token but cannot reproduce one, so a database compromise does not yield engine
    credentials. ``created_at`` is the registration time.
    """

    __tablename__ = "engine"

    name: str = Field(max_length=255, unique=True)
    token_hash: str = Field(max_length=128, unique=True, index=True)
    version: str | None = Field(default=None, max_length=64)
    status: EngineStatus = Field(
        default=EngineStatus.ACTIVE,
        sa_type=enum_type(EngineStatus, name="engine_status"),
    )
    last_heartbeat_at: datetime | None = Field(default=None, sa_type=utc_timestamp_type())


class Scan(TimestampedModel, table=True):
    """One scan run of a source, two-phase (discovery fans out into fetch tasks).

    The partial unique index enforces **one active scan per source**: concurrent
    scans of the same source would let two reconciliations race and resolve each
    other's findings (ADR 0006/0009).
    """

    __tablename__ = "scan"
    __table_args__ = (
        Index(
            "uq_scan_active_per_source",
            "source_id",
            unique=True,
            postgresql_where=_ACTIVE_SCAN_WHERE,
            sqlite_where=_ACTIVE_SCAN_WHERE,
        ),
    )

    source_id: uuid.UUID = Field(foreign_key="source.id", ondelete="CASCADE", index=True)
    trigger: ScanTrigger = Field(sa_type=enum_type(ScanTrigger, name="scan_trigger"))
    status: ScanStatus = Field(
        default=ScanStatus.QUEUED,
        sa_type=enum_type(ScanStatus, name="scan_status"),
    )

    #: The rule-pack version that produced this scan's findings, reported by the
    #: engines that ran it — results are only reproducible if it is recorded.
    rulepack_version: str | None = Field(default=None, max_length=64)

    #: Units scanned, findings new/resolved/suppressed, and so on.
    counts: dict[str, Any] = Field(default_factory=dict, sa_type=json_type())

    started_at: datetime | None = Field(default=None, sa_type=utc_timestamp_type())
    finished_at: datetime | None = Field(default=None, sa_type=utc_timestamp_type())
    error: str | None = Field(default=None)


class ScanTask(TimestampedModel, table=True):
    """A unit of work leased by exactly one engine.

    The broker message for a task carries its id and nothing else: the **lease is
    authoritative** (ADR 0009). Dramatiq retries are disabled, so lease expiry —
    detected via the ``(status, lease_expires_at)`` index — is the single
    re-delivery mechanism.
    """

    __tablename__ = "scan_task"
    __table_args__ = (Index("ix_scan_task_status_lease_expires_at", "status", "lease_expires_at"),)

    scan_id: uuid.UUID = Field(foreign_key="scan.id", ondelete="CASCADE", index=True)
    kind: ScanTaskKind = Field(sa_type=enum_type(ScanTaskKind, name="scan_task_kind"))

    #: What to fetch. Produced by the discovery task, never by the API — the API
    #: runs no connector code.
    spec: dict[str, Any] = Field(default_factory=dict, sa_type=json_type())

    status: ScanTaskStatus = Field(
        default=ScanTaskStatus.QUEUED,
        sa_type=enum_type(ScanTaskStatus, name="scan_task_status"),
    )
    engine_id: uuid.UUID | None = Field(
        default=None,
        foreign_key="engine.id",
        ondelete="SET NULL",
    )
    lease_expires_at: datetime | None = Field(default=None, sa_type=utc_timestamp_type())
    heartbeat_at: datetime | None = Field(default=None, sa_type=utc_timestamp_type())
    attempts: int = Field(default=0)
    started_at: datetime | None = Field(default=None, sa_type=utc_timestamp_type())
    finished_at: datetime | None = Field(default=None, sa_type=utc_timestamp_type())
    error: str | None = Field(default=None)
