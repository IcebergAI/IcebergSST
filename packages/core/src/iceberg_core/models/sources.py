"""Scan targets, their schedules, and their incremental watermarks."""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Index
from sqlmodel import Field

from iceberg_core.enums import CursorInvalidationReason, ScanMode, SourceType
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

    #: Operator labels — "pci", "eu", "team-payments". Free-form on purpose: they
    #: exist to be matched by routing rules (#146), and a controlled vocabulary
    #: would mean a migration every time a team reorganised. Never used by
    #: detection, so a typo here costs a routing miss, not a missed secret.
    tags: list[str] = Field(
        default_factory=list,
        sa_type=json_type(),
        # Declared here as well as in migration 0014, so autogenerate does not
        # propose dropping it: the column is NOT NULL and the migration had to
        # backfill existing rows, which means the default is part of the schema
        # rather than a one-off. Same pattern as `full_scan_interval_days`.
        sa_column_kwargs={"server_default": "'[]'"},
    )

    enabled: bool = Field(default=True)
    created_by_id: uuid.UUID | None = Field(
        default=None,
        foreign_key="app_user.id",
        ondelete="SET NULL",
    )

    #: How stale an incremental watermark may get before a scan is promoted to a
    #: full one regardless of what was asked for (#143). This is what makes the
    #: periodic full reconciliation a guarantee rather than a convention: an
    #: incremental scan never auto-resolves, so without a ceiling here a source
    #: scheduled incrementally forever would never resolve a remediated finding.
    full_scan_interval_days: int = Field(
        default=7, ge=1, le=365, sa_column_kwargs={"server_default": "7"}
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

    #: What this cadence asks for. Only a request: the API promotes it to a full
    #: scan whenever the source's cursors cannot be trusted, so a schedule can
    #: make scans cheaper but can never make reconciliation stop happening.
    mode: ScanMode = Field(
        default=ScanMode.FULL,
        sa_type=enum_type(ScanMode, name="schedule_scan_mode"),
        sa_column_kwargs={"server_default": ScanMode.FULL.value},
    )

    next_run_at: datetime | None = Field(default=None, sa_type=utc_timestamp_type(), index=True)
    last_run_at: datetime | None = Field(default=None, sa_type=utc_timestamp_type())


class SourceCursor(TimestampedModel, table=True):
    """How far a scan of one scope of one source got, for the next scan (#143).

    Per **scope** — a space, a project — rather than per source, because scopes
    complete independently. A space whose tasks failed simply does not advance and
    is re-read in full next time, which is the fail-closed default with no extra
    machinery.

    Only written when a scan reaches ``completed`` with complete coverage. A
    partial scan can never move a watermark forward, so an incremental scan can
    never inherit a position for content nobody actually read.
    """

    __tablename__ = "source_cursor"
    __table_args__ = (
        Index("uq_source_cursor_scope", "source_id", "scope", unique=True),
        Index("ix_source_cursor_source_id_invalidated_at", "source_id", "invalidated_at"),
    )

    source_id: uuid.UUID = Field(foreign_key="source.id", ondelete="CASCADE", index=True)

    #: The connector's own scope identifier — a space key, a project key. Opaque
    #: to the API, which runs no connector code and cannot interpret it.
    scope: str = Field(max_length=512)

    #: ``{"version": …, "position": {…}}``, authored by the connector. May hold a
    #: provider change token, so it is never logged and never leaves the API.
    position: dict[str, Any] = Field(default_factory=dict, sa_type=json_type())

    #: What this position is valid under. A change to either invalidates it: new
    #: rules must see content the old rules passed over, and a reconfigured source
    #: covers different content than the one the watermark was taken from.
    rulepack_version: str | None = Field(default=None, max_length=64)
    source_configuration_version: datetime | None = Field(
        default=None,
        sa_type=utc_timestamp_type(),
    )

    #: RESTRICT rather than CASCADE, matching `Finding.first_seen_scan_id`: a
    #: cursor claiming a scan as its provenance must not outlive it silently.
    minted_by_scan_id: uuid.UUID = Field(foreign_key="scan.id", ondelete="RESTRICT")
    minted_at: datetime = Field(sa_type=utc_timestamp_type())

    #: Set rather than deleted, so "why did this become a full scan?" stays
    #: answerable after the fact. A row with this set is inert for scan planning.
    invalidated_at: datetime | None = Field(default=None, sa_type=utc_timestamp_type())
    invalidation_reason: CursorInvalidationReason | None = Field(
        default=None,
        sa_type=enum_type(CursorInvalidationReason, name="source_cursor_invalidation_reason"),
    )
