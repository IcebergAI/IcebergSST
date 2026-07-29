"""Findings, their audit trail, and analyst suppressions."""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Index, UniqueConstraint
from sqlmodel import Field

from iceberg_core.enums import (
    FindingEventKind,
    FindingResolution,
    FindingState,
    Severity,
    SuppressionScope,
)
from iceberg_core.models.base import (
    IcebergModel,
    TimestampedModel,
    enum_type,
    json_type,
    utc_timestamp_type,
)


class Finding(TimestampedModel, table=True):
    """A secret found somewhere. Never the secret itself (ADR 0004).

    Identity is the ``fingerprint`` (ADR 0006), unique within a source: triage
    decisions are keyed on it, so they survive re-scans and a resolved secret that
    reappears re-opens. ``first_seen_scan_id``/``last_seen_scan_id`` are that
    history — the two together subsume what docs/data-model.md sketched as a
    single ``scan_id``.
    """

    __tablename__ = "finding"
    __table_args__ = (
        # Reconciliation's lookup, and the reason a fingerprint means one finding.
        UniqueConstraint("source_id", "fingerprint", name="uq_finding_source_id_fingerprint"),
        Index("ix_finding_source_id_state", "source_id", "state"),
    )

    source_id: uuid.UUID = Field(foreign_key="source.id", ondelete="CASCADE", index=True)
    fingerprint: str = Field(max_length=64, index=True)

    rule_id: str = Field(max_length=128, index=True)
    rulepack_version: str = Field(max_length=64)

    #: Coarse locator (page id, attachment name) **plus** display-only offsets.
    #: Only the coarse part feeds the fingerprint — see ADR 0006.
    resource_locator: dict[str, Any] = Field(default_factory=dict, sa_type=json_type())

    #: Masked context. Redacted inside the engine before transmission (ADR 0004).
    redacted_snippet: str

    #: Peppered HMAC of the secret. Not reversible, not brute-forceable offline.
    secret_hash: str = Field(max_length=64)

    entropy: float | None = Field(default=None)
    confidence: float | None = Field(default=None)
    severity: Severity = Field(sa_type=enum_type(Severity, name="severity"))

    state: FindingState = Field(
        default=FindingState.OPEN,
        sa_type=enum_type(FindingState, name="finding_state"),
    )
    #: How it was resolved: ``manual`` by an analyst, ``auto`` when a completed
    #: re-scan no longer saw it. Null unless resolved.
    resolution: FindingResolution | None = Field(
        default=None,
        sa_type=enum_type(FindingResolution, name="finding_resolution"),
    )
    assignee_id: uuid.UUID | None = Field(
        default=None,
        foreign_key="app_user.id",
        ondelete="SET NULL",
    )
    notes: str | None = Field(default=None)

    first_seen_scan_id: uuid.UUID = Field(foreign_key="scan.id", ondelete="CASCADE")
    last_seen_scan_id: uuid.UUID = Field(foreign_key="scan.id", ondelete="CASCADE")


class FindingEvent(IcebergModel, table=True):
    """Append-only audit trail for a finding.

    Deliberately not a :class:`TimestampedModel`: an audit row that can be updated
    is not an audit row.
    """

    __tablename__ = "finding_event"

    finding_id: uuid.UUID = Field(foreign_key="finding.id", ondelete="CASCADE", index=True)

    #: Null for system actions — auto-resolution, ingest-time suppression.
    actor_id: uuid.UUID | None = Field(
        default=None,
        foreign_key="app_user.id",
        ondelete="SET NULL",
    )
    kind: FindingEventKind = Field(sa_type=enum_type(FindingEventKind, name="finding_event_kind"))
    from_value: str | None = Field(default=None, max_length=255)
    to_value: str | None = Field(default=None, max_length=255)
    comment: str | None = Field(default=None)


class Suppression(TimestampedModel, table=True):
    """An analyst-managed allowlist entry (ADR 0008).

    Tuning lives in data, not code: suppressions are editable in the UI and applied
    server-side at result ingest, so silencing a known-benign match never needs a
    rule-pack release.
    """

    __tablename__ = "suppression"
    __table_args__ = (Index("ix_suppression_scope_source_id", "scope", "source_id"),)

    scope: SuppressionScope = Field(sa_type=enum_type(SuppressionScope, name="suppression_scope"))

    #: A path glob, a fingerprint, or a rule id, depending on ``scope``.
    pattern: str = Field(max_length=512)

    #: Null means global — every source.
    source_id: uuid.UUID | None = Field(
        default=None,
        foreign_key="source.id",
        ondelete="CASCADE",
    )
    reason: str
    created_by_id: uuid.UUID | None = Field(
        default=None,
        foreign_key="app_user.id",
        ondelete="SET NULL",
    )
    expires_at: datetime | None = Field(default=None, sa_type=utc_timestamp_type())
