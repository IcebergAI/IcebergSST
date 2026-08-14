"""Findings, their audit trail, and analyst suppressions."""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Index, UniqueConstraint, text
from sqlmodel import Field

from iceberg_core.enums import (
    FindingEventKind,
    FindingResolution,
    FindingState,
    Severity,
    SuppressionScope,
    ValidationReason,
    ValidationStatus,
)
from iceberg_core.models.base import (
    IcebergModel,
    TimestampedModel,
    enum_type,
    json_type,
    utc_timestamp_type,
)

#: Predicate for the finding-event idempotency index: a *system* event caused by a
#: known scan. Analyst rows carry an actor and no scan, and are unconstrained.
_SYSTEM_EVENT_WHERE = text("actor_id IS NULL AND scan_id IS NOT NULL")


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
        # The keyset order every list endpoint pages on. On the one table that
        # grows with every scan, its absence made the default queue view sort the
        # whole table per page request.
        Index("ix_finding_created_at_id", "created_at", "id"),
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

    #: API-minted equality label: same value ⇒ same id, and nothing else
    #: (ADR 0011). Derived from ``secret_hash`` under the correlation key at
    #: ingest — never by an engine. Null when the key is unconfigured or the row
    #: predates it; the maintenance loop backfills, `reindex-correlation` rotates.
    correlation_id: str | None = Field(default=None, max_length=64, index=True)

    entropy: float | None = Field(default=None)
    confidence: float | None = Field(default=None)
    severity: Severity = Field(sa_type=enum_type(Severity, name="severity"))

    #: Structured liveness metadata only. The credential itself never reaches
    #: this model; validation happens ephemerally inside the engine.
    validation_provider: str | None = Field(default=None, max_length=64)
    validation_validator_id: str | None = Field(default=None, max_length=128)
    validation_contract_version: str | None = Field(default=None, max_length=64)
    validation_status: ValidationStatus | None = Field(
        default=None,
        sa_type=enum_type(ValidationStatus, name="validation_status"),
    )
    validation_reason: ValidationReason | None = Field(
        default=None,
        sa_type=enum_type(ValidationReason, name="validation_reason"),
    )
    validated_at: datetime | None = Field(default=None, sa_type=utc_timestamp_type())

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

    #: Set when a suppression covered this finding at ingest (ADR 0008). Suppressed
    #: findings are **recorded, not discarded** — "why is this not in my list?" has
    #: an answer, and an expiring suppression brings the finding back rather than
    #: losing its history. A finding is *active* when it is ``open`` and this is null.
    suppressed_at: datetime | None = Field(default=None, sa_type=utc_timestamp_type())
    suppressed_by_id: uuid.UUID | None = Field(
        default=None,
        foreign_key="suppression.id",
        ondelete="SET NULL",
    )

    #: RESTRICT, not CASCADE: these columns are the finding's history, and a
    #: finding's lifecycle belongs to its *source*, not to any one scan. Deleting
    #: a scan row (retention, cleanup) must never silently take open findings and
    #: their audit trail with it — the scan rows it references cannot be deleted
    #: while the finding exists.
    first_seen_scan_id: uuid.UUID = Field(foreign_key="scan.id", ondelete="RESTRICT")
    last_seen_scan_id: uuid.UUID = Field(foreign_key="scan.id", ondelete="RESTRICT")


class FindingEvent(IcebergModel, table=True):
    """Append-only audit trail for a finding.

    Deliberately not a :class:`TimestampedModel`: an audit row that can be updated
    is not an audit row.
    """

    __tablename__ = "finding_event"
    __table_args__ = (
        # One system event of a given kind per finding per scan (#143). Results
        # ingest is idempotent for *findings* through the source/fingerprint
        # unique constraint, but until this index existed nothing stopped a
        # re-ingested batch appending a second identical reopen or auto-resolve
        # row. Analyst events are exempt: two people may legitimately record the
        # same transition, and their rows carry no scan.
        Index(
            "uq_finding_event_system_per_scan",
            "finding_id",
            "kind",
            "scan_id",
            unique=True,
            postgresql_where=_SYSTEM_EVENT_WHERE,
            sqlite_where=_SYSTEM_EVENT_WHERE,
        ),
    )

    finding_id: uuid.UUID = Field(foreign_key="finding.id", ondelete="CASCADE", index=True)

    #: Null for system actions — auto-resolution, ingest-time suppression.
    actor_id: uuid.UUID | None = Field(
        default=None,
        foreign_key="app_user.id",
        ondelete="SET NULL",
    )

    #: The scan that caused a system event, and null for an analyst action. It is
    #: what makes a system event idempotent; see the partial index above. RESTRICT
    #: for the same reason the finding's own scan columns are.
    scan_id: uuid.UUID | None = Field(
        default=None,
        foreign_key="scan.id",
        ondelete="RESTRICT",
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
