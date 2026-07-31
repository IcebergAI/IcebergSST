"""Request and response shapes for findings, their audit trail, and suppressions.

Two rules shape these:

* **A response never carries anything derived from the secret itself.** The
  ``redacted_snippet`` is masked inside the engine (ADR 0004) and is safe to show;
  ``secret_hash`` is not exposed at all. It is not reversible, but handing every
  viewer a stable comparison oracle for "is this the same secret as that one"
  buys a client nothing and costs the guarantee that the API never re-emits a
  secret in any form.
* **Filters are explicit, never implicit.** An analyst's default view is
  ``?state=open&suppressed=false``; the API does not silently hide rows, because a
  list endpoint that quietly drops records is one nobody can reconcile counts
  against.
"""

import uuid
from datetime import UTC, datetime
from typing import Any

from iceberg_core.enums import (
    FindingEventKind,
    FindingResolution,
    FindingState,
    Severity,
    SuppressionScope,
)
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from iceberg_api.schemas import UtcDatetime


class FindingRead(BaseModel):
    """A finding as the human API exposes it."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    source_id: uuid.UUID
    fingerprint: str
    rule_id: str
    rulepack_version: str

    #: Where it was found: page id, URL, attachment name, plus display offsets.
    resource_locator: dict[str, Any]
    #: Masked context — never plaintext (ADR 0004).
    redacted_snippet: str

    entropy: float | None
    confidence: float | None
    severity: Severity

    state: FindingState
    resolution: FindingResolution | None
    assignee_id: uuid.UUID | None
    notes: str | None

    #: Non-null means a suppression covered it; it is recorded but out of the
    #: active view until the suppression lapses or is deleted (ADR 0008).
    suppressed_at: UtcDatetime | None
    suppressed_by_id: uuid.UUID | None

    first_seen_scan_id: uuid.UUID
    last_seen_scan_id: uuid.UUID
    created_at: UtcDatetime
    updated_at: UtcDatetime


class FindingEventRead(BaseModel):
    """One entry in a finding's audit trail."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    #: Null for system actions — auto-resolution, ingest-time suppression.
    actor_id: uuid.UUID | None
    kind: FindingEventKind
    from_value: str | None
    to_value: str | None
    comment: str | None
    created_at: UtcDatetime


class FindingDetail(FindingRead):
    """``GET /findings/{id}``: the finding plus its history, oldest first.

    The history ships with the detail rather than behind a second request: "why is
    this finding in this state" is the question the detail view exists to answer,
    and an analyst should not have to know to ask twice.
    """

    events: list[FindingEventRead]


class FindingUpdate(BaseModel):
    """``PATCH /findings/{id}``: what an analyst may change.

    ``assignee_id`` and ``notes`` are nullable *and* optional, which are different
    things — sending ``null`` unassigns, omitting the field leaves the assignee
    alone. The route distinguishes them through ``model_fields_set``.
    """

    model_config = ConfigDict(extra="forbid")

    state: FindingState | None = None
    assignee_id: uuid.UUID | None = None
    notes: str | None = None
    #: Rationale, recorded on the events this change writes. "Rotated in Vault,
    #: closing" is worth more to the next analyst than the transition alone.
    comment: str | None = Field(default=None, max_length=2000)


class SuppressionCreate(BaseModel):
    """``POST /suppressions``: silence a known-benign match (ADR 0008)."""

    model_config = ConfigDict(extra="forbid")

    scope: SuppressionScope
    #: A path glob, a fingerprint, or a rule id, depending on ``scope``.
    pattern: str = Field(min_length=1, max_length=512)
    #: Null means global — every source.
    source_id: uuid.UUID | None = None
    #: Required, and required to be non-empty: a suppression without a stated
    #: reason is indistinguishable from a mistake six months later.
    reason: str = Field(min_length=1)
    expires_at: datetime | None = None

    @field_validator("pattern", "reason")
    @classmethod
    def _trimmed(cls, value: str) -> str:
        trimmed = value.strip()
        if not trimmed:
            raise ValueError("must not be blank")
        return trimmed

    @model_validator(mode="after")
    def _expiry_in_the_future(self) -> SuppressionCreate:
        if self.expires_at is None:
            return self
        # A naive timestamp is read as UTC, the same assumption every other
        # timestamp in the API makes.
        at = self.expires_at if self.expires_at.tzinfo else self.expires_at.replace(tzinfo=UTC)
        if at <= datetime.now(UTC):
            raise ValueError("expires_at must be in the future")
        self.expires_at = at
        return self


class SuppressionRead(BaseModel):
    """A suppression as the API exposes it."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    scope: SuppressionScope
    pattern: str
    source_id: uuid.UUID | None
    reason: str
    created_by_id: uuid.UUID | None
    expires_at: UtcDatetime | None
    created_at: UtcDatetime
