"""Scan read shapes for the human API (#68)."""

import uuid
from typing import Any, Literal

from iceberg_core.enums import (
    MAX_COVERAGE_GAP_REFERENCES,
    CoverageDisposition,
    CoverageObjectKind,
    CoverageReason,
    CoverageState,
    ScanStatus,
    ScanTaskKind,
    ScanTrigger,
)
from pydantic import BaseModel, ConfigDict, Field

from iceberg_api.engines.schemas import CoverageCounts, CoverageReasonCount, CoverageScope
from iceberg_api.schemas import UtcDatetime


class ScanRead(BaseModel):
    """A scan as the human API exposes it."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    source_id: uuid.UUID
    trigger: ScanTrigger
    status: ScanStatus
    rulepack_version: str | None
    #: Units scanned, findings new/resolved/suppressed — accumulated from tasks and
    #: completed by reconciliation.
    counts: dict[str, Any]
    started_at: UtcDatetime | None
    finished_at: UtcDatetime | None
    error: str | None
    created_at: UtcDatetime


class CoverageTaskCounts(BaseModel):
    """Terminal task-state totals; no specs or error strings."""

    model_config = ConfigDict(extra="forbid")

    total: int = Field(ge=0)
    completed: int = Field(ge=0)
    failed: int = Field(ge=0)
    cancelled: int = Field(ge=0)
    reported: int = Field(ge=0)
    unreported: int = Field(ge=0)


class CoverageManifestGap(BaseModel):
    """One bounded opaque gap reference with enough context to drill down."""

    model_config = ConfigDict(extra="forbid")

    task_id: uuid.UUID
    phase: ScanTaskKind
    kind: CoverageObjectKind
    outcome: CoverageDisposition
    reason: CoverageReason
    reference: str = Field(pattern=r"^[0-9a-f]{64}$")


class CoverageManifest(BaseModel):
    """Immutable, export-safe assurance record for one terminal scan."""

    model_config = ConfigDict(extra="forbid")

    manifest_version: Literal["1"] = "1"
    scan_id: uuid.UUID
    source_id: uuid.UUID
    scan_status: ScanStatus
    coverage_state: CoverageState
    source_configuration_version: UtcDatetime | None
    rulepack_version: str | None
    finalized_at: UtcDatetime
    counts: CoverageCounts
    scope: CoverageScope
    reasons: list[CoverageReasonCount]
    task_counts: CoverageTaskCounts
    gaps: list[CoverageManifestGap] = Field(max_length=MAX_COVERAGE_GAP_REFERENCES)
    gaps_omitted: int = Field(ge=0)
