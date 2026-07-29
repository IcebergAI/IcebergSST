"""Scan read shapes for the human API (#68)."""

import uuid
from typing import Any

from iceberg_core.enums import ScanStatus, ScanTrigger
from pydantic import BaseModel, ConfigDict

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
