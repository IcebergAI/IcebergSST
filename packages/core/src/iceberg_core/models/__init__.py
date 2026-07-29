"""SQLModel table definitions — the API's system of record.

**API role only**, like :mod:`iceberg_core.db`: these classes exist to be
mapped to Postgres. Engines describe their results with plain payload types and
the shared vocabulary in :mod:`iceberg_core.enums` (ADR 0002).

Entities land here as the milestones that own their behaviour arrive; the base
conventions every one of them follows live in :mod:`iceberg_core.models.base`.
"""

from iceberg_core.models.base import (
    NAMING_CONVENTION,
    IcebergModel,
    TimestampedModel,
    enum_type,
    json_type,
    metadata,
    utc_now,
    utc_timestamp_type,
)

__all__ = [
    "NAMING_CONVENTION",
    "IcebergModel",
    "TimestampedModel",
    "enum_type",
    "json_type",
    "metadata",
    "utc_now",
    "utc_timestamp_type",
]
