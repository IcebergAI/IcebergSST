"""SQLModel table definitions — the API's system of record.

**API role only**, like :mod:`iceberg_core.db`: these classes exist to be mapped
to Postgres. Engines describe their results with plain payload types and the
shared vocabulary in :mod:`iceberg_core.enums` (ADR 0002).

Importing this package registers every table on the shared metadata, which is
what Alembic's ``env.py`` targets — so a new entity must be re-exported here or
autogenerate will not see it. The conventions each table follows live in
:mod:`iceberg_core.models.base`; the entities themselves are documented in
``docs/data-model.md``.
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
from iceberg_core.models.findings import Finding, FindingEvent, Suppression
from iceberg_core.models.identity import User
from iceberg_core.models.notifications import NotificationChannel
from iceberg_core.models.scans import Engine, Scan, ScanTask
from iceberg_core.models.sources import Schedule, Source

__all__ = [
    "NAMING_CONVENTION",
    "Engine",
    "Finding",
    "FindingEvent",
    "IcebergModel",
    "NotificationChannel",
    "Scan",
    "ScanTask",
    "Schedule",
    "Source",
    "Suppression",
    "TimestampedModel",
    "User",
    "enum_type",
    "json_type",
    "metadata",
    "utc_now",
    "utc_timestamp_type",
]
