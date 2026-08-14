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

from iceberg_core.models.audit import (
    AUDIT_CHANNEL_CREATED,
    AUDIT_CHANNEL_DELETED,
    AUDIT_CHANNEL_SECRET_SET,
    AUDIT_CHANNEL_UPDATED,
    AUDIT_CORRELATION_CLUSTER_EXPORTED,
    AUDIT_CORRELATION_REINDEXED,
    AUDIT_ENGINE_REGISTERED,
    AUDIT_ENGINE_TOKEN_ROTATED,
    AUDIT_REMEDIATION_RECORDED,
    AUDIT_REMEDIATION_RETRACTED,
    AUDIT_REMEDIATION_VERIFIED,
    AUDIT_RETENTION_PURGED,
    AUDIT_SCHEDULE_CREATED,
    AUDIT_SCHEDULE_DELETED,
    AUDIT_SCHEDULE_UPDATED,
    AUDIT_SOURCE_CREATED,
    AUDIT_SOURCE_CREDENTIAL_ROTATED,
    AUDIT_SOURCE_CREDENTIAL_SET,
    AUDIT_SOURCE_DELETED,
    AUDIT_SOURCE_UPDATED,
    AUDIT_SUPPRESSION_CREATED,
    AUDIT_SUPPRESSION_DELETED,
    AUDIT_TARGET_CHANNEL,
    AUDIT_TARGET_CORRELATION,
    AUDIT_TARGET_ENGINE,
    AUDIT_TARGET_REMEDIATION,
    AUDIT_TARGET_RETENTION,
    AUDIT_TARGET_SCHEDULE,
    AUDIT_TARGET_SOURCE,
    AUDIT_TARGET_SUPPRESSION,
    AUDIT_TARGET_USER,
    AUDIT_TARGET_VALIDATION_POLICY,
    AUDIT_USER_DISABLED,
    AUDIT_USER_ENABLED,
    AUDIT_USER_ROLE_CHANGED,
    AUDIT_VALIDATION_POLICY_CREATED,
    AUDIT_VALIDATION_POLICY_DELETED,
    AUDIT_VALIDATION_POLICY_UPDATED,
    AuditEvent,
)
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
from iceberg_core.models.notifications import NotificationChannel, NotificationDelivery
from iceberg_core.models.remediation import RemediationAction
from iceberg_core.models.scans import Engine, Scan, ScanTask
from iceberg_core.models.sources import Schedule, Source, SourceCursor
from iceberg_core.models.validation import ValidationPolicy

__all__ = [
    "AUDIT_CHANNEL_CREATED",
    "AUDIT_CHANNEL_DELETED",
    "AUDIT_CHANNEL_SECRET_SET",
    "AUDIT_CHANNEL_UPDATED",
    "AUDIT_CORRELATION_CLUSTER_EXPORTED",
    "AUDIT_CORRELATION_REINDEXED",
    "AUDIT_ENGINE_REGISTERED",
    "AUDIT_ENGINE_TOKEN_ROTATED",
    "AUDIT_REMEDIATION_RECORDED",
    "AUDIT_REMEDIATION_RETRACTED",
    "AUDIT_REMEDIATION_VERIFIED",
    "AUDIT_RETENTION_PURGED",
    "AUDIT_SCHEDULE_CREATED",
    "AUDIT_SCHEDULE_DELETED",
    "AUDIT_SCHEDULE_UPDATED",
    "AUDIT_SOURCE_CREATED",
    "AUDIT_SOURCE_CREDENTIAL_ROTATED",
    "AUDIT_SOURCE_CREDENTIAL_SET",
    "AUDIT_SOURCE_DELETED",
    "AUDIT_SOURCE_UPDATED",
    "AUDIT_SUPPRESSION_CREATED",
    "AUDIT_SUPPRESSION_DELETED",
    "AUDIT_TARGET_CHANNEL",
    "AUDIT_TARGET_CORRELATION",
    "AUDIT_TARGET_ENGINE",
    "AUDIT_TARGET_REMEDIATION",
    "AUDIT_TARGET_RETENTION",
    "AUDIT_TARGET_SCHEDULE",
    "AUDIT_TARGET_SOURCE",
    "AUDIT_TARGET_SUPPRESSION",
    "AUDIT_TARGET_USER",
    "AUDIT_TARGET_VALIDATION_POLICY",
    "AUDIT_USER_DISABLED",
    "AUDIT_USER_ENABLED",
    "AUDIT_USER_ROLE_CHANGED",
    "AUDIT_VALIDATION_POLICY_CREATED",
    "AUDIT_VALIDATION_POLICY_DELETED",
    "AUDIT_VALIDATION_POLICY_UPDATED",
    "NAMING_CONVENTION",
    "AuditEvent",
    "Engine",
    "Finding",
    "FindingEvent",
    "IcebergModel",
    "NotificationChannel",
    "NotificationDelivery",
    "RemediationAction",
    "Scan",
    "ScanTask",
    "Schedule",
    "Source",
    "SourceCursor",
    "Suppression",
    "TimestampedModel",
    "User",
    "ValidationPolicy",
    "enum_type",
    "json_type",
    "metadata",
    "utc_now",
    "utc_timestamp_type",
]
