"""Enumerations shared by every role.

Kept free of database imports on purpose: engines need this vocabulary to build
result payloads, and nothing here should drag the ORM (or a DB session) into an
engine process (ADR 0002).

These are ``StrEnum``s so the wire form, the stored form, and the Python form are
the same string — one fewer mapping layer to get wrong.
"""

from enum import StrEnum


class UserRole(StrEnum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class SourceType(StrEnum):
    CONFLUENCE = "confluence"
    JIRA = "jira"
    SMB = "smb"


class ScanTrigger(StrEnum):
    MANUAL = "manual"
    SCHEDULED = "scheduled"


class ScanStatus(StrEnum):
    QUEUED = "queued"
    DISCOVERING = "discovering"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELLED = "cancelled"


#: Statuses in which a scan still holds its source. The "one active scan per
#: source" partial unique index is defined over exactly this set, and
#: reconciliation runs only for ``COMPLETED`` (ADR 0006/0009).
ACTIVE_SCAN_STATUSES: frozenset[ScanStatus] = frozenset(
    {ScanStatus.QUEUED, ScanStatus.DISCOVERING, ScanStatus.RUNNING}
)


class ScanTaskKind(StrEnum):
    DISCOVERY = "discovery"
    FETCH = "fetch"


class ScanTaskStatus(StrEnum):
    QUEUED = "queued"
    LEASED = "leased"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class FindingState(StrEnum):
    OPEN = "open"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"
    RESOLVED = "resolved"


class FindingResolution(StrEnum):
    MANUAL = "manual"
    AUTO = "auto"


class FindingEventKind(StrEnum):
    STATE_CHANGE = "state_change"
    ASSIGN = "assign"
    COMMENT = "comment"
    SUPPRESSED = "suppressed"
    REOPENED = "reopened"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SuppressionScope(StrEnum):
    PATH_GLOB = "path_glob"
    FINGERPRINT = "fingerprint"
    RULE = "rule"


class EngineStatus(StrEnum):
    ACTIVE = "active"
    DRAINING = "draining"
    OFFLINE = "offline"


class NotificationChannelType(StrEnum):
    EMAIL = "email"
    WEBHOOK = "webhook"
