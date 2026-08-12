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


#: Maximum opaque object references retained in either a task report or its
#: scan-level manifest. Exact aggregate counts continue beyond this boundary.
MAX_COVERAGE_GAP_REFERENCES = 10_000


class CoverageReason(StrEnum):
    """Stable, content-free explanations for scan coverage gaps.

    These values are part of the public API and exported manifests.  Keep them
    deliberately broad: connector-specific exception names and resource details
    belong in engine logs, not in a durable report that must stay comparable
    across connector and parser releases.
    """

    PERMISSION_DENIED = "permission_denied"
    RATE_LIMITED = "rate_limited"
    SIZE_LIMIT = "size_limit"
    OUTPUT_LIMIT = "output_limit"
    UNSUPPORTED_TYPE = "unsupported_type"
    CONNECTOR_ERROR = "connector_error"
    MISSING_RESOURCE = "missing_resource"
    INVALID_METADATA = "invalid_metadata"
    INVALID_RESPONSE = "invalid_response"
    PARSE_ERROR = "parse_error"
    TIMEOUT = "timeout"
    EMPTY_CONTENT = "empty_content"
    BINARY_CONTENT = "binary_content"
    CANCELLED = "cancelled"
    UNREPORTED = "unreported"


class CoverageState(StrEnum):
    """Operator-facing assurance state of a terminal scan manifest."""

    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELLED = "cancelled"


class CoverageDisposition(StrEnum):
    """How a requested object or scope gap affected assurance."""

    SKIPPED = "skipped"
    FAILED = "failed"
    SCOPE_GAP = "scope_gap"


_COVERAGE_REASONS_BY_DISPOSITION: dict[CoverageDisposition, frozenset[CoverageReason]] = {
    CoverageDisposition.SKIPPED: frozenset(
        {
            CoverageReason.UNSUPPORTED_TYPE,
            CoverageReason.EMPTY_CONTENT,
            CoverageReason.BINARY_CONTENT,
        }
    ),
    CoverageDisposition.FAILED: frozenset(
        {
            CoverageReason.PERMISSION_DENIED,
            CoverageReason.RATE_LIMITED,
            CoverageReason.SIZE_LIMIT,
            CoverageReason.OUTPUT_LIMIT,
            CoverageReason.CONNECTOR_ERROR,
            CoverageReason.MISSING_RESOURCE,
            CoverageReason.INVALID_METADATA,
            CoverageReason.INVALID_RESPONSE,
            CoverageReason.PARSE_ERROR,
            CoverageReason.TIMEOUT,
        }
    ),
    CoverageDisposition.SCOPE_GAP: frozenset(
        {
            CoverageReason.PERMISSION_DENIED,
            CoverageReason.RATE_LIMITED,
            CoverageReason.CONNECTOR_ERROR,
            CoverageReason.MISSING_RESOURCE,
            CoverageReason.INVALID_METADATA,
            CoverageReason.INVALID_RESPONSE,
            CoverageReason.TIMEOUT,
            CoverageReason.CANCELLED,
            CoverageReason.UNREPORTED,
        }
    ),
}


def coverage_reason_allowed(
    disposition: CoverageDisposition,
    reason: CoverageReason,
) -> bool:
    """Whether a stable reason has the stated assurance meaning."""
    return reason in _COVERAGE_REASONS_BY_DISPOSITION[disposition]


class CoverageObjectKind(StrEnum):
    """Content-free object classes shared by current and planned connectors."""

    SCOPE = "scope"
    PAGE = "page"
    COMMENT = "comment"
    ATTACHMENT = "attachment"
    PROJECT = "project"
    RECORD = "record"
    PATH = "path"


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
    #: Remediation actions (#142): recorded / one-way verified / set-once
    #: retracted. Stored as VARCHAR, so adding these needed no migration.
    REMEDIATION = "remediation"
    REMEDIATION_VERIFIED = "remediation_verified"
    REMEDIATION_RETRACTED = "remediation_retracted"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


#: Severity as an order, for "at or above this severity" policy checks. Lives
#: beside the enum because anything ranking severities must agree with it.
SEVERITY_RANK: dict[Severity, int] = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}


class RemediationActionKind(StrEnum):
    """What a responder did about an exposed credential (#142).

    The four verbs guidance separates, plus an explicit escape hatch — `other`
    forces the note to carry the story rather than mislabelling the action.
    """

    REVOKE = "revoke"
    ROTATE = "rotate"
    SCOPE_REDUCE = "scope_reduce"
    REMOVE_SOURCE = "remove_source"
    OTHER = "other"


class RemediationVerification(StrEnum):
    """Whether anyone has confirmed the action took effect. One-way."""

    UNVERIFIED = "unverified"
    VERIFIED = "verified"


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


class NotificationDeliveryStatus(StrEnum):
    """Where one announcement to one channel has got to (#60).

    ``failed`` is terminal and means *give up*, not *lost*: the row stays, with
    the error that ended it, so an operator can see what was never delivered.
    """

    PENDING = "pending"
    DELIVERED = "delivered"
    FAILED = "failed"
