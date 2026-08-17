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
    #: A mounted SMB or NFS share (#145). One type for both protocols, because
    #: the engine walks a read-only mount rather than speaking either protocol —
    #: which is what makes them the same connector. The reserved ``smb`` value it
    #: replaces was never storable: `validate_connection` refused it, so no row
    #: can carry it and the rename needs no migration. The column is a plain
    #: VARCHAR (``native_enum=False``, no CHECK), so adding a type never was one.
    FILESHARE = "fileshare"


class ScanTrigger(StrEnum):
    MANUAL = "manual"
    SCHEDULED = "scheduled"


class ScanMode(StrEnum):
    """How much of a source one scan undertook to read (#143).

    The distinction is load-bearing rather than informational: a ``FULL`` scan's
    absence of a finding is evidence the secret is gone, and reconciliation
    auto-resolves on it. An ``INCREMENTAL`` scan deliberately never looked at
    unchanged content, so the same absence means nothing and must never resolve
    anything (ADR 0013).
    """

    FULL = "full"
    INCREMENTAL = "incremental"


class CursorInvalidationReason(StrEnum):
    """Why an incremental scan was promoted to a full one, or a cursor dropped.

    Operator-facing and part of the coverage manifest, so these are stable values
    rather than free text: "why am I paying for a full scan again?" has to be
    answerable from an exported manifest months later.
    """

    #: This scope has never completed a scan, so nothing has been read.
    NO_CURSOR = "no_cursor"
    #: Scope filters or the base URL moved; the old watermark covers other content.
    SOURCE_CONFIGURATION_CHANGED = "source_configuration_changed"
    #: New rules must see content the old rules already passed over.
    RULEPACK_CHANGED = "rulepack_changed"
    #: Fingerprints move during a pepper rotation, so nothing would match.
    PEPPER_ROTATING = "pepper_rotating"
    #: The periodic full reconciliation this source is configured for came due.
    INTERVAL_ELAPSED = "interval_elapsed"
    #: The connector does not declare `INCREMENTAL`; full is the only honest scan.
    CONNECTOR_UNSUPPORTED = "connector_unsupported"
    #: An operator asked for the cursor to be dropped.
    OPERATOR_REQUESTED = "operator_requested"
    #: The source itself refused the stored position — an expired change token.
    SOURCE_REJECTED_CURSOR = "source_rejected_cursor"


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
    VALIDATION = "validation"
    #: Remediation actions (#142): recorded / one-way verified / set-once
    #: retracted. Stored as VARCHAR, so adding these needed no migration.
    REMEDIATION = "remediation"
    REMEDIATION_VERIFIED = "remediation_verified"
    REMEDIATION_RETRACTED = "remediation_retracted"
    #: The accountable *group* (#146), which routing may set and an analyst may
    #: override; ``ASSIGN`` above remains the individual currently holding it.
    #: There is no matching event for the response target: ``Finding.due_at`` is a
    #: column derived from the severity and the moment the finding opened, so an
    #: event per finding would double this table to record something already
    #: visible and fully explained by the two.
    OWNER = "owner"


class ValidationStatus(StrEnum):
    """A side-effect-free credential validator's structured conclusion.

    Absence of a result is represented by nullable finding fields, not another
    status: validation is opt-in and most findings will never be submitted to a
    provider.
    """

    LIVE = "live"
    REVOKED = "revoked"
    UNKNOWN = "unknown"
    BLOCKED = "blocked"
    ERROR = "error"


class ValidationReason(StrEnum):
    """Stable content-free reasons emitted by reviewed validators."""

    CREDENTIAL_ACCEPTED = "credential_accepted"
    CREDENTIAL_REJECTED = "credential_rejected"
    PROVIDER_RATE_LIMITED = "provider_rate_limited"
    PROVIDER_UNAVAILABLE = "provider_unavailable"
    INCONCLUSIVE_RESPONSE = "inconclusive_response"
    TIMEOUT = "timeout"
    PROTOCOL_ERROR = "protocol_error"
    POLICY_BUDGET_EXHAUSTED = "policy_budget_exhausted"


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


class HandoffTargetType(StrEnum):
    """The kind of external workflow a finding can be handed to (#141).

    One member on purpose. A signed webhook is the *reference adapter* the epic
    asks for, and it is what every ITSM and SOAR platform can receive — through
    its own automation, which is where the vendor-specific field names belong.
    Building a Jira or ServiceNow client here would mean this project owning
    their auth, their pagination, and their field schemas, and being wrong about
    all three the next time they change.
    """

    WEBHOOK = "webhook"


class HandoffStatus(StrEnum):
    """Where one finding's handoff to one target has got to.

    ``failed`` is terminal and means *give up*, not *lost*: the row stays with the
    error that ended it, and an operator can replay it. Same contract as
    :class:`NotificationDeliveryStatus`, and for the same reason — "what did we
    never manage to hand over?" has to be a query rather than a log search.
    """

    PENDING = "pending"
    DELIVERED = "delivered"
    FAILED = "failed"


class HandoffExternalState(StrEnum):
    """What the receiving system last said about the work item (#141).

    A **closed vocabulary**, which is the point: every ITSM and SOAR platform has
    its own status names, and accepting them verbatim would make "is this being
    worked?" unanswerable without knowing which product each row came from. The
    mapping from a vendor's statuses onto these five belongs on the receiving
    side, next to the automation that already knows them.

    Deliberately *not* :class:`FindingState`. These describe somebody else's work
    item, and a finding's state is a decision made here by a named analyst
    (`iceberg_api.findings.triage`). Keeping the vocabularies apart is what makes
    a disagreement between them expressible rather than a value that silently
    overwrote the other.
    """

    #: Received, not started.
    OPEN = "open"
    #: Somebody is working it.
    IN_PROGRESS = "in_progress"
    #: The work item was completed.
    RESOLVED = "resolved"
    #: The receiver refused it — wrong queue, not actionable, a duplicate of
    #: something they already had.
    REJECTED = "rejected"
    #: Withdrawn on their side without being worked.
    CANCELLED = "cancelled"


#: External states that mean nobody over there is going to do anything more.
#: ``rejected`` and ``cancelled`` are in here with ``resolved`` because for the
#: purpose of "is this still moving?" they are the same answer, and the reason
#: they differ is carried by the state itself.
HANDOFF_EXTERNAL_TERMINAL: frozenset[HandoffExternalState] = frozenset(
    {
        HandoffExternalState.RESOLVED,
        HandoffExternalState.REJECTED,
        HandoffExternalState.CANCELLED,
    }
)


class NotificationEventKind(StrEnum):
    """What an announcement is about (#60, #146).

    Two things a channel hears, with different meanings and different dedup keys:
    a finding *opened* — once per scan that opened it — and a finding that went
    *overdue* — once per deadline it missed. Stored as a checked VARCHAR like
    every other enum here, so a third kind is a value, not a migration.
    """

    FINDING_OPENED = "finding_opened"
    FINDING_OVERDUE = "finding_overdue"
