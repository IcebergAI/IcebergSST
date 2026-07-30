"""Payloads on the engine↔API channel (ADR 0009).

This is the wire format for the only conversation an engine has: register,
heartbeat, lease, report. Everything sensitive travels here rather than through the
broker, which is why TLS on this channel is mandatory (docs/security.md).
"""

import uuid
from typing import Any

from iceberg_core.enums import EngineStatus, ScanTaskKind, ScanTaskStatus, Severity
from pydantic import BaseModel, ConfigDict, Field

from iceberg_api.schemas import UtcDatetime


class RuleMetadata(BaseModel):
    """One rule, as an engine describes the pack it is running (#70).

    Metadata only — no regex. What a rule matches is code shipped in the image
    (ADR 0008); what the API needs is enough to name it in a filter and a UI.
    """

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=128)
    description: str = Field(min_length=1, max_length=255)
    severity: Severity


class RulepackReport(BaseModel):
    """The rule pack an engine has loaded, reported at registration and heartbeat."""

    model_config = ConfigDict(extra="forbid")

    version: str = Field(min_length=1, max_length=64)
    rules: list[RuleMetadata] = Field(default_factory=list)


class EngineRegister(BaseModel):
    """``POST /engines/register``."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=255)
    version: str | None = Field(default=None, max_length=64)
    #: Optional: an operator minting a token before the engine runs has nothing to
    #: report yet, and the first heartbeat fills it in.
    rulepack: RulepackReport | None = None


class EngineCredential(BaseModel):
    """The registration response. The only time the token is ever readable."""

    engine_id: uuid.UUID
    name: str
    #: Store it now; the API keeps only a hash and cannot show it again.
    token: str


class EngineRead(BaseModel):
    """An engine as the API describes it. No token, hashed or otherwise."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    version: str | None
    status: EngineStatus
    last_heartbeat_at: UtcDatetime | None
    created_at: UtcDatetime


class HeartbeatRequest(BaseModel):
    """``POST /engines/{id}/heartbeat``."""

    model_config = ConfigDict(extra="forbid")

    version: str | None = Field(default=None, max_length=64)
    #: Reported on every beat, so a rolling deploy is visible as it happens rather
    #: than only after someone re-registers the engine.
    rulepack: RulepackReport | None = None
    #: Tasks this engine believes it is working on, so the response can tell it
    #: which have been cancelled underneath it (#68).
    task_ids: list[uuid.UUID] = Field(default_factory=list)


class HeartbeatResponse(BaseModel):
    """Acknowledgement, plus the cancellations this engine needs to know about."""

    engine_id: uuid.UUID
    acknowledged_at: UtcDatetime
    #: Abandon these: their scan was cancelled while the engine was working
    #: (ADR 0009 — there is no way to reach into a worker, so it is told here).
    cancelled_task_ids: list[uuid.UUID] = Field(default_factory=list)


class LeaseResponse(BaseModel):
    """A granted lease: everything needed to do the work, and nothing more.

    The broker message that led here carried only a task id. This is where the spec,
    the credential, the pepper, and the suppressions arrive — over TLS, once, for
    one task (ADR 0009 §2).
    """

    task_id: uuid.UUID
    scan_id: uuid.UUID
    source_id: uuid.UUID
    source_type: str
    kind: ScanTaskKind
    attempt: int
    lease_expires_at: UtcDatetime

    #: What to fetch. Empty for a discovery task — finding out is its job.
    spec: dict[str, Any] = Field(default_factory=dict)
    #: How to reach the source, minus the credential.
    connection: dict[str, Any] = Field(default_factory=dict)

    #: The source credential in plaintext, scoped to this task. Deliberately a plain
    #: string rather than a SecretStr: pydantic would serialise that as asterisks
    #: and the engine needs the real value. It must never be logged.
    credential: str | None = None

    #: The fingerprint pepper, base64. Delivered per task, never in engine config
    #: (ADR 0007).
    fingerprint_pepper: str | None = None

    #: Suppressions the engine may pre-filter with. The API applies them again at
    #: ingest, so this is an optimisation, not the enforcement point (#44).
    suppressions: list[dict[str, str]] = Field(default_factory=list)

    #: Drop matches scoring below this. Delivered per task rather than configured
    #: in the engine so there is one value in one place; ingest applies it again,
    #: so an engine running a stale one cannot flood the queue (#70).
    confidence_threshold: float = Field(default=0.5, ge=0.0, le=1.0)


class FindingPayload(BaseModel):
    """One redacted finding, as an engine reports it (ADR 0004).

    There is no field for the secret. The engine redacts before transmitting, and
    what arrives is a masked snippet plus a peppered hash — so an API that wanted to
    store plaintext could not, because it was never sent one.
    """

    model_config = ConfigDict(extra="forbid")

    fingerprint: str = Field(min_length=16, max_length=64)
    rule_id: str = Field(min_length=1, max_length=128)
    rulepack_version: str = Field(min_length=1, max_length=64)
    resource_locator: dict[str, Any]
    redacted_snippet: str = Field(min_length=1)
    secret_hash: str = Field(min_length=16, max_length=64)
    entropy: float | None = None
    confidence: float | None = None
    severity: Severity


class ResultsSubmission(BaseModel):
    """``POST /scan-tasks/{id}/results`` — the only ingress for results."""

    model_config = ConfigDict(extra="forbid")

    #: ``<task id>:<attempt>``. A retry after an API error presents the same key and
    #: the replay is a no-op rather than a duplicate set of findings (ADR 0009 §2).
    idempotency_key: str = Field(min_length=1, max_length=128)

    #: How the task ended. Only these two are an engine's to report — cancelled is
    #: the API's decision, and queued/leased are not outcomes.
    status: ScanTaskStatus = ScanTaskStatus.COMPLETED
    error: str | None = Field(default=None, max_length=2000)

    #: Findings from a fetch task.
    findings: list[FindingPayload] = Field(default_factory=list)
    #: Specs from a discovery task; these become fetch tasks.
    task_specs: list[dict[str, Any]] = Field(default_factory=list)

    #: Which rule pack produced these findings, recorded on the scan so results are
    #: reproducible (ADR 0008).
    rulepack_version: str | None = Field(default=None, max_length=64)
    #: Engine-side tallies: units scanned, units skipped, matches dropped below the
    #: confidence threshold.
    counts: dict[str, int] = Field(default_factory=dict)


class ResultsAccepted(BaseModel):
    """What ingest did with a submission."""

    task_id: uuid.UUID
    #: True when this was a replay of an already-accepted submission.
    replay: bool = False
    findings_ingested: int = 0
    findings_suppressed: int = 0
    findings_reopened: int = 0
    #: Reported findings the API dropped for scoring below the threshold. Non-zero
    #: means the engine and the API disagree about it — worth a look, not an error.
    findings_below_threshold: int = 0
    fetch_tasks_created: int = 0
    #: Set when this submission finished the scan.
    scan_status: str | None = None


class ScanTaskRead(BaseModel):
    """A task as the human API exposes it (#68). No spec: it can name resources."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    scan_id: uuid.UUID
    kind: ScanTaskKind
    status: ScanTaskStatus
    engine_id: uuid.UUID | None
    attempts: int
    lease_expires_at: UtcDatetime | None
    heartbeat_at: UtcDatetime | None
    started_at: UtcDatetime | None
    finished_at: UtcDatetime | None
    error: str | None
    created_at: UtcDatetime
