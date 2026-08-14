"""Payloads on the engine↔API channel (ADR 0009).

This is the wire format for the only conversation an engine has: register,
heartbeat, lease, report. Everything sensitive travels here rather than through the
broker, which is why TLS on this channel is mandatory (docs/security.md).
"""

from __future__ import annotations

import uuid
from collections import Counter
from typing import Annotated, Any, Literal, Self

from iceberg_core.enums import (
    MAX_COVERAGE_GAP_REFERENCES,
    CoverageDisposition,
    CoverageObjectKind,
    CoverageReason,
    EngineStatus,
    ScanMode,
    ScanTaskKind,
    ScanTaskStatus,
    Severity,
    ValidationReason,
    ValidationStatus,
    coverage_reason_allowed,
)
from pydantic import BaseModel, ConfigDict, Field, model_validator

from iceberg_api.schemas import UtcDatetime

#: Ceiling on progress batches for one task (#143). A runaway-loop backstop set far
#: above any real task: at the engine's flush thresholds this is hundreds of
#: thousands of findings, and a task producing more of them has a different problem.
MAX_BATCH_SEQUENCE = 1_000


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

    #: Where a previous attempt of this task got to (#143), or empty to start from
    #: the top. Empty whenever the configuration the position was taken under has
    #: since moved, because resuming into content the current configuration does
    #: not cover would report a scan of the wrong thing.
    checkpoint: dict[str, Any] = Field(default_factory=dict)

    #: How many batches this task has already had accepted. The engine's first
    #: batch is this plus one; the counter is per task, so a reclaimed attempt
    #: continues it rather than colliding with its predecessor's numbers.
    checkpoint_sequence: int = Field(default=0, ge=0)

    #: Per-scope watermarks for an incremental scan, ``{scope: position}``. Empty
    #: for a full scan, which is every scan unless a schedule asked otherwise and
    #: every cursor survived validation.
    cursors: dict[str, Any] = Field(default_factory=dict)

    #: What this scan undertook to read. An engine does not decide it; it is
    #: reported so the connector can narrow discovery and so logs say which it was.
    mode: ScanMode = ScanMode.FULL

    #: The source credential in plaintext, scoped to this task. Deliberately a plain
    #: string rather than a SecretStr: pydantic would serialise that as asterisks
    #: and the engine needs the real value. It must never be logged.
    credential: str | None = None

    #: The fingerprint pepper, base64. Delivered per task, never in engine config
    #: (ADR 0007).
    fingerprint_pepper: str | None = None

    #: The pepper being rotated out, base64, present only during a rotation
    #: window (#64). When it is here the engine reports a second identity for
    #: every finding, computed under this pepper, so ingest can recognise a
    #: finding it already has and carry its triage state onto the new identity.
    #: Null in normal operation, which is almost always.
    previous_fingerprint_pepper: str | None = None

    #: Suppressions the engine may pre-filter with. The API applies them again at
    #: ingest, so this is an optimisation, not the enforcement point (#44).
    suppressions: list[dict[str, str]] = Field(default_factory=list)

    #: Drop matches scoring below this. Delivered per task rather than configured
    #: in the engine so there is one value in one place; ingest applies it again,
    #: so an engine running a stale one cannot flood the queue (#70).
    confidence_threshold: float = Field(default=0.5, ge=0.0, le=1.0)

    #: Enabled policy snapshot at lease time. An empty list is the default and
    #: authorizes no outbound credential validation.
    validation_policies: list[LeaseValidationPolicy] = Field(default_factory=list)


class LeaseValidationPolicy(BaseModel):
    """The bounded authorization an engine receives for one task."""

    model_config = ConfigDict(extra="forbid")

    policy_id: uuid.UUID
    rule_id: str = Field(min_length=1, max_length=128)
    validator_id: str = Field(min_length=1, max_length=128)
    timeout_seconds: float = Field(ge=0.1, le=30.0)
    requests_per_minute: int = Field(ge=1, le=10_000)
    max_attempts_per_task: int = Field(ge=1, le=10)


class CredentialValidationResult(BaseModel):
    """Content-free result produced while a credential exists in engine memory."""

    model_config = ConfigDict(extra="forbid")

    provider: str = Field(min_length=1, max_length=64)
    validator_id: str = Field(min_length=1, max_length=128)
    contract_version: str = Field(min_length=1, max_length=64)
    status: ValidationStatus
    # Stable machine reason, not a provider body or exception string. Keeping
    # this vocabulary-shaped prevents accidental response/credential capture.
    reason: ValidationReason


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
    validation: CredentialValidationResult | None = None

    #: The same finding's identity under the outgoing pepper, sent only during a
    #: rotation window (#64). Ingest looks this up when the primary fingerprint
    #: is unknown; a match is the *same* finding under a new key, so it is
    #: re-keyed in place rather than created afresh — which is what carries the
    #: analyst's decision across a rotation.
    previous_fingerprint: str | None = Field(default=None, min_length=16, max_length=64)
    previous_secret_hash: str | None = Field(default=None, min_length=16, max_length=64)


class CoverageCounts(BaseModel):
    """Per-object outcomes for one task, reconciled before ingest."""

    model_config = ConfigDict(extra="forbid")

    requested: int = Field(ge=0)
    discovered: int = Field(ge=0)
    scanned: int = Field(ge=0)
    skipped: int = Field(ge=0)
    failed: int = Field(ge=0)

    @model_validator(mode="after")
    def _reconciles(self) -> Self:
        if self.requested != self.discovered:
            raise ValueError("object requested and discovered counts must match")
        if self.discovered != self.scanned + self.skipped + self.failed:
            raise ValueError("object outcomes must reconcile to discovered")
        return self


class CoverageScope(BaseModel):
    """Discovery or collection scopes whose object cardinality may be unknown."""

    model_config = ConfigDict(extra="forbid")

    requested: int | None = Field(default=None, ge=0)
    discovered: int = Field(ge=0)
    gaps: int = Field(ge=0)

    @model_validator(mode="after")
    def _reconciles_when_requested_is_known(self) -> Self:
        if self.requested is not None and self.requested != self.discovered + self.gaps:
            raise ValueError("scope requested count must equal discovered plus gaps")
        return self


class CoverageReasonCount(BaseModel):
    """One stable reason subtotal."""

    model_config = ConfigDict(extra="forbid")

    outcome: CoverageDisposition
    reason: CoverageReason
    count: int = Field(gt=0)

    @model_validator(mode="after")
    def _reason_matches_outcome(self) -> Self:
        if not coverage_reason_allowed(self.outcome, self.reason):
            raise ValueError(
                f"{self.reason.value} is not a valid {self.outcome.value} coverage reason"
            )
        return self


class CoverageGap(BaseModel):
    """A content-free, correlatable reference to one uninspected object or scope."""

    model_config = ConfigDict(extra="forbid")

    kind: CoverageObjectKind
    outcome: CoverageDisposition
    reason: CoverageReason
    reference: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def _scope_kind_matches_outcome(self) -> Self:
        is_scope_gap = self.outcome is CoverageDisposition.SCOPE_GAP
        if is_scope_gap != (self.kind is CoverageObjectKind.SCOPE):
            raise ValueError("only scope gaps may use the scope object kind")
        return self


class TaskCoverageReport(BaseModel):
    """Versioned engine assurance report stored immutably on a terminal task."""

    model_config = ConfigDict(extra="forbid")

    version: Literal["1"]
    phase: ScanTaskKind
    counts: CoverageCounts
    scope: CoverageScope
    reasons: list[CoverageReasonCount] = Field(default_factory=list)
    gaps: list[CoverageGap] = Field(
        default_factory=list,
        max_length=MAX_COVERAGE_GAP_REFERENCES,
    )
    gaps_omitted: int = Field(default=0, ge=0)

    @model_validator(mode="after")
    def _reason_and_reference_totals_reconcile(self) -> Self:
        keys = [(entry.outcome, entry.reason) for entry in self.reasons]
        if len(keys) != len(set(keys)):
            raise ValueError("coverage reason subtotals must be unique")

        expected = {
            CoverageDisposition.SKIPPED: self.counts.skipped,
            CoverageDisposition.FAILED: self.counts.failed,
            CoverageDisposition.SCOPE_GAP: self.scope.gaps,
        }
        actual = {
            outcome: sum(entry.count for entry in self.reasons if entry.outcome is outcome)
            for outcome in CoverageDisposition
        }
        if actual != expected:
            raise ValueError("coverage reason subtotals must reconcile to outcomes")

        total_gaps = self.counts.skipped + self.counts.failed + self.scope.gaps
        if len(self.gaps) + self.gaps_omitted != total_gaps:
            raise ValueError("coverage gap references must reconcile to non-scanned outcomes")
        for gap in self.gaps:
            if not any(
                entry.outcome is gap.outcome and entry.reason is gap.reason
                for entry in self.reasons
            ):
                raise ValueError("coverage gap has no matching reason subtotal")
        reason_totals = {(entry.outcome, entry.reason): entry.count for entry in self.reasons}
        gap_totals = Counter((gap.outcome, gap.reason) for gap in self.gaps)
        if any(count > reason_totals[key] for key, count in gap_totals.items()):
            raise ValueError("coverage gap references exceed their reason subtotal")
        if self.phase is ScanTaskKind.DISCOVERY and any(
            (
                self.counts.requested,
                self.counts.discovered,
                self.counts.scanned,
                self.counts.skipped,
                self.counts.failed,
            )
        ):
            raise ValueError("discovery tasks report scope coverage, not object outcomes")
        return self


class CursorProposal(BaseModel):
    """A connector's proposal for where the next scan of one scope starts (#143).

    The scope is named by the engine rather than derived by the API: scope
    parameter names are connector knowledge (``space_key``, ``project_key``), and
    the API runs no connector code. ``position`` is opaque here — it may hold a
    provider change token, so it is stored but never logged or exported.
    """

    model_config = ConfigDict(extra="forbid")

    scope: str = Field(min_length=1, max_length=512)
    version: str = Field(min_length=1, max_length=32)
    position: dict[str, Any] = Field(default_factory=dict)


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
    counts: dict[str, Annotated[int, Field(ge=0)]] = Field(default_factory=dict)
    #: Structured assurance. Optional only for rolling compatibility with an old
    #: engine; a missing report is surfaced as ``unreported`` in the manifest and
    #: can never produce a clean coverage state.
    coverage: TaskCoverageReport | None = None

    #: How many progress batches preceded this submission (#143). Zero — an engine
    #: that never flushed, or one predating batching — means ``counts`` and
    #: ``coverage`` describe the whole task, exactly as they always have. Above
    #: zero they are the remaining delta and the API merges them onto what the
    #: batches already recorded.
    checkpoint_sequence: int = Field(default=0, ge=0, le=MAX_BATCH_SEQUENCE)

    #: Where the next scan of this scope should start, proposed by the connector.
    #: Stored only if the whole scan reaches ``completed`` with complete coverage.
    cursor: CursorProposal | None = None


class ProgressSubmission(BaseModel):
    """``POST /scan-tasks/{id}/progress`` — one durable batch of a running task.

    The counterpart to :class:`ResultsSubmission` for work that is not finished.
    Findings and the resume point move together in one transaction, because a
    checkpoint stored ahead of its findings would tell the next attempt to skip
    them.
    """

    model_config = ConfigDict(extra="forbid")

    #: Strictly monotonic within a task, starting at one past whatever the lease
    #: reported. The API accepts ``sequence`` only when it is exactly one ahead of
    #: the stored counter, which makes duplicate, out-of-order, and stale-engine
    #: batches indistinguishable — all three are simply refused.
    sequence: int = Field(ge=1, le=MAX_BATCH_SEQUENCE)

    #: The connector position these findings are complete up to.
    checkpoint: dict[str, Any] = Field(default_factory=dict)

    #: Findings, tallies, and assurance for this batch only — never running totals.
    findings: list[FindingPayload] = Field(default_factory=list)
    counts: dict[str, Annotated[int, Field(ge=0)]] = Field(default_factory=dict)
    coverage: TaskCoverageReport | None = None

    rulepack_version: str | None = Field(default=None, max_length=64)


class ProgressAccepted(BaseModel):
    """What a batch did, and where the task now stands."""

    task_id: uuid.UUID
    #: The stored counter after this call. On a replay it is unchanged, which is
    #: how an engine learns its batch was already recorded.
    sequence: int
    replay: bool = False
    findings_ingested: int = 0
    findings_suppressed: int = 0
    findings_reopened: int = 0
    findings_below_threshold: int = 0


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
