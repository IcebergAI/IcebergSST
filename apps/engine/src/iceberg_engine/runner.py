"""One scan task, start to finish (#50 — ADR 0002, 0004, 0009).

The loop the whole system exists to run:

    lease → connector → detect → fingerprint → redact → pre-filter → report

Every piece of that already exists and is tested on its own. This module is the
wiring, and the wiring is where the interesting decisions are — mostly about what
happens when something goes wrong, because a scan of fifty thousand pages will
find a way.

**A task always ends by reporting.** Completed or failed, the API hears about it,
because a task that dies silently is one the API can only resolve by waiting for
the lease to expire — a delay measured in minutes, on every failure. The one
exception is a refused lease: the task was already claimed, finished, or
cancelled, so there is nothing to report and the correct move is to drop the
message (ADR 0009 §2).

**Plaintext has one optional outbound path.** Detection redacts before reporting.
When an administrator has enabled an exact reviewed policy, the candidate may be
sent once to that provider from this function; it never enters the API payload,
broker, logs, metrics, audit events, or database (ADR 0004 and ADR 0010).
"""

import base64
import uuid
from collections import Counter
from collections.abc import Iterator
from contextlib import nullcontext
from dataclasses import dataclass, field
from time import monotonic
from typing import Any, cast

import structlog
from dramatiq.middleware import Interrupt
from iceberg_connectors import (
    Checkpoint,
    ConnectorCapability,
    ConnectorError,
    ConnectorFailureCode,
    ContentUnit,
    FetchOutcome,
    TaskCoverage,
    TaskSpec,
    registry,
)
from iceberg_connectors.protocol import Connector, IncrementalConnector
from iceberg_core.enums import CoverageObjectKind, CoverageReason, ScanTaskKind
from iceberg_core.fingerprint import fingerprint, secret_hash
from iceberg_core.metrics import (
    ENGINE_CONNECTOR_FAILURES,
    ENGINE_FINDINGS_REPORTED,
    ENGINE_TASKS_RUN,
)
from iceberg_core.suppression import SuppressionRule
from iceberg_detect import DetectionResult, RulePack, detect

from iceberg_engine.api_client import (
    AuthenticationFailed,
    EngineApiError,
    EngineClient,
    Lease,
    LeaseNotHeld,
    LeaseRefused,
)
from iceberg_engine.heartbeat import TaskRegistry
from iceberg_engine.suppression import prefilter, rules_from_lease
from iceberg_engine.validation import RateLimiter, ValidationExecutor

logger = structlog.get_logger()

DISCOVERY = "discovery"
FETCH = "fetch"


class TaskCancelled(Exception):
    """The API cancelled this task while the engine was working on it.

    Not a failure: the API already moved the task to `cancelled` and is not
    waiting for anything. Reporting would be answered with a 409, so the engine
    stops and says nothing (ADR 0009 §4).
    """


@dataclass(frozen=True, slots=True)
class Candidate:
    """A detected secret, fingerprinted and redacted, ready to report.

    Shaped for :func:`~iceberg_engine.suppression.prefilter`, which is why the
    three fields it matches on are attributes rather than nested in the payload.
    """

    fingerprint: str
    rule_id: str
    resource_locator: dict[str, Any]
    payload: dict[str, Any]
    secret: str = field(repr=False)


@dataclass(slots=True)
class TaskReport:
    """What the task will tell the API, accumulated as it goes."""

    status: str = "completed"
    error: str | None = None
    findings: list[dict[str, Any]] = field(default_factory=list)
    task_specs: list[dict[str, Any]] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)
    coverage: TaskCoverage | None = None
    #: Set when the coverage above is a *remainder* rather than the whole task —
    #: the rest went out in progress batches (#143). Zero means one submission
    #: carried everything, which is the ordinary case.
    checkpoint_sequence: int = 0
    #: Overrides `coverage` when batching has already sent part of it, because a
    #: delta cannot be expressed as a `TaskCoverage`.
    coverage_payload: dict[str, Any] | None = None
    #: Where the next scan of this scope should start, if the connector said.
    cursor: dict[str, Any] | None = None

    def as_submission(self, idempotency_key: str, rulepack_version: str | None) -> dict[str, Any]:
        submission: dict[str, Any] = {
            "idempotency_key": idempotency_key,
            "status": self.status,
            "findings": self.findings,
            "task_specs": self.task_specs,
            "counts": self.counts,
            "checkpoint_sequence": self.checkpoint_sequence,
        }
        if self.error:
            submission["error"] = self.error
        if rulepack_version:
            submission["rulepack_version"] = rulepack_version
        if self.coverage_payload is not None:
            submission["coverage"] = self.coverage_payload
        elif self.coverage is not None:
            submission["coverage"] = self.coverage.as_payload()
        if self.cursor is not None:
            submission["cursor"] = self.cursor
        return submission


#: Flush thresholds (#143). Deliberately coarse: a batch costs a round trip and a
#: transaction, and the point is to bound how much a reclaimed task re-reads, not
#: to stream. Whichever trips first wins, so a slow source still checkpoints.
CHECKPOINT_BATCH_FINDINGS = 500
CHECKPOINT_BATCH_SECONDS = 30.0


def _coverage_delta(current: dict[str, Any], sent: dict[str, Any]) -> dict[str, Any]:
    """What ``current`` adds to a coverage payload already reported.

    Valid because a batch is only ever cut at a boundary between units: counts
    accumulate monotonically across boundaries, and ``gaps`` is append-only, so the
    new references are exactly the tail of the list. (Within one unit a truncation
    can move a count from ``scanned`` to ``failed``, but both sides of that land
    inside the same boundary, so no delta ever goes negative.)
    """
    current_counts, sent_counts = current["counts"], sent["counts"]
    current_scope, sent_scope = current["scope"], sent["scope"]

    reasons: Counter[tuple[str, str]] = Counter()
    for entry in current["reasons"]:
        reasons[(entry["outcome"], entry["reason"])] += entry["count"]
    for entry in sent["reasons"]:
        reasons[(entry["outcome"], entry["reason"])] -= entry["count"]

    requested = current_scope["requested"]
    if requested is not None and sent_scope["requested"] is not None:
        requested -= sent_scope["requested"]

    return {
        "version": current["version"],
        "phase": current["phase"],
        "counts": {key: current_counts[key] - sent_counts[key] for key in current_counts},
        "scope": {
            "requested": requested,
            "discovered": current_scope["discovered"] - sent_scope["discovered"],
            "gaps": current_scope["gaps"] - sent_scope["gaps"],
        },
        "reasons": [
            {"outcome": outcome, "reason": reason, "count": count}
            for (outcome, reason), count in sorted(reasons.items())
            if count > 0
        ],
        "gaps": current["gaps"][len(sent["gaps"]) :],
        "gaps_omitted": current["gaps_omitted"] - sent["gaps_omitted"],
    }


@dataclass(frozen=True, slots=True)
class _Batch:
    """One composed batch, held so a retry is a true retransmission (#143)."""

    payload: dict[str, Any]
    checkpoint: Checkpoint
    #: What the ledger advances to once the API confirms it holds this batch.
    covered: int
    coverage: dict[str, Any]
    counts: dict[str, int]


@dataclass(slots=True)
class _Batcher:
    """Flushes findings and their resume point to the API mid-fetch (#143).

    Holds the one thing the runner cannot recompute: how much of the task the API
    has already accepted. A batch is cut only where the connector's published
    checkpoint and the accumulated findings describe the same prefix of the work —
    see :meth:`boundary`, which is what makes a resumed attempt neither skip nor
    double-count.
    """

    client: EngineClient
    lease: Lease
    rulepack_version: str | None
    log: Any
    sequence: int
    #: Coverage the API has accepted, as a payload. Diffed to build each delta.
    sent_coverage: dict[str, Any]
    #: Candidates already submitted, as an index into the runner's growing list.
    sent_candidates: int = 0
    sent_counts: dict[str, int] = field(default_factory=dict)
    #: Work completed as of the end of the last unit: how many candidates it had
    #: produced, and the coverage and tallies that described exactly those units.
    pending: tuple[int, dict[str, Any], dict[str, int]] | None = None
    flushed_checkpoint: Checkpoint | None = None
    deadline: float = 0.0
    #: A batch that was sent and never acknowledged, kept verbatim.
    #:
    #: A sequence number is bound to the payload it was first sent with. If a
    #: response is lost, the API may already hold that batch, and the only safe
    #: retry is the *same* bytes at the *same* number: a bigger payload wearing an
    #: already-accepted sequence would be answered as a replay, and treating that
    #: as acknowledgement would advance the sent ledger past findings the API never
    #: received — which the terminal submission then omits. Silent data loss.
    in_flight: _Batch | None = None

    def boundary(
        self,
        candidates: int,
        coverage: dict[str, Any],
        counts: dict[str, int],
    ) -> None:
        """Record what has been fully processed, at the end of a unit.

        No checkpoint is recorded with it, because there is not one yet. ``fetch``
        is a generator: the ``checkpoint_at`` call covering this unit does not run
        until the consumer asks for the next one. So the position that matches this
        snapshot only becomes visible at the *top* of the following iteration,
        which is where :meth:`due` pairs the two.

        Getting this backwards is the subtle failure the design has to avoid.
        Pairing the checkpoint visible *now* with the work visible *now* would ship
        a batch covering one unit more than its position admits, and every resumed
        attempt would re-report that unit and inflate the merged coverage.
        """
        self.pending = (candidates, coverage, dict(counts))

    def due(self, checkpoint: Checkpoint | None, candidates: int, now: float) -> bool:
        """Whether there is a boundary worth spending a round trip on."""
        if self.in_flight is not None:
            # An unacknowledged batch outranks any new one: until its fate is
            # known, no later sequence number is safe to use.
            return now >= self.deadline
        if self.pending is None or checkpoint is None or checkpoint == self.flushed_checkpoint:
            return False
        unsent = self.pending[0] - self.sent_candidates
        if unsent <= 0 and self.pending[0] == self.sent_candidates:
            # Nothing new to make durable; a bare position is not worth a round
            # trip, and the next boundary will carry it anyway.
            return now >= self.deadline and self.pending[1] != self.sent_coverage
        return unsent >= CHECKPOINT_BATCH_FINDINGS or now >= self.deadline

    def send(
        self,
        checkpoint: Checkpoint,
        findings: list[dict[str, Any]],
        suppressed: int,
    ) -> None:
        """Compose the pending boundary into a batch and try to deliver it."""
        if self.pending is None:  # pragma: no cover — guarded by `due`
            return
        covered, coverage, counts = self.pending
        delta_counts = {key: value - self.sent_counts.get(key, 0) for key, value in counts.items()}
        # Already a per-slice number rather than a running total, so it is not
        # part of the diff above.
        delta_counts["prefiltered"] = suppressed
        payload: dict[str, Any] = {
            "sequence": self.sequence + 1,
            "checkpoint": checkpoint.as_payload(),
            "findings": findings,
            "counts": delta_counts,
            "coverage": _coverage_delta(coverage, self.sent_coverage),
        }
        if self.rulepack_version:
            payload["rulepack_version"] = self.rulepack_version
        self.in_flight = _Batch(
            payload=payload,
            checkpoint=checkpoint,
            covered=covered,
            coverage=coverage,
            counts=counts,
        )
        self.deliver()

    def deliver(self) -> None:
        """Deliver (or redeliver) the in-flight batch, verbatim.

        The ledger advances only when the API's own counter reaches the sequence
        this batch carries. A replay at that sequence is still an acknowledgement —
        it means the API already holds *this* payload, because the payload and the
        number were bound together when it was first composed. A reported counter
        *below* it means the batch was refused, so nothing moves and the work rides
        on the terminal submission instead.

        Losing a batch costs a re-read after a reclaim. Advancing the ledger past
        what the API stored would cost the findings.
        """
        batch = self.in_flight
        if batch is None:  # pragma: no cover — guarded by callers
            return
        try:
            accepted = self.client.submit_progress(self.lease.task_id, batch.payload)
        except EngineApiError as exc:
            # Includes a lost lease: the task is about to be reclaimed anyway, and
            # the reclaimed attempt resumes from the last batch the API *did* take.
            self.log.warning("scan_task_batch_failed", error=type(exc).__name__)
            return

        sequence = int(batch.payload["sequence"])
        reported = int(accepted.get("sequence", sequence))
        if reported < sequence:
            self.log.warning("scan_task_batch_refused", offered=sequence, stored=reported)
            self.in_flight = None
            return

        self.sequence = reported
        self.flushed_checkpoint = batch.checkpoint
        self.sent_coverage = batch.coverage
        self.sent_counts = batch.counts
        self.sent_candidates = batch.covered
        self.pending = None
        self.in_flight = None
        ENGINE_FINDINGS_REPORTED.inc(len(batch.payload["findings"]))


def _discovered(connector: Connector, lease: Lease) -> Iterator[TaskSpec]:
    """Run discovery, narrowed to what changed when the scan asked for that (#143).

    The keyword is passed only when the connector declares ``INCREMENTAL``. Gating
    on the declared capability rather than on ``isinstance``: a runtime-checkable
    Protocol checks that ``discover`` exists, not that it accepts ``cursors``, so
    an SDK 1.0 connector would pass the check and fail on the call.

    Cursors are withheld unless the *API* put the scan in incremental mode. A
    connector handed positions during a full scan could narrow without the control
    plane intending it, and that scan would then auto-resolve against content it
    never looked at.
    """
    capabilities = getattr(connector, "metadata", None)
    incremental = (
        lease.incremental
        and capabilities is not None
        and ConnectorCapability.INCREMENTAL in capabilities.capabilities
    )
    if not incremental:
        return connector.discover(lease.connection, lease.credential)
    return cast(IncrementalConnector, connector).discover(
        lease.connection, lease.credential, cursors=lease.cursors
    )


def _validator(
    lease: Lease,
    pack: RulePack,
    limiter: RateLimiter | None,
) -> ValidationExecutor:
    """One executor for the whole task, batches included.

    Built once rather than per batch because its budget and its per-secret cache
    are task-scoped: a fresh one per batch would re-spend the provider allowance
    and re-validate a secret the task has already seen (ADR 0010).
    """
    eligible_bindings = {
        rule.id: rule.validator_id for rule in pack.rules if rule.validator_id is not None
    }
    return ValidationExecutor.from_payloads(
        [
            policy
            for policy in lease.validation_policies
            if eligible_bindings.get(str(policy.get("rule_id"))) == str(policy.get("validator_id"))
        ],
        limiter=limiter,
    )


def _prepare(
    candidates: list[Candidate],
    rules: list[SuppressionRule],
    validator: ValidationExecutor,
    *,
    validate: bool,
) -> tuple[list[dict[str, Any]], int]:
    """Pre-filter and validate one slice of candidates, ready to report.

    Pre-filtering locally saves bandwidth. The API applies the same suppressions
    again at ingest, authoritatively, so this can only ever be the more permissive
    of the two (#44).

    ``validate`` is false after cancellation: that is an explicit revocation of
    further sensitive work, so coverage accounting still finishes but no provider
    call is initiated once the heartbeat has observed it.
    """
    filtered = prefilter(candidates, rules)
    if validate:
        for candidate in filtered.kept:
            validation = validator.validate(
                rule_id=candidate.rule_id,
                secret_hash=str(candidate.payload["secret_hash"]),
                secret=candidate.secret,
            )
            if validation is not None:
                candidate.payload["validation"] = validation.as_payload()
    return [candidate.payload for candidate in filtered.kept], filtered.suppressed_count


def _batcher(
    client: EngineClient | None,
    lease: Lease,
    connector: Connector,
    pack: RulePack,
    *,
    log: Any,
) -> _Batcher | None:
    """A batcher, but only for a connector that can actually resume (#143).

    Gated on the declared capability rather than attempted universally. Flushing a
    connector that cannot resume would be worse than useless: the API would hold a
    checkpoint the next attempt ignores, so it would re-read from the top and
    re-report everything the batch already delivered.
    """
    if client is None:
        return None
    capabilities = getattr(connector, "metadata", None)
    if capabilities is None or ConnectorCapability.CHECKPOINTS not in capabilities.capabilities:
        return None
    return _Batcher(
        client=client,
        lease=lease,
        rulepack_version=pack.version,
        log=log,
        sequence=lease.checkpoint_sequence,
        sent_coverage=FetchOutcome(reference_key=None).as_coverage(),
        deadline=monotonic() + CHECKPOINT_BATCH_SECONDS,
    )


def _flush(
    batcher: _Batcher,
    checkpoint: Checkpoint,
    candidates: list[Candidate],
    rules: list[SuppressionRule],
    validator: ValidationExecutor,
) -> None:
    """Prepare and send the pending boundary, then arm the next interval."""
    if batcher.in_flight is not None:
        # Redelivered verbatim. Composing a fresh, larger payload under the same
        # sequence would be answered as a replay of the *old* one, and taking that
        # as acknowledgement would strand everything the two differ by.
        batcher.deliver()
    else:
        covered = batcher.pending[0] if batcher.pending else batcher.sent_candidates
        findings, suppressed = _prepare(
            candidates[batcher.sent_candidates : covered], rules, validator, validate=True
        )
        batcher.send(checkpoint, findings, suppressed)
    # Armed whether or not the send worked: a source that is failing should not be
    # retried once per unit.
    batcher.deadline = monotonic() + CHECKPOINT_BATCH_SECONDS


def _incomplete_content_error(failed: int, truncated: int) -> str | None:
    """A content-free reason suitable for the API and durable task state."""
    if failed and not truncated:
        noun = "unit" if failed == 1 else "units"
        return f"{failed} requested content {noun} could not be read"
    if truncated and not failed:
        noun = "unit" if truncated == 1 else "units"
        verb = "was" if truncated == 1 else "were"
        return f"{truncated} requested content {noun} {verb} truncated"
    if failed and truncated:
        return f"{failed} requested content units could not be read and {truncated} were truncated"
    return None


def run_task(
    task_id: uuid.UUID,
    *,
    client: EngineClient,
    pack: RulePack,
    tasks: TaskRegistry | None = None,
    validation_executor: ValidationExecutor | None = None,
    validation_limiter: RateLimiter | None = None,
) -> TaskReport | None:
    """Lease a task, do it, and report.

    Returns None when there is nothing to report: the lease was refused, or the
    task was cancelled underneath us. Otherwise never raises for anything the API
    should hear about — a connector failure becomes a ``failed`` submission naming
    the reason, so the scan settles promptly instead of waiting out a lease. A
    dramatiq interrupt is the one thing that leaves this frame, and only after it
    has been reported: the thread it was raised in is being killed either way.

    ``tasks`` is the registry the heartbeat thread reports from and writes
    cancellations into. Without one the task still runs; it just cannot renew its
    lease or notice a cancellation, which is right for a one-shot call and wrong
    for a worker.
    """
    try:
        lease = client.lease(task_id)
    except LeaseRefused:
        # Already claimed, finished, or cancelled. Nothing to report, nothing to do.
        logger.info("scan_task_lease_refused", task_id=str(task_id))
        return None

    log = logger.bind(task_id=str(task_id), scan_id=str(lease.scan_id), kind=lease.kind)
    report = TaskReport()
    held = tasks.holding(task_id) if tasks else nullcontext()

    # Bound inside the `try`, but read by the handlers below to learn how this
    # connector names its scopes. An unknown source type never gets that far, so the
    # handlers must tolerate it still being None.
    connector: Connector | None = None

    try:
        with held:
            connector = registry.get(lease.source_type)
            if lease.kind == DISCOVERY:
                _discover(connector, lease, report)
            elif lease.kind == FETCH:
                _fetch(
                    connector,
                    lease,
                    report,
                    pack=pack,
                    client=client,
                    tasks=tasks,
                    task_id=task_id,
                    validation_executor=validation_executor,
                    validation_limiter=validation_limiter,
                )
            else:
                # A kind this engine does not implement (a newer API, say). Fail
                # loudly rather than silently mis-running it as a fetch.
                raise ConnectorError(f"unsupported task kind {lease.kind!r}")
    except TaskCancelled:
        # The API is not waiting for this, and submitting would be a 409.
        log.info("scan_task_abandoned_after_cancellation")
        ENGINE_TASKS_RUN.labels(kind=lease.kind, outcome="cancelled").inc()
        return None
    except ConnectorError as exc:
        # The source said no — bad credential, unreachable, unsupported type. The
        # scan should report why rather than an empty result that reads as "clean".
        # Even connector exceptions can embed response text, paths, filenames, or
        # credential-bearing URLs. The stable reason is enough for operators and
        # is the only detail that crosses the engine boundary or enters its log.
        report.status = "failed"
        reason = _coverage_reason(exc)
        report.error = f"{type(exc).__name__}: {reason.value}"
        _record_task_gap(report, lease, reason, connector)
        log.warning("scan_task_connector_failed", error=report.error)
        ENGINE_CONNECTOR_FAILURES.labels(source_type=lease.source_type).inc()
    except Interrupt as exc:
        # Dramatiq's time limit and its shutdown both raise a `BaseException`, so
        # neither handler here sees one and the task would end without reporting —
        # leaving the API to wait out the lease and redeliver a task that will be
        # interrupted at exactly the same point (#106). Report what the fetch got
        # through, then let the interrupt go on killing the thread it was raised in.
        report.status = "failed"
        report.error = type(exc).__name__
        _record_task_gap(report, lease, CoverageReason.TIMEOUT, connector)
        log.warning("scan_task_interrupted", error=report.error)
        _submit(client, lease, report, pack, log)
        ENGINE_TASKS_RUN.labels(kind=lease.kind, outcome="interrupted").inc()
        raise
    except Exception as exc:
        # A bug, or something nobody anticipated. The message may have been produced
        # by a third-party library quoting its input, which could be page content or
        # a secret — so only the exception *type* is reported or logged (ADR 0004).
        report.status = "failed"
        report.error = type(exc).__name__
        _record_task_gap(report, lease, CoverageReason.CONNECTOR_ERROR, connector)
        log.error("scan_task_failed", error_type=type(exc).__name__)

    if not _submit(client, lease, report, pack, log):
        ENGINE_TASKS_RUN.labels(kind=lease.kind, outcome="unreported").inc()
        return None
    ENGINE_TASKS_RUN.labels(kind=lease.kind, outcome=report.status).inc()
    ENGINE_FINDINGS_REPORTED.inc(len(report.findings))
    log.info(
        "scan_task_reported",
        status=report.status,
        findings=len(report.findings),
        task_specs=len(report.task_specs),
    )
    return report


def _submit(
    client: EngineClient,
    lease: Lease,
    report: TaskReport,
    pack: RulePack,
    log: Any,
) -> bool:
    """Send the report. Returns False when there was nothing the API would accept.

    A results submission can lose a race the runner cannot see: the task may have
    been cancelled or its lease reclaimed while the scan ran. The API answers 409
    ("no longer leased") or 403 ("not leased by this engine") — routine outcomes,
    not crashes (ADR 0009 §2). And if the API is simply unreachable through every
    retry, the task will be reclaimed and redone, so that too is logged rather than
    left to escape the actor as an unhandled exception.
    """
    try:
        client.submit_results(
            lease.task_id, report.as_submission(lease.idempotency_key, pack.version)
        )
        return True
    except LeaseRefused, LeaseNotHeld:
        # The lease is gone, not the token: it worked at lease time and the task
        # has been reclaimed or cancelled since. Nothing of ours to report.
        log.info("scan_task_lease_lost_before_report", status=report.status)
        return False
    except AuthenticationFailed as exc:
        # The token, and a task runs for long enough that it can be rotated
        # underneath one: re-registering an engine invalidates the old token
        # immediately, and every in-flight task then discards its results. On an
        # engine running without an id there is no heartbeat to fail either, so
        # this line is the only signal an operator gets (#131).
        log.warning("scan_task_token_rejected", status=report.status, error=str(exc))
        return False
    except EngineApiError as exc:
        # Unreachable through all retries; reclaim will redeliver the task.
        log.warning("scan_task_report_failed", error=str(exc))
        return False


def _discover(connector: Connector, lease: Lease, report: TaskReport) -> None:
    """Phase one: split the source into fetch specs and hand them back.

    The API persists these as fetch tasks in the same transaction that completes
    this one, so a crash cannot record the discovery as done yet lose what it
    found (ADR 0009).
    """
    scope_key, scope_param = _scope_keys(connector)
    configured_scopes = {
        str(value).strip().casefold()
        for value in lease.connection.get(scope_key) or ()
        if str(value).strip()
    }
    coverage = TaskCoverage(
        phase=ScanTaskKind.DISCOVERY,
        reference_key=_coverage_key(lease),
        # Current saves reject case-insensitive duplicates. Normalizing here keeps
        # pre-existing rows from producing an impossible requested/discovered
        # equation during a rolling upgrade.
        scope_requested=len(configured_scopes) or None,
    )
    report.coverage = coverage
    seen_scopes: set[str] = set()
    try:
        for spec in _discovered(connector, lease):
            # Append as discovery progresses so a late failure (for example one
            # configured space missing after other matches) does not discard the
            # matched spaces.  The failed discovery keeps the overall scan partial,
            # so fetching these specs can surface findings but cannot reconcile.
            report.task_specs.append(spec.as_payload())

            # One *scope*, however many specs cover it. A connector that splits a
            # scope into several fetch specs — Jira windows a project by `created`
            # — would otherwise report more scopes discovered than were requested,
            # and the API nulls the whole manifest's `scope.requested` when the
            # equation does not balance (scans/coverage.py). The operator silently
            # loses "you asked for three projects and we enumerated three".
            scope = str(spec.params.get(scope_param) or "")
            if scope and scope in seen_scopes:
                continue
            seen_scopes.add(scope)
            coverage.scope_found(spec.params)
    finally:
        report.counts["specs_discovered"] = len(report.task_specs)


def _fetch(
    connector: Connector,
    lease: Lease,
    report: TaskReport,
    *,
    pack: RulePack,
    client: EngineClient | None = None,
    tasks: TaskRegistry | None = None,
    task_id: uuid.UUID | None = None,
    validation_executor: ValidationExecutor | None = None,
    validation_limiter: RateLimiter | None = None,
) -> None:
    """Phase two: scan the content one spec describes.

    Text extraction is not here. A connector yields `ContentUnit`s that already
    hold text, so whether an attachment needed a PDF parser — and the sandbox that
    parser ran in — is the connector's business (#46). The runner sees text.
    """
    pepper = _pepper(lease)
    previous_pepper = _previous_pepper(lease)
    outcome = FetchOutcome(
        reference_key=pepper,
        # Handed back only when the API judged it still valid under this scan's
        # configuration; otherwise this is None and the spec restarts (#143).
        resume_from=Checkpoint.from_payload(lease.checkpoint),
    )
    spec = TaskSpec.from_payload(lease.spec)

    candidates: list[Candidate] = []
    tallies = {"units_truncated": 0, "dropped_below_threshold": 0}
    suppression_rules = rules_from_lease(lease.suppressions)
    validator = validation_executor or _validator(lease, pack, validation_limiter)
    batcher = _batcher(client, lease, connector, pack, log=logger)

    cancelled = False
    try:
        for unit in connector.fetch(lease.connection, spec, lease.credential, outcome):
            # Between units, not mid-unit: a content unit is small and finishing one
            # is cheaper than the bookkeeping to abandon it half-scanned.
            if tasks is not None and task_id is not None and tasks.is_cancelled(task_id):
                raise TaskCancelled(str(task_id))

            # Before this unit is touched. The generator has just published the
            # checkpoint covering the *previous* unit, which is exactly the
            # boundary recorded at the end of the previous iteration — so here,
            # and only here, position and work describe the same prefix. Findings
            # sent are durable, and a reclaimed attempt resumes past them (#143).
            published = outcome.checkpoint
            if (
                batcher is not None
                and published is not None
                and batcher.due(published, len(candidates), monotonic())
            ):
                _flush(batcher, published, candidates, suppression_rules, validator)

            result = detect(unit.text, pack, threshold=lease.confidence_threshold)
            tallies["dropped_below_threshold"] += result.dropped_below_threshold
            tallies["units_truncated"] += int(result.truncated)
            if result.truncated and not unit.display.get("truncated", False):
                outcome.scanned_but_incomplete(
                    CoverageReason.OUTPUT_LIMIT,
                    _coverage_kind(unit, connector),
                    unit.locator.canonical_parts(),
                )
            candidates.extend(
                _candidates(unit, result, pepper=pepper, previous_pepper=previous_pepper, pack=pack)
            )
            if batcher is not None:
                batcher.boundary(
                    len(candidates),
                    outcome.as_coverage(),
                    {**outcome.as_counts(), **tallies},
                )
    except TaskCancelled:
        cancelled = True
        raise
    finally:
        # In a `finally` because a source that gives out halfway — a pagination cap,
        # retries exhausted against a blipping Confluence — must not discard the
        # units before it. `complete_task(FAILED)` is terminal, so anything left
        # here surfaces only if an operator re-runs the whole scan (#115).
        #
        # Only what the batches did not already carry. Everything before
        # `sent_candidates` is durable in the API and must not be sent twice: the
        # findings would dedupe, but the tallies and coverage would not (#143).
        remaining = candidates[batcher.sent_candidates :] if batcher else candidates
        findings, suppressed = _prepare(
            remaining, suppression_rules, validator, validate=not cancelled
        )

        report.findings = findings
        counts = {**outcome.as_counts(), **tallies}
        if batcher is not None:
            report.checkpoint_sequence = batcher.sequence
            report.counts = {
                key: value - batcher.sent_counts.get(key, 0) for key, value in counts.items()
            }
            report.counts["prefiltered"] = suppressed
            report.coverage_payload = _coverage_delta(outcome.as_coverage(), batcher.sent_coverage)
        else:
            report.counts = {**counts, "prefiltered": suppressed}
            report.coverage = outcome.coverage
        if outcome.cursor is not None:
            report.cursor = outcome.cursor.as_payload()

        # Task-wide totals, never the remainder: whether the *task* read everything
        # it was asked to is not a property of its last batch.
        if error := _incomplete_content_error(outcome.failed, tallies["units_truncated"]):
            # Findings from readable units are still valuable and the API ingests
            # them even for a failed task.  The status is nevertheless failed:
            # calling a partial read completed would let source-wide reconciliation
            # auto-resolve findings in the content the connector could not read.
            # Keep the error content-free; connector resource details remain in
            # the engine log and may contain attacker-controlled names.
            report.status = "failed"
            report.error = error


def _coverage_reason(exc: ConnectorError) -> CoverageReason:
    if exc.code is ConnectorFailureCode.CREDENTIAL_REJECTED:
        return CoverageReason.PERMISSION_DENIED
    if exc.code is ConnectorFailureCode.RATE_LIMITED:
        return CoverageReason.RATE_LIMITED
    return CoverageReason.CONNECTOR_ERROR


def _record_task_gap(
    report: TaskReport,
    lease: Lease,
    reason: CoverageReason,
    connector: Connector | None = None,
) -> None:
    """Preserve a task-wide blind spot without inventing an object count."""
    try:
        phase = ScanTaskKind(lease.kind)
    except ValueError:  # a future API task kind this engine cannot represent
        return
    coverage = report.coverage or TaskCoverage(
        phase=phase,
        reference_key=_coverage_key(lease),
    )
    report.coverage = coverage

    scope_key, scope_param = _scope_keys(connector)
    if phase is ScanTaskKind.DISCOVERY and coverage.scope_requested is not None:
        wanted = {str(value).casefold(): value for value in lease.connection.get(scope_key) or ()}
        found = {
            str(spec.get("params", {}).get(scope_param) or "").casefold()
            for spec in report.task_specs
        }
        missing = [value for key, value in wanted.items() if key not in found]
        if missing:
            for value in missing:
                coverage.scope_gap(reason, value)
            return
        # The configured scopes were enumerated, but something failed after that.
        # Its remaining cardinality is unknown, so do not break the known-count
        # invariant by pretending another configured scope existed.
        coverage.scope_requested = None

    reference: object = (
        {"source_id": str(lease.source_id), "spec": lease.spec}
        if phase is ScanTaskKind.FETCH
        else {"source_id": str(lease.source_id), "phase": phase.value}
    )
    coverage.scope_gap(reason, reference)


def _coverage_key(lease: Lease) -> bytes | None:
    if not lease.fingerprint_pepper:
        return None
    try:
        return base64.b64decode(lease.fingerprint_pepper, validate=True)
    except ValueError, TypeError:
        return None


def _scope_keys(connector: Connector | None) -> tuple[str, str]:
    """How this connector names its scopes, in the blob and in a spec's params.

    Read with ``getattr`` rather than added to the ``Connector`` protocol: it is a
    ``@runtime_checkable`` Protocol, so a new required attribute would break
    ``isinstance`` for every third-party connector and force an SDK major bump
    (``CONNECTOR_SDK_VERSION`` is "1.0", and ``docs/connector-sdk.md`` promises that
    a minor release adds only optional things). The defaults are Confluence's, which
    is what every connector predating this meant.
    """
    return (
        getattr(connector, "scope_key", "spaces"),
        getattr(connector, "scope_param", "space_key"),
    )


def _coverage_kind(unit: ContentUnit, connector: Connector | None = None) -> CoverageObjectKind:
    if unit.origin.value == "comment":
        return CoverageObjectKind.COMMENT
    if unit.origin.value == "attachment":
        return CoverageObjectKind.ATTACHMENT
    # A body's object kind is the connector's word, because the kind is domain-
    # separated into the gap's HMAC. A Jira issue counted as `record` by the
    # connector but marked incomplete as `page` here would still reconcile
    # numerically while growing a phantom `page` gap on a source that has none.
    return getattr(connector, "body_kind", CoverageObjectKind.PAGE)


def _candidates(
    unit: ContentUnit,
    result: DetectionResult,
    *,
    pepper: bytes,
    previous_pepper: bytes | None,
    pack: RulePack,
) -> Iterator[Candidate]:
    """Turn detected secrets into reportable findings.

    The only place the plaintext is touched: hashed once for identity — twice
    during a pepper rotation — and then left behind. What continues is a masked
    snippet and hex digests.

    The second identity is the whole mechanism behind pepper rotation (#64).
    Identity is an HMAC keyed by the pepper and the plaintext is never stored, so
    the API cannot recompute a finding's identity under a new key; only an engine
    holding the secret can, and only while it holds it. Computing both here is
    what lets ingest recognise a finding it already has.
    """
    for found in result.secrets:
        hashed = secret_hash(found.secret, pepper=pepper)
        identity = fingerprint(
            locator=unit.locator, rule_id=found.rule_id, secret_hash=hashed, pepper=pepper
        )
        locator = unit.resource_locator() | {"offset": found.span.start}
        payload: dict[str, object] = {
            "fingerprint": identity,
            "rule_id": found.rule_id,
            "rulepack_version": pack.version,
            "resource_locator": locator,
            "redacted_snippet": found.redacted_snippet,
            "secret_hash": hashed,
            "entropy": found.entropy,
            "confidence": found.confidence,
            "severity": found.severity,
        }
        if previous_pepper is not None:
            previous_hashed = secret_hash(found.secret, pepper=previous_pepper)
            payload["previous_secret_hash"] = previous_hashed
            payload["previous_fingerprint"] = fingerprint(
                locator=unit.locator,
                rule_id=found.rule_id,
                secret_hash=previous_hashed,
                pepper=previous_pepper,
            )
        yield Candidate(
            fingerprint=identity,
            rule_id=found.rule_id,
            resource_locator=locator,
            payload=payload,
            secret=found.secret,
        )


def _pepper(lease: Lease) -> bytes:
    """The fingerprint pepper, from the lease and nowhere else (ADR 0007).

    Missing is fatal for the task rather than something to work around:
    fingerprints computed without it match nothing already stored, so every
    finding would ingest as new and reconciliation would auto-resolve the real
    ones — losing triage state that no scan can rebuild (ADR 0006).
    """
    if not lease.fingerprint_pepper:
        raise ConnectorError("lease carried no fingerprint pepper; refusing to scan")
    try:
        return base64.b64decode(lease.fingerprint_pepper, validate=True)
    except (ValueError, TypeError) as exc:
        raise ConnectorError("lease carried an unreadable fingerprint pepper") from exc


def _previous_pepper(lease: Lease) -> bytes | None:
    """The outgoing pepper during a rotation window, or None (#64).

    Unlike the pepper itself, an unreadable one here is not fatal. Without it the
    scan still produces correct findings under the current pepper — they simply
    ingest as new rather than re-keying what is already stored, which the next
    scan of the window can still fix. Refusing to scan would be the worse trade.
    """
    if not lease.previous_fingerprint_pepper:
        return None
    try:
        return base64.b64decode(lease.previous_fingerprint_pepper, validate=True)
    except ValueError, TypeError:
        logger.warning("lease_previous_pepper_unreadable")
        return None
