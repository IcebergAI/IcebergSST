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

**Plaintext never leaves this function.** Detection redacts before returning, the
secret is used exactly twice — hashed, then dropped — and the payload type has no
field for it. The engine is the last place a secret exists in the clear, which is
the whole of ADR 0004.
"""

import base64
import uuid
from collections.abc import Iterator
from contextlib import nullcontext
from dataclasses import dataclass, field
from typing import Any

import structlog
from dramatiq.middleware import Interrupt
from iceberg_connectors import (
    ConnectorError,
    ConnectorFailureCode,
    ContentUnit,
    FetchOutcome,
    TaskCoverage,
    TaskSpec,
    registry,
)
from iceberg_connectors.protocol import Connector
from iceberg_core.enums import CoverageObjectKind, CoverageReason, ScanTaskKind
from iceberg_core.fingerprint import fingerprint, secret_hash
from iceberg_core.metrics import (
    ENGINE_CONNECTOR_FAILURES,
    ENGINE_FINDINGS_REPORTED,
    ENGINE_TASKS_RUN,
)
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


@dataclass(slots=True)
class TaskReport:
    """What the task will tell the API, accumulated as it goes."""

    status: str = "completed"
    error: str | None = None
    findings: list[dict[str, Any]] = field(default_factory=list)
    task_specs: list[dict[str, Any]] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)
    coverage: TaskCoverage | None = None

    def as_submission(self, idempotency_key: str, rulepack_version: str | None) -> dict[str, Any]:
        submission: dict[str, Any] = {
            "idempotency_key": idempotency_key,
            "status": self.status,
            "findings": self.findings,
            "task_specs": self.task_specs,
            "counts": self.counts,
        }
        if self.error:
            submission["error"] = self.error
        if rulepack_version:
            submission["rulepack_version"] = rulepack_version
        if self.coverage is not None:
            submission["coverage"] = self.coverage.as_payload()
        return submission


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

    try:
        with held:
            connector = registry.get(lease.source_type)
            if lease.kind == DISCOVERY:
                _discover(connector, lease, report)
            elif lease.kind == FETCH:
                _fetch(connector, lease, report, pack=pack, tasks=tasks, task_id=task_id)
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
        _record_task_gap(report, lease, reason)
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
        _record_task_gap(report, lease, CoverageReason.TIMEOUT)
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
        _record_task_gap(report, lease, CoverageReason.CONNECTOR_ERROR)
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
    configured_scopes = {
        str(value).strip().casefold()
        for value in lease.connection.get("spaces") or ()
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
    try:
        for spec in connector.discover(lease.connection, lease.credential):
            # Append as discovery progresses so a late failure (for example one
            # configured space missing after other matches) does not discard the
            # matched spaces.  The failed discovery keeps the overall scan partial,
            # so fetching these specs can surface findings but cannot reconcile.
            report.task_specs.append(spec.as_payload())
            coverage.scope_found(spec.params)
    finally:
        report.counts["specs_discovered"] = len(report.task_specs)


def _fetch(
    connector: Connector,
    lease: Lease,
    report: TaskReport,
    *,
    pack: RulePack,
    tasks: TaskRegistry | None = None,
    task_id: uuid.UUID | None = None,
) -> None:
    """Phase two: scan the content one spec describes.

    Text extraction is not here. A connector yields `ContentUnit`s that already
    hold text, so whether an attachment needed a PDF parser — and the sandbox that
    parser ran in — is the connector's business (#46). The runner sees text.
    """
    pepper = _pepper(lease)
    previous_pepper = _previous_pepper(lease)
    outcome = FetchOutcome(reference_key=pepper)
    spec = TaskSpec.from_payload(lease.spec)

    candidates: list[Candidate] = []
    tallies = {"units_truncated": 0, "dropped_below_threshold": 0}

    try:
        for unit in connector.fetch(lease.connection, spec, lease.credential, outcome):
            # Between units, not mid-unit: a content unit is small and finishing one
            # is cheaper than the bookkeeping to abandon it half-scanned.
            if tasks is not None and task_id is not None and tasks.is_cancelled(task_id):
                raise TaskCancelled(str(task_id))
            result = detect(unit.text, pack, threshold=lease.confidence_threshold)
            tallies["dropped_below_threshold"] += result.dropped_below_threshold
            tallies["units_truncated"] += int(result.truncated)
            if result.truncated and not unit.display.get("truncated", False):
                outcome.scanned_but_incomplete(
                    CoverageReason.OUTPUT_LIMIT,
                    _coverage_kind(unit),
                    unit.locator.canonical_parts(),
                )
            candidates.extend(
                _candidates(unit, result, pepper=pepper, previous_pepper=previous_pepper, pack=pack)
            )
    finally:
        # In a `finally` because a source that gives out halfway — a pagination cap,
        # retries exhausted against a blipping Confluence — must not discard the
        # units before it. `complete_task(FAILED)` is terminal, so anything left
        # here surfaces only if an operator re-runs the whole scan (#115).
        #
        # Pre-filter locally to save bandwidth. The API applies the same
        # suppressions again at ingest, authoritatively, so this can only ever be
        # the more permissive of the two (#44).
        filtered = prefilter(candidates, rules_from_lease(lease.suppressions))

        report.findings = [candidate.payload for candidate in filtered.kept]
        report.counts = {
            **outcome.as_counts(),
            **tallies,
            "prefiltered": filtered.suppressed_count,
        }
        report.coverage = outcome.coverage
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

    if phase is ScanTaskKind.DISCOVERY and coverage.scope_requested is not None:
        wanted = {str(value).casefold(): value for value in lease.connection.get("spaces") or ()}
        found = {
            str(spec.get("params", {}).get("space_key") or "").casefold()
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


def _coverage_kind(unit: ContentUnit) -> CoverageObjectKind:
    if unit.origin.value == "comment":
        return CoverageObjectKind.COMMENT
    if unit.origin.value == "attachment":
        return CoverageObjectKind.ATTACHMENT
    return CoverageObjectKind.PAGE


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
