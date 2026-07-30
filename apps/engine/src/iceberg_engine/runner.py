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
from iceberg_connectors import (
    ConnectorError,
    ContentUnit,
    FetchOutcome,
    TaskSpec,
    registry,
)
from iceberg_connectors.protocol import Connector
from iceberg_core.fingerprint import fingerprint, secret_hash
from iceberg_detect import DetectionResult, RulePack, detect

from iceberg_engine.api_client import (
    AuthenticationFailed,
    EngineApiError,
    EngineClient,
    Lease,
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
        return submission


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
    the reason, so the scan settles promptly instead of waiting out a lease.

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
        return None
    except ConnectorError as exc:
        # The source said no — bad credential, unreachable, unsupported type. The
        # scan should report why rather than an empty result that reads as "clean".
        # Connector messages are our own and carry paths, not content (ADR 0004).
        report.status = "failed"
        report.error = f"{type(exc).__name__}: {exc}"[:2000]
        log.warning("scan_task_connector_failed", error=report.error)
    except Exception as exc:
        # A bug, or something nobody anticipated. The message may have been produced
        # by a third-party library quoting its input, which could be page content or
        # a secret — so only the exception *type* is reported to the API and stored
        # (ADR 0004). The full detail stays in this engine's local log.
        report.status = "failed"
        report.error = type(exc).__name__
        log.exception("scan_task_failed")

    if not _submit(client, lease, report, pack, log):
        return None
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
    except (LeaseRefused, AuthenticationFailed):
        # On the results route a 403/409 means the lease is gone, not a bad token:
        # it worked at lease time moments ago. The task is no longer ours to report.
        log.info("scan_task_lease_lost_before_report", status=report.status)
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
    specs = list(connector.discover(lease.connection, lease.credential))
    report.task_specs = [spec.as_payload() for spec in specs]
    report.counts["specs_discovered"] = len(specs)


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
    outcome = FetchOutcome()
    spec = TaskSpec.from_payload(lease.spec)

    candidates: list[Candidate] = []
    tallies = {"units_truncated": 0, "dropped_below_threshold": 0}

    for unit in connector.fetch(lease.connection, spec, lease.credential, outcome):
        # Between units, not mid-unit: a content unit is small and finishing one
        # is cheaper than the bookkeeping to abandon it half-scanned.
        if tasks is not None and task_id is not None and tasks.is_cancelled(task_id):
            raise TaskCancelled(str(task_id))
        result = detect(unit.text, pack, threshold=lease.confidence_threshold)
        tallies["dropped_below_threshold"] += result.dropped_below_threshold
        tallies["units_truncated"] += int(result.truncated)
        candidates.extend(_candidates(unit, result, pepper=pepper, pack=pack))

    # Pre-filter locally to save bandwidth. The API applies the same suppressions
    # again at ingest, authoritatively, so this can only ever be the more
    # permissive of the two (#44).
    filtered = prefilter(candidates, rules_from_lease(lease.suppressions))

    report.findings = [candidate.payload for candidate in filtered.kept]
    report.counts = {
        **outcome.as_counts(),
        **tallies,
        "prefiltered": filtered.suppressed_count,
    }


def _candidates(
    unit: ContentUnit,
    result: DetectionResult,
    *,
    pepper: bytes,
    pack: RulePack,
) -> Iterator[Candidate]:
    """Turn detected secrets into reportable findings.

    The only place the plaintext is touched: hashed once for identity, then left
    behind. What continues is a masked snippet and two hex digests.
    """
    for found in result.secrets:
        hashed = secret_hash(found.secret, pepper=pepper)
        identity = fingerprint(
            locator=unit.locator, rule_id=found.rule_id, secret_hash=hashed, pepper=pepper
        )
        locator = unit.resource_locator() | {"offset": found.span.start}
        yield Candidate(
            fingerprint=identity,
            rule_id=found.rule_id,
            resource_locator=locator,
            payload={
                "fingerprint": identity,
                "rule_id": found.rule_id,
                "rulepack_version": pack.version,
                "resource_locator": locator,
                "redacted_snippet": found.redacted_snippet,
                "secret_hash": hashed,
                "entropy": found.entropy,
                "confidence": found.confidence,
                "severity": found.severity,
            },
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
