"""Persisting what an engine reports (#36, #37 — ADR 0004, 0006, 0008).

The "new" and "matching" halves of reconciliation happen here, at the moment a
finding arrives:

* **unseen fingerprint** → a new finding, ``open``
* **known fingerprint** → keep its triage state, bump ``last_seen_scan``, refresh
  the display fields
* **known and auto-resolved** → re-open it: the secret came back
* **suppressed** → stored and marked, never discarded (ADR 0008)

A deliberate asymmetry: an analyst's decision (`false_positive`, `accepted_risk`) is
never overwritten by a scan, but an *automatic* resolution is, because that was only
ever an inference from absence.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime

import structlog
from iceberg_core.enums import FindingEventKind, FindingResolution, FindingState
from iceberg_core.metrics import FINDINGS_INGESTED
from iceberg_core.models import Finding, FindingEvent, Scan
from sqlmodel import Session, col, select

from iceberg_api import suppressions
from iceberg_api.engines.schemas import FindingPayload

logger = structlog.get_logger()


@dataclass(slots=True)
class IngestOutcome:
    """Tallies for the response, the scan's counts, and the logs."""

    ingested: int = 0
    suppressed: int = 0
    reopened: int = 0
    fingerprints: list[str] = field(default_factory=list)


def ingest_findings(
    db: Session,
    scan: Scan,
    payloads: list[FindingPayload],
    *,
    now: datetime | None = None,
) -> IngestOutcome:
    """Store a task's findings. Does not commit; the route owns the transaction."""
    at = now or datetime.now(UTC)
    rules = suppressions.applicable_suppressions(db, scan.source_id, now=at)
    outcome = IngestOutcome()

    for payload in payloads:
        suppression = suppressions.first_match(
            rules,
            fingerprint=payload.fingerprint,
            rule_id=payload.rule_id,
            resource_locator=payload.resource_locator,
        )
        existing = db.exec(
            select(Finding)
            .where(col(Finding.source_id) == scan.source_id)
            .where(col(Finding.fingerprint) == payload.fingerprint)
        ).first()

        if existing is None:
            _create(db, scan, payload, suppression=suppression, at=at)
        elif _refresh(db, existing, scan, payload, suppression=suppression, at=at):
            outcome.reopened += 1

        outcome.ingested += 1
        outcome.fingerprints.append(payload.fingerprint)
        if suppression is not None:
            outcome.suppressed += 1

    FINDINGS_INGESTED.inc(outcome.ingested)
    logger.info(
        "findings_ingested",
        scan_id=str(scan.id),
        ingested=outcome.ingested,
        suppressed=outcome.suppressed,
        reopened=outcome.reopened,
    )
    return outcome


def _create(
    db: Session,
    scan: Scan,
    payload: FindingPayload,
    *,
    suppression: suppressions.SuppressionRule | None,
    at: datetime,
) -> Finding:
    finding = Finding(
        source_id=scan.source_id,
        fingerprint=payload.fingerprint,
        rule_id=payload.rule_id,
        rulepack_version=payload.rulepack_version,
        resource_locator=payload.resource_locator,
        redacted_snippet=payload.redacted_snippet,
        secret_hash=payload.secret_hash,
        entropy=payload.entropy,
        confidence=payload.confidence,
        severity=payload.severity,
        state=FindingState.OPEN,
        first_seen_scan_id=scan.id,
        last_seen_scan_id=scan.id,
    )
    db.add(finding)
    db.flush()
    if suppression is not None:
        suppressions.suppress(db, finding, suppression, at=at)
    return finding


def _refresh(
    db: Session,
    finding: Finding,
    scan: Scan,
    payload: FindingPayload,
    *,
    suppression: suppressions.SuppressionRule | None,
    at: datetime,
) -> bool:
    """Update a known finding for this sighting. Returns True if it re-opened."""
    finding.last_seen_scan_id = scan.id

    # Display metadata is refreshed — line numbers move, snippets change around the
    # secret — while identity (fingerprint, secret_hash) is by definition unchanged.
    finding.resource_locator = payload.resource_locator
    finding.redacted_snippet = payload.redacted_snippet
    finding.rulepack_version = payload.rulepack_version
    finding.entropy = payload.entropy
    finding.confidence = payload.confidence
    finding.severity = payload.severity

    reopened = False
    if finding.state is FindingState.RESOLVED and finding.resolution is FindingResolution.AUTO:
        # It disappeared, we resolved it, and now it is back. An automatic
        # resolution was an inference; a sighting is evidence.
        finding.state = FindingState.OPEN
        finding.resolution = None
        db.add(
            FindingEvent(
                finding_id=finding.id,
                actor_id=None,
                kind=FindingEventKind.REOPENED,
                from_value=FindingState.RESOLVED.value,
                to_value=FindingState.OPEN.value,
                comment=f"seen again by scan {scan.id}",
            )
        )
        reopened = True

    # A suppression that appeared since the last scan applies now; one that expired
    # stops applying, and the finding returns to the active view.
    if suppression is not None:
        suppressions.suppress(db, finding, suppression, at=at)
    else:
        suppressions.release(db, finding, reason=f"no suppression matched in scan {scan.id}")

    db.add(finding)
    return reopened


def merge_scan_counts(scan: Scan, outcome: IngestOutcome, engine_counts: dict[str, int]) -> None:
    """Accumulate one task's tallies onto the scan.

    Additive because tasks report independently and in any order: a scan's counts are
    the sum of what its tasks saw, not whatever the last one to finish happened to
    report.
    """
    totals: dict[str, int] = {
        key: int(value) for key, value in scan.counts.items() if isinstance(value, int | float)
    }
    for key, value in engine_counts.items():
        totals[key] = totals.get(key, 0) + int(value)
    totals["findings"] = totals.get("findings", 0) + outcome.ingested
    totals["suppressed"] = totals.get("suppressed", 0) + outcome.suppressed
    totals["reopened"] = totals.get("reopened", 0) + outcome.reopened
    scan.counts = {**scan.counts, **totals}
