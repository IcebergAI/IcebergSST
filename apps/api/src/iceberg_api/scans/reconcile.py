"""Re-scan reconciliation (#37 — ADR 0006, ADR 0009 §4).

Triage decisions live on the fingerprint, so they have to survive a re-scan. The
diff ADR 0006 describes is split across two moments, which is worth being explicit
about:

* **new** and **matching** are handled at *ingest* (:mod:`iceberg_api.engines.ingest`).
  A finding arriving with an unseen fingerprint is created ``open``; one that
  matches an existing fingerprint keeps its triage state and has ``last_seen_scan``
  bumped. Doing it there means a finding is correct the moment it is stored, not
  after a later pass.
* **missing** is handled here, once, when the scan finishes: anything still open
  for this source that this scan did not see has been remediated, so it becomes
  ``resolved`` with resolution ``auto``.

The guard matters more than the diff. This runs **only for a scan that reached
`completed`**. A partial or failed scan did not see the whole source, and treating
"not seen" as "gone" would silently resolve every finding in the part it never
reached.
"""

import uuid
from dataclasses import asdict, dataclass
from datetime import UTC, datetime

import structlog
from iceberg_core.enums import (
    FindingEventKind,
    FindingResolution,
    FindingState,
    ScanStatus,
)
from iceberg_core.models import Finding, FindingEvent, Scan
from sqlmodel import Session, col, func, select

logger = structlog.get_logger()


@dataclass(frozen=True, slots=True)
class ReconciliationResult:
    """What one reconciliation did, recorded on the scan for the UI and for #64."""

    #: Fingerprints seen for the first time in this scan.
    new: int
    #: Fingerprints this scan saw that were already known.
    seen: int
    #: Previously-open findings this scan did not see, now auto-resolved.
    resolved: int
    #: Findings this scan saw whose fingerprint reappeared after being resolved.
    reopened: int


def reconcile_scan(
    db: Session,
    scan: Scan,
    *,
    now: datetime | None = None,
) -> ReconciliationResult | None:
    """Auto-resolve what this scan did not see. Returns None if it must not run.

    Refusing to run for a non-``completed`` scan is the whole safety property, so it
    is checked here rather than trusted to callers.
    """
    if scan.status is not ScanStatus.COMPLETED:
        logger.info(
            "reconciliation_skipped",
            scan_id=str(scan.id),
            status=scan.status.value,
            reason="only a completed scan may auto-resolve findings",
        )
        return None

    at = now or datetime.now(UTC)
    missing = list(
        db.exec(
            select(Finding)
            .where(col(Finding.source_id) == scan.source_id)
            .where(col(Finding.state) == FindingState.OPEN)
            .where(col(Finding.last_seen_scan_id) != scan.id)
        )
    )

    for finding in missing:
        finding.state = FindingState.RESOLVED
        finding.resolution = FindingResolution.AUTO
        db.add(finding)
        db.add(
            FindingEvent(
                finding_id=finding.id,
                # No actor: nobody decided this, a scan observed it.
                actor_id=None,
                kind=FindingEventKind.STATE_CHANGE,
                from_value=FindingState.OPEN.value,
                to_value=FindingState.RESOLVED.value,
                comment=f"not seen by scan {scan.id}",
            )
        )

    result = ReconciliationResult(
        new=_count(db, scan.source_id, first_seen=scan.id),
        seen=_count(db, scan.source_id, last_seen=scan.id),
        resolved=len(missing),
        reopened=int(scan.counts.get("reopened", 0)),
    )

    # Kept on the scan so the UI can say what the run changed without recomputing.
    scan.counts = {**scan.counts, **asdict(result)}
    scan.finished_at = scan.finished_at or at
    db.add(scan)
    db.commit()

    logger.info("reconciliation_complete", scan_id=str(scan.id), **asdict(result))
    return result


def _count(
    db: Session,
    source_id: uuid.UUID,
    *,
    first_seen: uuid.UUID | None = None,
    last_seen: uuid.UUID | None = None,
) -> int:
    statement = select(func.count()).select_from(Finding).where(col(Finding.source_id) == source_id)
    if first_seen is not None:
        statement = statement.where(col(Finding.first_seen_scan_id) == first_seen)
    if last_seen is not None:
        statement = statement.where(col(Finding.last_seen_scan_id) == last_seen)
    return int(db.exec(statement).one())
