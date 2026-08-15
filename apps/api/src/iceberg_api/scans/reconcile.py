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
    ScanTaskKind,
)
from iceberg_core.models import Finding, FindingEvent, Scan, ScanTask
from sqlmodel import Session, col, func, select, update

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

    Does not commit: the caller owns the transaction, so the scan's status and the
    resolutions it justifies land together.
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
    # Suppressed findings are excluded: the lease invites engines to pre-filter
    # with the suppression list (#44), so "this scan did not report it" is not
    # evidence a suppressed secret is gone. It stays open-and-suppressed until a
    # scan sees it after the suppression lapses (ADR 0008 — recorded, never
    # silently resolved).
    missing = list(
        db.exec(
            select(Finding)
            .where(col(Finding.source_id) == scan.source_id)
            .where(col(Finding.state) == FindingState.OPEN)
            .where(col(Finding.last_seen_scan_id) != scan.id)
            .where(col(Finding.suppressed_at).is_(None))
        )
    )

    if missing and not _saw_any_content(db, scan):
        # A completed scan with no fetch work at all claims every open finding is
        # gone at once. An empty space is possible — but so is a credential whose
        # scope was quietly reduced, which enumerates nothing and errors nowhere.
        # Mass-resolving on zero evidence is the failure ADR 0009 §4 exists to
        # prevent, so these findings keep their state and a human gets a log line.
        logger.warning(
            "reconciliation_refused_empty_scan",
            scan_id=str(scan.id),
            open_findings=len(missing),
            reason="scan fetched nothing; refusing to auto-resolve on absence alone",
        )
        missing = []

    # Conditional per finding rather than read-then-write. An analyst triaging
    # ``open`` → ``false_positive`` between the select above and this write would
    # otherwise be silently overwritten to resolved/auto — a transition the state
    # machine forbids, and a scan overruling a person, which ingest's whole
    # asymmetry exists to prevent. A row that moved is skipped, event included, so
    # the trail never records a `from_value` that was not true.
    resolved = 0
    for finding in missing:
        outcome = db.exec(
            update(Finding)
            .where(col(Finding.id) == finding.id, col(Finding.state) == FindingState.OPEN)
            .values(state=FindingState.RESOLVED, resolution=FindingResolution.AUTO)
        )
        if outcome.rowcount != 1:
            logger.info("auto_resolve_skipped_triaged", finding_id=str(finding.id))
            continue
        db.add(
            FindingEvent(
                finding_id=finding.id,
                # No actor: nobody decided this, a scan observed it.
                actor_id=None,
                # Provenance, and what makes this row idempotent: a partial unique
                # index refuses a second auto-resolve of this finding by this scan
                # (`models/findings.py`).
                scan_id=scan.id,
                kind=FindingEventKind.STATE_CHANGE,
                from_value=FindingState.OPEN.value,
                to_value=FindingState.RESOLVED.value,
                comment=f"not seen by scan {scan.id}",
            )
        )
        resolved += 1

    result = ReconciliationResult(
        new=_count(db, scan.source_id, first_seen=scan.id),
        seen=_count(db, scan.source_id, last_seen=scan.id),
        resolved=resolved,
        reopened=int(scan.counts.get("reopened", 0)),
    )

    # Kept on the scan so the UI can say what the run changed without recomputing.
    scan.counts = {**scan.counts, **asdict(result)}
    scan.finished_at = scan.finished_at or at
    db.add(scan)

    logger.info("reconciliation_complete", scan_id=str(scan.id), **asdict(result))
    return result


def _saw_any_content(db: Session, scan: Scan) -> bool:
    """Whether this scan had any fetch task — i.e. looked at anything at all."""
    fetched = db.exec(
        select(func.count())
        .select_from(ScanTask)
        .where(col(ScanTask.scan_id) == scan.id)
        .where(col(ScanTask.kind) == ScanTaskKind.FETCH)
    ).one()
    return int(fetched) > 0


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
