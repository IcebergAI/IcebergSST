"""Correlation-id upkeep (ADR 0011, #140).

Two jobs, one derivation:

* :func:`fill_missing` — the maintenance round's repair pass. NULL ids exist
  whenever a row predates the key, or ingest ran while the key was unreadable
  (ingest fails open on this, deliberately). The input is the stored hash, so
  the repair needs no engine and no rescan.
* :func:`reindex_all` — the rotation move. After the operator swaps
  ``ICEBERG_CORRELATION_KEY_REF``, every row's id must be re-derived under the
  new key. Idempotent and restartable: rows already carrying the right value
  are counted, not rewritten, so a second run reports zero changed and an
  interrupted run converges on re-run. There is deliberately no dual-key
  window — nothing needs to *match* across the swap the way fingerprints must
  across a pepper rotation; clusters are simply recomputed.

Both run in id order with the select-then-update batch shape retention uses,
and neither commits — the caller owns the transaction.

**Every write re-asserts the hash it derived from.** An id is only correct with
respect to a particular ``secret_hash``, and ingest's pepper re-key
(`engines/ingest.py`) rewrites hash and id together in another session. A plain
ORM write here would derive from the hash this session read, then flush after
that re-key committed, leaving a *populated* id derived from a hash that no
longer exists — which neither `fill_missing` (it only selects NULLs) nor an
ordinary re-sighting would ever repair. Conditioning the UPDATE on the hash
means the loser of that race simply updates nothing.
"""

import uuid
from dataclasses import dataclass

import structlog
from iceberg_core.correlation import correlation_id
from iceberg_core.models import Finding
from sqlmodel import Session, col, select, update

logger = structlog.get_logger()


def _claim(db: Session, finding: Finding, derived: str, *, only_when_null: bool) -> bool:
    """Write ``derived`` only while the row still holds the hash it came from.

    Returns whether the row was written. ``only_when_null`` additionally keeps
    the backfill from overwriting an id another writer has meanwhile set — the
    repair pass exists to fill gaps, never to have an opinion about a populated
    value.
    """
    statement = (
        update(Finding)
        .where(col(Finding.id) == finding.id)
        .where(col(Finding.secret_hash) == finding.secret_hash)
    )
    if only_when_null:
        statement = statement.where(col(Finding.correlation_id).is_(None))
    result = db.exec(
        statement.values(correlation_id=derived).execution_options(synchronize_session="fetch")
    )
    return int(result.rowcount) > 0


@dataclass(slots=True)
class ReindexOutcome:
    """What a full reindex did, for the CLI's summary and the audit row."""

    scanned: int = 0
    updated: int = 0


def fill_missing(db: Session, key: bytes, *, batch: int) -> int:
    """Derive ids for rows that have none. Returns how many were filled.

    Bounded to one batch per call: this runs inside the maintenance round, and
    a deployment that just configured the key may have a large backlog that
    should not stall the round — the next beat continues where this one ended.
    """
    rows = list(
        db.exec(
            select(Finding)
            .where(col(Finding.correlation_id).is_(None))
            .order_by(col(Finding.id))
            .limit(batch)
        )
    )
    filled = 0
    for finding in rows:
        derived = correlation_id(finding.secret_hash, key=key)
        if _claim(db, finding, derived, only_when_null=True):
            filled += 1
    if filled:
        logger.info("correlation_backfilled", filled=filled)
    return filled


def reindex_all(db: Session, key: bytes, *, batch: int) -> ReindexOutcome:
    """Re-derive every row's id under ``key``. The key-rotation migration path.

    Walks the whole table in id-ordered batches inside one transaction. Rows
    whose stored id already matches are left untouched, which is what makes the
    second run after a completed rotation report ``updated=0`` — the operator's
    signal that the rotation is done.
    """
    outcome = ReindexOutcome()
    last_id: uuid.UUID | None = None
    while True:
        query = select(Finding).order_by(col(Finding.id)).limit(batch)
        if last_id is not None:
            query = query.where(col(Finding.id) > last_id)
        rows = list(db.exec(query))
        if not rows:
            break
        for finding in rows:
            outcome.scanned += 1
            derived = correlation_id(finding.secret_hash, key=key)
            if finding.correlation_id != derived and _claim(
                db, finding, derived, only_when_null=False
            ):
                outcome.updated += 1
        last_id = rows[-1].id
    logger.info("correlation_reindexed", scanned=outcome.scanned, updated=outcome.updated)
    return outcome
