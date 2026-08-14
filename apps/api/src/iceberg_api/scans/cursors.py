"""Per-scope incremental watermarks and their invalidation (#143, ADR 0013).

A cursor records how far a *completed* scan of one scope of one source got, so the
next scan can ask the source only for what changed. Everything here exists to keep
one property true: **a cursor never claims coverage of content nobody read.**

That is why cursors are per scope rather than per source — a space whose tasks
failed simply does not advance, and is re-read in full next time, with no extra
machinery. It is why minting happens inside the same gate that authorises
reconciliation, rather than beside it. And it is why invalidation sets a column
rather than deleting the row: "why did this become a full scan?" has to stay
answerable after the cursor that caused it has gone.

The API cannot interpret a position — connectors run only in engines (ADR 0002) —
so a position is stored, compared for staleness by the metadata *around* it, and
handed back verbatim. It may hold a provider change token, which is bearer-ish for
a place in a result set, so it is never logged and never exported.
"""

import uuid
from datetime import UTC, datetime, timedelta

import structlog
from iceberg_core.enums import CursorInvalidationReason
from iceberg_core.models import Scan, Source, SourceCursor
from sqlmodel import Session, col, select

logger = structlog.get_logger()


def active_cursors(db: Session, source_id: uuid.UUID) -> dict[str, SourceCursor]:
    """Every live watermark for a source, keyed by the connector's scope name."""
    rows = db.exec(
        select(SourceCursor).where(
            col(SourceCursor.source_id) == source_id,
            col(SourceCursor.invalidated_at).is_(None),
        )
    )
    return {row.scope: row for row in rows}


def positions_for_scan(db: Session, scan: Scan) -> dict[str, dict[str, object]]:
    """The positions to hand an engine for this scan, or nothing for a full one.

    A full scan gets an empty mapping rather than the cursors it is ignoring: a
    connector that received positions during a full scan could narrow discovery
    without the API ever intending it, and the resulting scan would auto-resolve
    against content it never looked at.
    """
    from iceberg_core.enums import ScanMode

    if scan.mode is not ScanMode.FULL:
        return {
            scope: dict(cursor.position)
            for scope, cursor in active_cursors(db, scan.source_id).items()
        }
    return {}


def invalidation_for(
    cursor: SourceCursor | None,
    *,
    source: Source,
    rulepack_version: str | None,
    pepper_rotating: bool,
    now: datetime,
) -> CursorInvalidationReason | None:
    """Why this cursor cannot be trusted, or ``None`` if it can.

    The order is deliberate — the reason an operator sees should be the most
    actionable one. "You changed the source" beats "and also it is now stale".
    """
    if cursor is None:
        return CursorInvalidationReason.NO_CURSOR
    if cursor.invalidated_at is not None:
        return cursor.invalidation_reason or CursorInvalidationReason.OPERATOR_REQUESTED
    if cursor.source_configuration_version != source.updated_at:
        # Scope filters or the base URL moved, so the watermark covers a different
        # set of content than the one this scan is about to enumerate.
        return CursorInvalidationReason.SOURCE_CONFIGURATION_CHANGED
    if rulepack_version is None or cursor.rulepack_version != rulepack_version:
        # New rules must see content the old rules passed over. An unknown fleet
        # version is treated the same way: unverifiable is not the same as equal.
        return CursorInvalidationReason.RULEPACK_CHANGED
    if pepper_rotating:
        # Every fingerprint moves during a rotation, so nothing an incremental scan
        # reported would match what is stored (ADR 0006/0007).
        return CursorInvalidationReason.PEPPER_ROTATING
    if now - cursor.minted_at >= timedelta(days=source.full_scan_interval_days):
        # The periodic full reconciliation this source is configured for. This is
        # what makes it a guarantee: an incremental scan never auto-resolves, so
        # without this ceiling a source scheduled incrementally forever would never
        # resolve a remediated finding.
        return CursorInvalidationReason.INTERVAL_ELAPSED
    return None


def invalidate(
    db: Session,
    source_id: uuid.UUID,
    reason: CursorInvalidationReason,
    *,
    scope: str | None = None,
    now: datetime | None = None,
) -> int:
    """Retire live cursors so the next scan of them is a full one. No commit."""
    at = now or datetime.now(UTC)
    predicates = [
        col(SourceCursor.source_id) == source_id,
        col(SourceCursor.invalidated_at).is_(None),
    ]
    if scope is not None:
        predicates.append(col(SourceCursor.scope) == scope)

    retired = 0
    for cursor in db.exec(select(SourceCursor).where(*predicates)):
        cursor.invalidated_at = at
        cursor.invalidation_reason = reason
        db.add(cursor)
        retired += 1
    if retired:
        logger.info(
            "source_cursors_invalidated",
            source_id=str(source_id),
            reason=reason.value,
            count=retired,
        )
    return retired
