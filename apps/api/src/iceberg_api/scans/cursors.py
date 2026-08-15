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
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta

import structlog
from iceberg_core.enums import (
    CursorInvalidationReason,
    EngineStatus,
    ScanMode,
    ScanTaskStatus,
)
from iceberg_core.models import Engine, Scan, ScanTask, Source, SourceCursor
from sqlmodel import Session, col, select

logger = structlog.get_logger()


def _utc(value: datetime | None) -> datetime | None:
    """SQLite hands back naive datetimes even for TIMESTAMPTZ columns.

    Normalised on every comparison rather than trusted: a naive value compared to
    an aware one raises on subtraction and is silently unequal on ``!=``, and the
    silent branch is the dangerous one — it would invalidate every cursor on every
    launch and quietly turn incremental scanning off.
    """
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def _all_cursors(db: Session, source_id: uuid.UUID) -> list[SourceCursor]:
    """Every cursor row for a source, retired ones included."""
    return list(db.exec(select(SourceCursor).where(col(SourceCursor.source_id) == source_id)))


def active_cursors(db: Session, source_id: uuid.UUID) -> dict[str, SourceCursor]:
    """Every live watermark for a source, keyed by the connector's scope name.

    Live only: a retired row is inert for planning a scan. Writers want
    :func:`_all_cursors` instead, because the uniqueness index does not care
    whether a row is retired.
    """
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
    if _utc(cursor.source_configuration_version) != _utc(source.updated_at):
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
    minted = _utc(cursor.minted_at)
    if minted is not None and now - minted >= timedelta(days=source.full_scan_interval_days):
        # The periodic full reconciliation this source is configured for. This is
        # what makes it a guarantee: an incremental scan never auto-resolves, so
        # without this ceiling a source scheduled incrementally forever would never
        # resolve a remediated finding.
        return CursorInvalidationReason.INTERVAL_ELAPSED
    return None


def fleet_rulepack_version(db: Session) -> str | None:
    """The rule-pack version the fleet is running, if they agree on one.

    Rule packs ship inside engine images (ADR 0008), so the fleet is the only place
    that knows which rules are actually running. During a rolling deploy more than
    one answer is correct at once — and "we cannot say" has to read as *changed*,
    because a watermark validated against the wrong version would skip content the
    new rules have never been shown. So disagreement returns ``None``, and ``None``
    invalidates.
    """
    versions = {
        str(engine.rulepack.get("version"))
        for engine in db.exec(select(Engine).where(col(Engine.status) == EngineStatus.ACTIVE))
        if isinstance(engine.rulepack, dict) and engine.rulepack.get("version")
    }
    return versions.pop() if len(versions) == 1 else None


def plan_mode(
    db: Session,
    source: Source,
    *,
    requested: ScanMode,
    rulepack_version: str | None,
    pepper_rotating: bool,
    now: datetime,
) -> tuple[ScanMode, CursorInvalidationReason | None, datetime | None]:
    """Decide what mode a scan actually runs in, and why (#143).

    A schedule can ask for an incremental scan; it cannot have one on terms that
    would make the result untrustworthy. **Every** live cursor for the source has
    to survive validation, not just some: a scan running incrementally over the
    spaces that still have watermarks and fully over those that do not would be
    incremental for reconciliation purposes — it would still never auto-resolve —
    while costing as much as a full scan for the rest. Promoting the whole scan is
    both simpler and the only version an operator can reason about.

    Returns the resolved mode, the reason it was promoted (``None`` if it was not),
    and the baseline instant an incremental scan is starting from.
    """
    if requested is ScanMode.FULL:
        return ScanMode.FULL, None, None

    live = active_cursors(db, source.id)
    if not live:
        return ScanMode.FULL, CursorInvalidationReason.NO_CURSOR, None

    for cursor in live.values():
        reason = invalidation_for(
            cursor,
            source=source,
            rulepack_version=rulepack_version,
            pepper_rotating=pepper_rotating,
            now=now,
        )
        if reason is not None:
            invalidate(db, source.id, reason, now=now)
            return ScanMode.FULL, reason, None

    # The oldest watermark, because that is the point before which *nothing* in
    # this scan looked — the honest thing to put in the manifest.
    baseline = min(_utc(cursor.minted_at) or now for cursor in live.values())
    return ScanMode.INCREMENTAL, None, baseline


def commit_proposals(
    db: Session,
    scan: Scan,
    tasks: Sequence[ScanTask],
    *,
    now: datetime | None = None,
) -> int:
    """Store the watermarks a completed scan's tasks proposed. No commit.

    Called only from inside the gate that authorises reconciliation, and for the
    same reason: a scan that cannot be trusted to have read everything cannot be
    trusted to say where the next one should start.

    A task that *failed* proposes nothing even within a complete scan — the scan's
    coverage being complete means every object reached a disposition, not that
    every task succeeded — so its scope simply keeps the watermark it had and is
    re-read next time.
    """
    at = now or datetime.now(UTC)
    # Every row for the source, retired ones included. Retirement is modelled in
    # place while `(source_id, scope)` is unique across live and retired alike, so
    # a scope whose cursor was retired must have that row *revived* rather than a
    # second one inserted beside it. Inserting would violate the index and take
    # down the transaction that finalizes the scan — and this is the ordinary
    # path, not an edge case: every promotion retires a cursor, and the full scan
    # it promoted to then proposes a replacement for that same scope.
    existing = {row.scope: row for row in _all_cursors(db, scan.source_id)}
    stored = 0

    for task in tasks:
        if task.status is not ScanTaskStatus.COMPLETED:
            continue
        proposal = task.cursor_proposal
        if not proposal:
            continue
        scope = str(proposal.get("scope") or "")
        position = proposal.get("position")
        version = str(proposal.get("version") or "")
        if not scope or not version or not isinstance(position, dict):
            logger.warning("source_cursor_proposal_malformed", scan_id=str(scan.id))
            continue

        cursor = existing.get(scope)
        if cursor is None:
            cursor = SourceCursor(
                source_id=scan.source_id,
                scope=scope,
                position={},
                minted_by_scan_id=scan.id,
                minted_at=at,
            )
            existing[scope] = cursor
        cursor.position = {"version": version, **position}
        cursor.rulepack_version = scan.rulepack_version
        cursor.source_configuration_version = scan.source_configuration_version
        cursor.minted_by_scan_id = scan.id
        cursor.minted_at = at
        cursor.invalidated_at = None
        cursor.invalidation_reason = None
        db.add(cursor)
        stored += 1

    if stored:
        logger.info("source_cursors_stored", scan_id=str(scan.id), count=stored)
    return stored


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
