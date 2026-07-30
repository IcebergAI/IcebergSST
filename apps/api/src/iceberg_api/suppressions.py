"""Matching analyst suppressions against findings, and applying them (ADR 0008).

Suppressions are runtime data, not code: an analyst silences a known-benign match
without waiting for a rule-pack release. Matching lives here rather than in
:mod:`iceberg_api.findings` because both surfaces need it — the engine-facing lease
sends the applicable rules to a worker, and ingest applies them again on the way
in. The CRUD routes are in :mod:`iceberg_api.findings.suppression_routes` (#40).

Three properties are worth stating because they are easy to get wrong:

* **The API is the authoritative enforcement point.** Engines receive the
  applicable suppressions in their lease and pre-filter locally to save bandwidth,
  but ingest applies them again. A suppression created after an engine leased its
  task is still honoured, because the copy that decides is the one read at ingest
  (#44).
* **Suppressed findings are recorded, not discarded.** They are stored and marked,
  so "why is this not in my list?" has an answer and an expiring suppression brings
  the finding back rather than losing the history.
* **One matcher, two roles.** Whether a suppression covers a finding is decided by
  :mod:`iceberg_core.suppression`, which the engine imports too. Two
  implementations that agreed today would drift, and a match the engine pre-filters
  away that the API would have kept is a finding that silently never existed.
* **Suppression is applied and lifted eagerly.** Creating one covers the findings
  it already matches, deleting one releases them, and
  :func:`release_lapsed` returns findings whose suppression has expired. Waiting
  for the next scan would make a suppression feel broken for a day and, worse,
  would leave an expired one hiding findings indefinitely for a source nobody
  re-scans.
"""

import uuid
from datetime import UTC, datetime

import structlog
from iceberg_core.enums import FindingEventKind, SuppressionScope
from iceberg_core.models import Finding, FindingEvent, Suppression
from iceberg_core.suppression import SuppressionRule, first_match, matches
from sqlmodel import Session, col, or_, select

__all__ = [
    "SuppressionRule",
    "applicable_suppressions",
    "apply_to_existing",
    "first_match",
    "matches",
    "release",
    "release_covered_by",
    "release_lapsed",
    "suppress",
]

logger = structlog.get_logger()


def applicable_suppressions(
    db: Session,
    source_id: uuid.UUID,
    *,
    now: datetime | None = None,
) -> list[SuppressionRule]:
    """Every live suppression for this source, plus the global ones.

    ``source_id IS NULL`` means global. An expired suppression is simply not
    returned — expiry is how an analyst says "silence this for a sprint" without
    having to remember to undo it.
    """
    at = now or datetime.now(UTC)
    rows = db.exec(
        select(Suppression).where(
            or_(col(Suppression.source_id) == source_id, col(Suppression.source_id).is_(None))
        )
    )
    return [
        SuppressionRule(id=row.id, scope=row.scope, pattern=row.pattern)
        for row in rows
        if row.expires_at is None or _as_utc(row.expires_at) > at
    ]


def suppress(
    db: Session,
    finding: Finding,
    rule: SuppressionRule,
    *,
    at: datetime,
    actor_id: uuid.UUID | None = None,
) -> None:
    """Mark a finding as covered by ``rule`` and record why. Does not commit.

    Idempotent: a finding already out of the active view is left with the timestamp
    it was first suppressed at, so "since when?" keeps its original answer.
    """
    already = finding.suppressed_at is not None
    finding.suppressed_at = finding.suppressed_at or at
    finding.suppressed_by_id = rule.id
    db.add(finding)
    if not already:
        db.add(
            FindingEvent(
                finding_id=finding.id,
                actor_id=actor_id,
                kind=FindingEventKind.SUPPRESSED,
                to_value=rule.scope.value,
                comment=f"matched suppression {rule.id}",
            )
        )


def release(
    db: Session,
    finding: Finding,
    *,
    reason: str,
    actor_id: uuid.UUID | None = None,
) -> None:
    """Return a suppressed finding to the active view and say why. Does not commit.

    The event matters as much as the flag: a finding reappearing in the queue with
    no explanation is the kind of thing analysts learn to distrust.
    """
    if finding.suppressed_at is None:
        return
    finding.suppressed_at = None
    finding.suppressed_by_id = None
    db.add(finding)
    db.add(
        FindingEvent(
            finding_id=finding.id,
            actor_id=actor_id,
            kind=FindingEventKind.COMMENT,
            comment=reason,
        )
    )


def apply_to_existing(
    db: Session,
    suppression: Suppression,
    *,
    now: datetime | None = None,
    actor_id: uuid.UUID | None = None,
) -> int:
    """Suppress the findings a new suppression already covers. Does not commit.

    An analyst silencing known noise expects the noise to go away now, not after
    the next scan of a source that may be scheduled weekly.
    """
    at = now or datetime.now(UTC)
    rule = SuppressionRule(id=suppression.id, scope=suppression.scope, pattern=suppression.pattern)

    statement = select(Finding).where(col(Finding.suppressed_at).is_(None))
    if suppression.source_id is not None:
        statement = statement.where(col(Finding.source_id) == suppression.source_id)
    # Narrow in SQL where the scope allows it. `path_glob` cannot: the glob is
    # matched against a JSON locator whose shape differs per connector, so those
    # candidates are filtered in Python by the same `matches` the ingest path uses.
    match rule.scope:
        case SuppressionScope.FINGERPRINT:
            statement = statement.where(col(Finding.fingerprint) == rule.pattern)
        case SuppressionScope.RULE:
            statement = statement.where(col(Finding.rule_id) == rule.pattern)
        case SuppressionScope.PATH_GLOB:
            pass

    covered = 0
    for finding in db.exec(statement):
        if matches(
            rule,
            fingerprint=finding.fingerprint,
            rule_id=finding.rule_id,
            resource_locator=finding.resource_locator,
        ):
            suppress(db, finding, rule, at=at, actor_id=actor_id)
            covered += 1

    logger.info(
        "suppression_applied",
        suppression_id=str(suppression.id),
        scope=suppression.scope.value,
        findings_suppressed=covered,
    )
    return covered


def release_covered_by(
    db: Session,
    suppression: Suppression,
    *,
    actor_id: uuid.UUID | None = None,
) -> int:
    """Release everything one suppression is hiding. Does not commit.

    Called when the suppression is deleted. The database would only null the
    foreign key, which is the worst outcome available: a finding hidden forever
    with nothing left to say which rule hid it.

    Suppressions overlap — a rule-wide one and a path glob can cover the same
    finding — and only the first match is recorded. A finding another live
    suppression still covers is handed over to it rather than released, so deleting
    one rule does not make findings a different rule silences reappear.
    """
    at = datetime.now(UTC)
    findings = db.exec(select(Finding).where(col(Finding.suppressed_by_id) == suppression.id)).all()
    # Cached per source: the covered findings usually share one.
    remaining: dict[uuid.UUID, list[SuppressionRule]] = {}

    released = 0
    for finding in findings:
        if finding.source_id not in remaining:
            remaining[finding.source_id] = [
                rule
                for rule in applicable_suppressions(db, finding.source_id, now=at)
                if rule.id != suppression.id
            ]
        replacement = first_match(
            remaining[finding.source_id],
            fingerprint=finding.fingerprint,
            rule_id=finding.rule_id,
            resource_locator=finding.resource_locator,
        )
        if replacement is not None:
            # Still hidden, by something else. No release event: it never left the
            # hidden set, and an event pair saying so would only be noise.
            finding.suppressed_by_id = replacement.id
            db.add(finding)
            logger.info(
                "suppression_handed_over",
                finding_id=str(finding.id),
                from_suppression_id=str(suppression.id),
                to_suppression_id=str(replacement.id),
            )
            continue
        release(db, finding, reason=f"suppression {suppression.id} deleted", actor_id=actor_id)
        released += 1

    return released


def release_lapsed(db: Session, *, now: datetime | None = None) -> int:
    """Return findings whose suppression has expired or vanished. Does not commit.

    Ingest already stops applying a lapsed suppression, but that only helps a
    source that gets scanned again. This runs on the maintenance beat so expiry is
    a property of the clock rather than of the scan schedule.
    """
    at = now or datetime.now(UTC)
    hidden = db.exec(select(Finding).where(col(Finding.suppressed_at).is_not(None))).all()
    if not hidden:
        return 0
    # Suppressions are analyst-managed and few; reading them once beats a lookup
    # per hidden finding.
    by_id = {row.id: row for row in db.exec(select(Suppression))}

    released = 0
    for finding in hidden:
        suppression = by_id.get(finding.suppressed_by_id) if finding.suppressed_by_id else None
        if suppression is None:
            # The suppression row is gone but the finding still points at nothing.
            # Self-healing rather than an invariant: a hidden finding with no
            # explanation must not survive a beat.
            release(db, finding, reason="suppression no longer exists")
        elif suppression.expires_at is not None and _as_utc(suppression.expires_at) <= at:
            release(db, finding, reason=f"suppression {suppression.id} expired")
        else:
            continue
        released += 1

    if released:
        logger.info("suppressions_lapsed", findings_released=released)
    return released


def _as_utc(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)
