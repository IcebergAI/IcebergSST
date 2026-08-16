"""Routing a finding to an accountable group, and starting its clock (#146).

Two decisions, made at the same moment and for the same reason — a finding has
just become actionable — but with different rules about when they may be redone:

**Ownership is established once, then left alone.** An unowned finding is routed
on every sighting, so a rule added today drains yesterday's unowned queue at the
next scan. An *owned* finding is never re-routed: rules change, teams reorganise,
and a queue that silently reshuffles under the people working it is worse than one
that is occasionally out of date. Moving a finding between teams is a decision, and
a decision needs a name attached — which is what the manual override is for, and
why :attr:`Finding.owner_pinned` closes the door behind it permanently.

**The clock restarts whenever the finding opens.** A resolved secret that comes
back is not late from the day it was first found; the team gets the response target
again, from the sighting that refuted the resolution.

Everything here is pure with respect to time: the caller passes ``at``. Nothing
reads the clock, so two replicas ingesting the same batch agree, and a test can
pin a due date rather than assert around one.
"""

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import structlog
from iceberg_core.enums import SEVERITY_RANK, FindingEventKind, FindingState, Severity
from iceberg_core.models import (
    Finding,
    FindingEvent,
    OwnerGroup,
    ResponseTarget,
    RoutingRule,
    Source,
)
from sqlalchemy import case, func
from sqlalchemy.sql.elements import ColumnElement
from sqlmodel import Session, col, select

logger = structlog.get_logger()


@dataclass(frozen=True, slots=True)
class Policy:
    """The routing rules and response targets in force, loaded once.

    Held as a value rather than re-queried per finding: an ingest batch is up to a
    few hundred findings, and re-reading the same handful of rules for each one is
    both slower and *less* correct — every finding in one submission should be
    routed by the same rule set, not by whatever a concurrent edit left behind
    halfway through.
    """

    #: Enabled rules in evaluation order: priority, then created_at, then id.
    rules: tuple[RoutingRule, ...] = ()
    #: Severity → hours. A severity with no row has no target, and a finding of
    #: that severity gets no due date rather than an invented one.
    targets: dict[Severity, int] = field(default_factory=dict)
    #: The tags of each source the batch touches, by source id.
    source_tags: dict[uuid.UUID, frozenset[str]] = field(default_factory=dict)

    def target_for(self, severity: Severity) -> int | None:
        return self.targets.get(severity)

    def tags_for(self, source_id: uuid.UUID) -> frozenset[str]:
        return self.source_tags.get(source_id, frozenset())


def load(db: Session, source_id: uuid.UUID) -> Policy:
    """Read the policy in force for one source's ingest transaction."""
    rules = tuple(
        db.exec(
            select(RoutingRule)
            .where(col(RoutingRule.enabled).is_(True))
            # A rule may only route to a group that still exists and still takes
            # work. Filtering here rather than at match time keeps the "first
            # match wins" order honest: a disabled group's rule does not silently
            # swallow findings a lower-priority rule would have caught.
            .join(OwnerGroup, onclause=col(RoutingRule.owner_group_id) == col(OwnerGroup.id))
            .where(col(OwnerGroup.disabled).is_(False))
            .order_by(
                col(RoutingRule.priority),
                col(RoutingRule.created_at),
                col(RoutingRule.id),
            )
        )
    )
    targets = {row.severity: row.hours for row in db.exec(select(ResponseTarget))}
    source = db.get(Source, source_id)
    # Folded once here rather than per rule; `matches` folds the other side.
    tags = frozenset(
        str(tag).strip().casefold() for tag in (source.tags if source else ()) if str(tag).strip()
    )
    return Policy(rules=rules, targets=targets, source_tags={source_id: tags})


def matches(rule: RoutingRule, finding: Finding, tags: frozenset[str]) -> bool:
    """Whether one rule claims one finding. Matchers are ANDed; null never narrows."""
    if rule.source_id is not None and rule.source_id != finding.source_id:
        return False
    if rule.rule_id is not None and rule.rule_id != finding.rule_id:
        return False
    if (
        rule.min_severity is not None
        and SEVERITY_RANK[finding.severity] < SEVERITY_RANK[rule.min_severity]
    ):
        return False
    # Every listed tag must be present: a rule narrows, so listing more tags can
    # only ever select fewer findings.
    #
    # Compared case-insensitively. Tags are free-form labels typed twice, once on
    # the source and once on the rule, and "PCI" failing to match "pci" is a rule
    # that silently routes nothing — the hardest kind of misconfiguration to
    # notice, because the symptom is an empty queue rather than an error. The
    # stored strings keep the case an operator typed; only the comparison folds.
    return {tag.casefold() for tag in rule.source_tags}.issubset(tags)


def route(
    db: Session,
    finding: Finding,
    policy: Policy,
    *,
    scan_id: uuid.UUID,
) -> RoutingRule | None:
    """Give an unowned finding an owner, if a rule claims it. Does not commit.

    A pinned or already-owned finding is left exactly as it is; see the module
    docstring for why ownership is sticky. Returns the rule that matched, or None
    when nothing did — which is not a failure, it is the unowned queue doing its
    job.
    """
    if finding.owner_pinned or finding.owner_group_id is not None:
        return None
    tags = policy.tags_for(finding.source_id)
    for rule in policy.rules:
        if not matches(rule, finding, tags):
            continue
        finding.owner_group_id = rule.owner_group_id
        db.add(finding)
        db.add(
            FindingEvent(
                finding_id=finding.id,
                # No actor: a rule decided this, not a person. The rule's name is
                # in the comment because "which rule sent this to us?" is the
                # first question the owning team will ask.
                actor_id=None,
                scan_id=scan_id,
                kind=FindingEventKind.OWNER,
                from_value=None,
                to_value=str(rule.owner_group_id),
                comment=f"routed by rule {rule.name}",
            )
        )
        logger.info(
            "finding_routed",
            finding_id=str(finding.id),
            owner_group_id=str(rule.owner_group_id),
            rule=rule.name,
        )
        return rule
    return None


def start_clock(
    db: Session,
    finding: Finding,
    policy: Policy,
    *,
    at: datetime,
    restart: bool = False,
) -> datetime | None:
    """Set the finding's response target. Does not commit.

    ``restart`` is for a reopen: the secret came back, so the team gets the full
    target again rather than inheriting a deadline that expired while the finding
    was correctly resolved.

    Without ``restart`` this only fills a *missing* date, which is what backfills
    rows that predate ownership and rows ingested before anyone configured a
    target. An existing date is never recomputed: the target is editable, and
    re-deriving would let an edit reach backwards and declare closed work to have
    been late.

    No event is written. The date is a column, and it is a pure function of the
    finding's severity and the moment it opened — both of which are already in the
    trail — so an event per finding would double that table to say nothing new.
    """
    if finding.due_at is not None and not restart:
        return finding.due_at
    hours = policy.target_for(finding.severity)
    if hours is None:
        return None
    finding.due_at = at + timedelta(hours=hours)
    db.add(finding)
    return finding.due_at


def overdue(finding: Finding, *, at: datetime) -> bool:
    """Whether an *actionable* finding has passed its target.

    Actionable means open and not suppressed. A suppressed finding still carries
    its due date — the suppression may lapse, and the clock it was running on
    should not have to be reinvented — but it is nobody's overdue work while it
    is out of the queue (ADR 0008).

    A stored date read back without an offset is read as UTC, which is what it
    was written as. Postgres returns ``TIMESTAMP WITH TIME ZONE`` aware and
    SQLite does not, and a comparison that raised on one database and not the
    other would be a portability trap in the one function every "is this late?"
    answer goes through. Same normalisation, and same reason, as
    ``iceberg_api.schemas._assume_utc``.
    """
    if finding.state is not FindingState.OPEN or finding.suppressed_at is not None:
        return False
    if finding.due_at is None:
        return False
    due = finding.due_at if finding.due_at.tzinfo else finding.due_at.replace(tzinfo=UTC)
    return due < at


def actionable() -> tuple[ColumnElement[bool], ...]:
    """Work somebody actually owes, as ``WHERE`` clauses to splat into a query.

    The SQL half of :func:`overdue`'s first two conditions, and the reason it is a
    function rather than two lines copied into each caller: "actionable" appears
    in the owner queue, the overdue queue, and every dashboard count, and three
    copies of it would eventually disagree about whether a suppressed finding is
    somebody's problem.

    Clauses rather than a statement wrapper, because the callers are not the same
    shape — one selects findings, the other aggregates over them.
    """
    return (
        col(Finding.state) == FindingState.OPEN,
        col(Finding.suppressed_at).is_(None),
    )


@dataclass(frozen=True, slots=True)
class OwnedCounts:
    """Per-group workload, from one grouped query rather than two per group."""

    open_findings: dict[uuid.UUID, int] = field(default_factory=dict)
    overdue_findings: dict[uuid.UUID, int] = field(default_factory=dict)

    def open_for(self, group_id: uuid.UUID) -> int:
        return self.open_findings.get(group_id, 0)

    def overdue_for(self, group_id: uuid.UUID) -> int:
        return self.overdue_findings.get(group_id, 0)


def owned_counts(db: Session, *, at: datetime) -> OwnedCounts:
    """What each group currently owes, and how much of it is late.

    Grouped in the database, not in Python: the alternative is a console issuing
    two findings queries per group to render one list, and the table it would
    walk is the one that grows with every scan.
    """
    statement = (
        select(
            col(Finding.owner_group_id),
            func.count(col(Finding.id)),
            # Counted in the same pass: `case` yields NULL when the finding is not
            # late, and `count` skips NULLs. A second query would also be a second
            # walk of the table findings accumulate in.
            func.count(case((col(Finding.due_at) < at, 1))),
        )
        .where(*actionable())
        .where(col(Finding.owner_group_id).is_not(None))
        .group_by(col(Finding.owner_group_id))
    )
    open_by_group: dict[uuid.UUID, int] = {}
    overdue_by_group: dict[uuid.UUID, int] = {}
    for group_id, open_count, overdue_count in db.exec(statement).all():
        if group_id is None:  # pragma: no cover — excluded by the predicate above
            continue
        open_by_group[group_id] = int(open_count)
        overdue_by_group[group_id] = int(overdue_count)
    return OwnedCounts(open_findings=open_by_group, overdue_findings=overdue_by_group)
