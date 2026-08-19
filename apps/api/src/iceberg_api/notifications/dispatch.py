"""Deciding who to tell, and then telling them (#60).

Two halves, deliberately in different transactions.

:func:`enqueue_for_scan` runs at the end of reconciliation, in the transaction
that finished the scan. It writes one ``NotificationDelivery`` row per (channel,
finding) that qualifies and sends nothing. A transactional outbox: if the scan
commits, the intention to announce commits with it, and no webhook timeout can
roll back a scan or drop an alert.

:func:`deliver_pending` runs in the maintenance loop, under the same advisory
lock as everything else there, so one replica delivers even when five are up. It
attempts due rows, marks them delivered, or schedules a retry with exponential
backoff until the attempt ceiling — at which point the row goes ``failed`` and
stays, holding the error that ended it. Nothing is deleted, so "what were we
never able to send?" is a query rather than a log search.

Which findings qualify is narrower than it might look. A finding is announced
when **this scan opened it** — first seen here, or seen again after having been
resolved. Not every open finding every scan: an operator who is told about the
same secret weekly stops reading the alerts, and the finding is on the console
either way.
"""

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

import structlog
from iceberg_core.config import ApiSettings
from iceberg_core.enums import (
    FindingEventKind,
    FindingState,
    NotificationChannelType,
    NotificationDeliveryStatus,
    NotificationEventKind,
    Severity,
)
from iceberg_core.models import (
    Finding,
    FindingEvent,
    NotificationChannel,
    NotificationDelivery,
    OwnerGroup,
    Scan,
    Source,
)
from iceberg_core.secrets import SecretStore
from sqlalchemy import ColumnElement, and_, func, or_, true
from sqlmodel import Session, col, select

from iceberg_api.findings import ownership
from iceberg_api.notifications.payload import (
    email_subject,
    escalation_subject,
    finding_opened,
    finding_overdue,
)
from iceberg_api.notifications.schemas import EventFilter
from iceberg_api.notifications.transports import (
    DeliveryError,
    Transport,
    build_transports,
)

logger = structlog.get_logger()

#: Severity order for the ``min_severity`` filter. Defined here rather than on the
#: enum because "critical is worse than high" is a policy this filter applies, not
#: a property of the label.
_SEVERITY_RANK: dict[Severity, int] = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}


@dataclass(frozen=True, slots=True)
class DeliveryOutcome:
    """What one delivery round did."""

    delivered: int = 0
    retrying: int = 0
    failed: int = 0


def newly_opened_findings(db: Session, scan: Scan) -> list[Finding]:
    """Findings this scan opened: first seen here, or re-opened here.

    Suppressed findings are excluded. A suppression is an analyst saying "stop
    telling me about this" (ADR 0008), and it would be a poor system that honoured
    that in the UI and mailed them anyway.
    """
    first_seen = select(Finding).where(
        col(Finding.first_seen_scan_id) == scan.id,
        col(Finding.state) == FindingState.OPEN,
        col(Finding.suppressed_at).is_(None),
    )
    # A re-opened finding was first seen by some earlier scan, so it is identified
    # by the event ingest wrote when the secret came back — which carries this
    # scan's id. (Not the display comment: rewording that in ingest must not
    # silently stop reopen announcements.)
    reopened = (
        select(Finding)
        .join(FindingEvent, col(FindingEvent.finding_id) == col(Finding.id))
        .where(
            col(Finding.last_seen_scan_id) == scan.id,
            col(Finding.state) == FindingState.OPEN,
            col(Finding.suppressed_at).is_(None),
            col(FindingEvent.kind) == FindingEventKind.REOPENED,
            col(FindingEvent.scan_id) == scan.id,
        )
    )
    findings = {finding.id: finding for finding in db.exec(first_seen)}
    findings.update({finding.id: finding for finding in db.exec(reopened)})
    return list(findings.values())


class Filtered(Protocol):
    """Anything carrying an event filter.

    A protocol rather than :class:`NotificationChannel`, because a handoff target
    carries the same filter for the same purpose (#141) — one filter vocabulary
    across both egress paths, rather than two that drift.
    """

    event_filter: dict[str, Any]


def channel_wants(channel: Filtered, finding: Finding) -> bool:
    """Whether this channel's event filter selects this finding."""
    event_filter = EventFilter.model_validate(channel.event_filter)
    if event_filter.min_severity is not None and (
        _SEVERITY_RANK[finding.severity] < _SEVERITY_RANK[event_filter.min_severity]
    ):
        return False
    return not (event_filter.source_ids and finding.source_id not in event_filter.source_ids)


def _severities_at_or_above(minimum: Severity) -> list[Severity]:
    """The severities a ``min_severity`` filter accepts.

    Enumerated rather than compared in SQL, because the column stores the label
    and the order is this filter's policy, not the label's.
    """
    return [level for level in Severity if _SEVERITY_RANK[level] >= _SEVERITY_RANK[minimum]]


def _wanted_by(channel: Filtered) -> ColumnElement[bool]:
    """:func:`channel_wants`, as a predicate the database can apply.

    The same parsed :class:`EventFilter` drives both, so there is one filter
    *vocabulary*; only the place it is evaluated differs, and
    ``test_the_two_readings_of_a_channel_filter_agree`` holds the two answers
    together rather than trusting them to stay in step.

    It exists because "does this finding have anywhere to escalate to?" has to be
    answerable *before* the limit. Answering it in Python after the page is
    selected is what let findings with no target hold the front of the queue
    forever (#190).
    """
    event_filter = EventFilter.model_validate(channel.event_filter)
    clauses: list[ColumnElement[bool]] = []
    if event_filter.min_severity is not None:
        clauses.append(
            col(Finding.severity).in_(_severities_at_or_above(event_filter.min_severity))
        )
    if event_filter.source_ids:
        clauses.append(col(Finding.source_id).in_(event_filter.source_ids))
    return and_(*clauses) if clauses else true()


def _has_escalation_target(
    channels: list[NotificationChannel], groups: list[OwnerGroup]
) -> ColumnElement[bool]:
    """Whether an overdue finding has anywhere to go — the SQL twin of
    :func:`_escalation_targets`.

    Three ways to have a target, mirroring that function: an owning team whose
    channel is enabled; no owner at all, or a disbanded one, plus some enabled
    channel whose filter selects the finding. A team that is silent by choice
    matches none of them, which is the point — silence is allowed, but it must not
    cost everybody behind them their escalation (#190).
    """
    enabled_channel_ids = {channel.id for channel in channels}
    targeted = [
        group.id
        for group in groups
        if not group.disabled and group.notification_channel_id in enabled_channel_ids
    ]
    disbanded = [group.id for group in groups if group.disabled]
    broadcast = or_(*[_wanted_by(channel) for channel in channels])
    return or_(
        col(Finding.owner_group_id).in_(targeted),
        and_(
            or_(
                col(Finding.owner_group_id).is_(None),
                col(Finding.owner_group_id).in_(disbanded),
            ),
            broadcast,
        ),
    )


def enqueue_for_scan(db: Session, scan: Scan, *, now: datetime | None = None) -> int:
    """Record an announcement per (enabled channel, newly-opened finding).

    Does not commit — the caller owns the transaction, which is the whole point
    of an outbox. Returns how many rows were written.
    """
    channels = list(db.exec(select(NotificationChannel).where(col(NotificationChannel.enabled))))
    if not channels:
        return 0

    findings = newly_opened_findings(db, scan)
    if not findings:
        return 0

    at = now or datetime.now(UTC)
    queued = 0
    for finding in findings:
        for channel in channels:
            if not channel_wants(channel, finding):
                continue
            # The unique constraint is the real guard against double-announcing;
            # this check just avoids a savepoint in the common case. Re-running
            # enqueue for the same scan (the stalled-scan sweep does exactly that)
            # must be a no-op.
            already = db.exec(
                select(NotificationDelivery).where(
                    col(NotificationDelivery.channel_id) == channel.id,
                    col(NotificationDelivery.finding_id) == finding.id,
                    col(NotificationDelivery.scan_id) == scan.id,
                )
            ).first()
            if already is not None:
                continue
            db.add(
                NotificationDelivery(
                    channel_id=channel.id,
                    finding_id=finding.id,
                    scan_id=scan.id,
                    status=NotificationDeliveryStatus.PENDING,
                    next_attempt_at=at,
                )
            )
            queued += 1

    if queued:
        logger.info(
            "notifications_enqueued",
            scan_id=str(scan.id),
            findings=len(findings),
            channels=len(channels),
            queued=queued,
        )
    return queued


def escalate_overdue(db: Session, *, now: datetime | None = None, limit: int = 200) -> int:
    """Announce findings that have passed their response target (#146).

    Runs in the maintenance loop rather than at ingest, because nothing *happens*
    when a finding goes overdue — a deadline passes. There is no transaction to
    hang an outbox row off, so the clock is what notices.

    **Who hears about it.** The owning team's channel, if the group has one: an
    escalation is a message to the people accountable, not a broadcast. A finding
    nobody owns has no such channel, so it falls back to every enabled channel
    that would have announced it when it opened — those channels already hear
    about this class of finding, and "late, and nobody has picked it up" is the
    one state most worth saying out loud. A group with no channel configured is
    silent by choice, and the console's overdue queue is still the record.

    **Once per deadline.** The row carries the ``due_at`` it is about, and a
    partial unique index enforces one escalation per (channel, finding, deadline).
    A reopened finding gets a fresh deadline and therefore a fresh escalation,
    which is right — the team missed a new target, not the old one again.

    Does not commit; the caller owns the transaction, like every other outbox
    write here. Returns how many rows were written.
    """
    at = now or datetime.now(UTC)
    channels = list(db.exec(select(NotificationChannel).where(col(NotificationChannel.enabled))))
    if not channels:
        return 0

    # Actionable, past the target, and **not already escalated for this deadline**.
    #
    # The exclusion is in SQL, before the limit, and that ordering is the whole
    # point: filtering in Python afterwards would re-select the same oldest page
    # on every beat, skip all of it as already queued, and never reach the 201st
    # overdue finding. A backlog larger than one page would stall permanently.
    #
    # Keyed on (finding, deadline) rather than (channel, finding, deadline), so a
    # finding already escalated somewhere is done. A channel added later therefore
    # does not hear about findings that went overdue before it existed — the same
    # rule `enqueue_for_scan` already follows, where a new channel hears about the
    # next scan rather than every finding in the table.
    escalated = (
        select(NotificationDelivery.id)
        .where(col(NotificationDelivery.kind) == NotificationEventKind.FINDING_OVERDUE)
        .where(col(NotificationDelivery.finding_id) == col(Finding.id))
        .where(col(NotificationDelivery.due_at) == col(Finding.due_at))
    )
    # Bounded, because a deployment that turns escalation on after months of
    # backlog should not try to mail its whole history in one beat; with the
    # exclusion above, each beat now takes the *next* page rather than the same one.
    # Owner groups are teams, so there are tens of them, not millions: loading
    # them once answers "does this finding have a target?" for the query below and
    # saves a `db.get` per finding in the loop after it.
    groups = list(db.exec(select(OwnerGroup)))
    overdue = list(
        db.exec(
            select(Finding)
            .where(*ownership.actionable())
            .where(col(Finding.due_at).is_not(None), col(Finding.due_at) < at)
            .where(~escalated.exists())
            # …and has somewhere to go. A finding with no target writes no row, so
            # the exclusion above never stops selecting it: ordered by deadline,
            # the oldest of them hold the front of the page and everything behind
            # them starves. Excluded here rather than skipped in Python for the
            # same reason the exclusion above is in SQL — it has to happen before
            # the limit (#190).
            .where(_has_escalation_target(channels, groups))
            .order_by(col(Finding.due_at))
            .limit(limit)
        )
    )
    if not overdue:
        return 0

    by_id = {channel.id: channel for channel in channels}
    by_group_id = {group.id: group for group in groups}
    queued = 0
    for finding in overdue:
        group = (
            by_group_id.get(finding.owner_group_id) if finding.owner_group_id is not None else None
        )
        targets = _escalation_targets(finding, group, channels, by_id)
        for channel in targets:
            # No per-row dedup check here: the query above already excluded every
            # finding that has an escalation for this deadline, and the partial
            # unique index is the structural guard behind both.
            db.add(
                NotificationDelivery(
                    channel_id=channel.id,
                    finding_id=finding.id,
                    kind=NotificationEventKind.FINDING_OVERDUE,
                    # No scan caused this, and the deadline is the identity.
                    scan_id=None,
                    due_at=finding.due_at,
                    status=NotificationDeliveryStatus.PENDING,
                    next_attempt_at=at,
                )
            )
            queued += 1

    if queued:
        logger.info("escalations_enqueued", overdue=len(overdue), queued=queued)
    return queued


def _escalation_targets(
    finding: Finding,
    group: OwnerGroup | None,
    channels: list[NotificationChannel],
    by_id: dict[uuid.UUID, NotificationChannel],
) -> list[NotificationChannel]:
    """Where one overdue finding's escalation goes.

    An owned finding escalates to its team's channel and nowhere else — telling
    six other channels about work that has an owner is how alerting becomes
    noise. A disabled channel is not a target even if the group still names one,
    because disabling a channel is an operator saying stop.
    """
    if group is not None and not group.disabled:
        channel = (
            by_id.get(group.notification_channel_id) if group.notification_channel_id else None
        )
        return [channel] if channel is not None else []
    return [channel for channel in channels if channel_wants(channel, finding)]


def deliver_pending(
    db: Session,
    settings: ApiSettings,
    store: SecretStore,
    *,
    now: datetime | None = None,
    transports: dict[NotificationChannelType, Transport] | None = None,
) -> DeliveryOutcome:
    """Attempt every due delivery, up to the configured batch size."""
    at = now or datetime.now(UTC)
    resolved = transports if transports is not None else build_transports(settings, store)

    due = list(
        db.exec(
            select(NotificationDelivery)
            .where(
                col(NotificationDelivery.status) == NotificationDeliveryStatus.PENDING,
                col(NotificationDelivery.next_attempt_at) <= at,
            )
            .order_by(col(NotificationDelivery.next_attempt_at))
            .limit(settings.notification_batch_size)
        )
    )
    if not due:
        return DeliveryOutcome()

    delivered = retrying = failed = 0
    for delivery in due:
        result = _attempt(db, delivery, settings, resolved, at=at)
        # Per delivery, not per batch. The outbox is at-least-once by design, but a
        # crash after N sends and before a batch-wide commit would leave all N
        # pending with a past due time and re-send every one of them on the next
        # beat. Rounds are already serialised by the maintenance advisory lock, so
        # committing here costs nothing but the extra transactions.
        db.commit()
        match result:
            case NotificationDeliveryStatus.DELIVERED:
                delivered += 1
            case NotificationDeliveryStatus.FAILED:
                failed += 1
            case _:
                retrying += 1

    logger.info(
        "notifications_delivered",
        attempted=len(due),
        delivered=delivered,
        retrying=retrying,
        failed=failed,
    )
    return DeliveryOutcome(delivered=delivered, retrying=retrying, failed=failed)


def _attempt(
    db: Session,
    delivery: NotificationDelivery,
    settings: ApiSettings,
    transports: dict[NotificationChannelType, Transport],
    *,
    at: datetime,
) -> NotificationDeliveryStatus:
    """One attempt. Always leaves the row in a defensible state."""
    delivery.attempts += 1

    channel = db.get(NotificationChannel, delivery.channel_id)
    finding = db.get(Finding, delivery.finding_id)
    # Null by design on an escalation: a deadline passing is not a scan.
    scan = db.get(Scan, delivery.scan_id) if delivery.scan_id is not None else None
    source = db.get(Source, finding.source_id) if finding is not None else None
    escalation = delivery.kind is NotificationEventKind.FINDING_OVERDUE

    if channel is None or finding is None or source is None or (scan is None and not escalation):
        # Deleted between enqueue and delivery. Nothing to announce and nothing to
        # retry, so this is a terminal state rather than an error worth alarming on.
        return _fail(db, delivery, "referenced row no longer exists", at=at)
    if not channel.enabled:
        # Disabling a channel is an operator saying stop, including for what is
        # already queued.
        return _fail(db, delivery, "channel disabled before delivery", at=at)

    transport = transports.get(channel.type)
    if transport is None:  # pragma: no cover — every enum member has a transport
        return _fail(db, delivery, f"no transport for channel type {channel.type}", at=at)

    # Building the payload is inside the guard, not before it: a row whose finding
    # carries something the formatter chokes on would otherwise abort the round
    # before its commit, undoing the marks and counters of every delivery already
    # sent — and re-sending all of them, every beat, until an operator noticed.
    # A poisoned row now fails itself.
    try:
        if escalation:
            payload = finding_overdue(
                finding,
                source=source,
                channel=channel,
                owner_group=(
                    db.get(OwnerGroup, finding.owner_group_id)
                    if finding.owner_group_id is not None
                    else None
                ),
                # The deadline this row was queued for, not wherever the finding's
                # clock has since moved to.
                due_at=delivery.due_at,
                at=at,
            )
            subject = escalation_subject(finding, source)
        else:
            # `scan` is non-None here: the guard above is terminal for a
            # non-escalation without one.
            assert scan is not None  # noqa: S101  # narrowing, not validation
            payload = finding_opened(finding, source=source, scan=scan, channel=channel)
            subject = email_subject(finding, source)
        transport.send(channel, payload, subject=subject)
    except DeliveryError as exc:
        return _retry_or_fail(db, delivery, exc, settings, at=at)
    except Exception as exc:  # a formatter or transport bug must not strand the row
        logger.exception("notification_attempt_crashed", delivery_id=str(delivery.id))
        crash = DeliveryError(f"delivery error: {exc.__class__.__name__}")
        return _retry_or_fail(db, delivery, crash, settings, at=at)

    delivery.status = NotificationDeliveryStatus.DELIVERED
    delivery.delivered_at = at
    delivery.last_error = None
    db.add(delivery)
    logger.info(
        "notification_sent",
        delivery_id=str(delivery.id),
        channel=channel.name,
        channel_type=channel.type.value,
        finding_id=str(finding.id),
        attempts=delivery.attempts,
    )
    return NotificationDeliveryStatus.DELIVERED


def _retry_or_fail(
    db: Session,
    delivery: NotificationDelivery,
    error: DeliveryError,
    settings: ApiSettings,
    *,
    at: datetime,
) -> NotificationDeliveryStatus:
    exhausted = delivery.attempts >= settings.notification_max_attempts
    if error.permanent or exhausted:
        return _fail(db, delivery, str(error), at=at, exhausted=exhausted)

    # Exponential: 60s, 120s, 240s… from the first failure, so a receiver that is
    # restarting is not hammered and one that is down for ten minutes is still
    # caught by the ceiling.
    delay = settings.notification_retry_backoff_seconds * (2 ** (delivery.attempts - 1))
    delivery.next_attempt_at = at + timedelta(seconds=delay)
    delivery.last_error = str(error)
    db.add(delivery)
    logger.warning(
        "notification_retry_scheduled",
        delivery_id=str(delivery.id),
        attempts=delivery.attempts,
        retry_in_seconds=delay,
        error=str(error),
    )
    return NotificationDeliveryStatus.PENDING


def _fail(
    db: Session,
    delivery: NotificationDelivery,
    reason: str,
    *,
    at: datetime,
    exhausted: bool = False,
) -> NotificationDeliveryStatus:
    delivery.status = NotificationDeliveryStatus.FAILED
    delivery.last_error = reason
    delivery.next_attempt_at = at
    db.add(delivery)
    logger.error(
        "notification_failed",
        delivery_id=str(delivery.id),
        attempts=delivery.attempts,
        exhausted=exhausted,
        reason=reason,
    )
    return NotificationDeliveryStatus.FAILED


def pending_count(db: Session, *, channel_id: uuid.UUID | None = None) -> int:
    """How much is queued. Used by the tests and worth having for an operator."""
    statement = (
        select(func.count())
        .select_from(NotificationDelivery)
        .where(col(NotificationDelivery.status) == NotificationDeliveryStatus.PENDING)
    )
    if channel_id is not None:
        statement = statement.where(col(NotificationDelivery.channel_id) == channel_id)
    return db.exec(statement).one()


__all__ = [
    "DeliveryOutcome",
    "channel_wants",
    "deliver_pending",
    "enqueue_for_scan",
    "newly_opened_findings",
    "pending_count",
]
