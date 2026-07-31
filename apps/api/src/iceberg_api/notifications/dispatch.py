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

import structlog
from iceberg_core.config import ApiSettings
from iceberg_core.enums import (
    FindingEventKind,
    FindingState,
    NotificationChannelType,
    NotificationDeliveryStatus,
    Severity,
)
from iceberg_core.models import (
    Finding,
    FindingEvent,
    NotificationChannel,
    NotificationDelivery,
    Scan,
    Source,
)
from iceberg_core.secrets import SecretStore
from sqlmodel import Session, col, select

from iceberg_api.notifications.payload import email_subject, finding_opened
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
    # by the event ingest wrote when the secret came back — which names this scan.
    reopened = (
        select(Finding)
        .join(FindingEvent, col(FindingEvent.finding_id) == col(Finding.id))
        .where(
            col(Finding.last_seen_scan_id) == scan.id,
            col(Finding.state) == FindingState.OPEN,
            col(Finding.suppressed_at).is_(None),
            col(FindingEvent.kind) == FindingEventKind.REOPENED,
            col(FindingEvent.comment) == f"seen again by scan {scan.id}",
        )
    )
    findings = {finding.id: finding for finding in db.exec(first_seen)}
    findings.update({finding.id: finding for finding in db.exec(reopened)})
    return list(findings.values())


def channel_wants(channel: NotificationChannel, finding: Finding) -> bool:
    """Whether this channel's event filter selects this finding."""
    event_filter = EventFilter.model_validate(channel.event_filter)
    if event_filter.min_severity is not None and (
        _SEVERITY_RANK[finding.severity] < _SEVERITY_RANK[event_filter.min_severity]
    ):
        return False
    return not (event_filter.source_ids and finding.source_id not in event_filter.source_ids)


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
        match result:
            case NotificationDeliveryStatus.DELIVERED:
                delivered += 1
            case NotificationDeliveryStatus.FAILED:
                failed += 1
            case _:
                retrying += 1
    db.commit()

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
    scan = db.get(Scan, delivery.scan_id)
    source = db.get(Source, finding.source_id) if finding is not None else None

    if channel is None or finding is None or scan is None or source is None:
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

    payload = finding_opened(finding, source=source, scan=scan, channel=channel)
    try:
        transport.send(channel, payload, subject=email_subject(finding, source))
    except DeliveryError as exc:
        return _retry_or_fail(db, delivery, exc, settings, at=at)
    except Exception as exc:  # a transport bug must not strand the row
        logger.exception("notification_transport_crashed", delivery_id=str(delivery.id))
        crash = DeliveryError(f"transport error: {exc.__class__.__name__}")
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
    statement = select(NotificationDelivery).where(
        col(NotificationDelivery.status) == NotificationDeliveryStatus.PENDING
    )
    if channel_id is not None:
        statement = statement.where(col(NotificationDelivery.channel_id) == channel_id)
    return len(list(db.exec(statement)))


__all__ = [
    "DeliveryOutcome",
    "channel_wants",
    "deliver_pending",
    "enqueue_for_scan",
    "newly_opened_findings",
    "pending_count",
]
