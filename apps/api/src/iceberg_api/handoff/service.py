"""Requesting a hand-over, and delivering it (#141).

Two halves in different transactions, the same shape as notification dispatch and
for the same reason.

:func:`request` runs inside the analyst's request. It writes one
``FindingHandoff`` row and sends nothing — a transactional outbox, so "the
operator asked for this" commits before anything leaves the deployment and no
receiver timeout can turn a click into a 504 with an unknown outcome.

:func:`deliver_pending` runs in the maintenance loop, under the same advisory
lock as everything else there. It attempts due rows, records what the receiver
called the work item, or schedules a retry with exponential backoff until the
ceiling — at which point the row goes ``failed`` and stays, holding the error
that ended it. An operator can then replay it.

**The idempotency key is never regenerated.** Ours stops a second row; the key
stops a second *ticket* when a request arrived and its reply did not. A retry
that minted a fresh key would defeat the half our own constraint cannot cover.
"""

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

import structlog
from iceberg_core.config import ApiSettings
from iceberg_core.enums import HandoffStatus
from iceberg_core.models import (
    AUDIT_HANDOFF_REQUESTED,
    AUDIT_TARGET_HANDOFF,
    Finding,
    FindingHandoff,
    HandoffTarget,
    OwnerGroup,
    Source,
)
from iceberg_core.secrets import SecretStore
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, col, select

from iceberg_api import audit
from iceberg_api.handoff.payload import handoff_requested
from iceberg_api.notifications.dispatch import channel_wants
from iceberg_api.notifications.transports import DeliveryError
from iceberg_api.remediation import service as remediation

logger = structlog.get_logger()


class HandoffRefused(ValueError):
    """The hand-over cannot be made, and retrying will not change that."""


@dataclass(frozen=True, slots=True)
class DeliveryOutcome:
    """What one delivery round did."""

    delivered: int = 0
    retrying: int = 0
    failed: int = 0


class Sender(Protocol):
    """What :func:`deliver_pending` needs from a transport.

    Narrower than the notification transport's, because a handoff has a reply
    worth keeping: the receiver's own id for the work item, and a link to it.
    Returning a mapping rather than nothing is the whole difference between
    announcing something and handing it over.
    """

    def send(
        self, target: HandoffTarget, payload: dict[str, Any]
    ) -> dict[str, str]: ...  # pragma: no cover - protocol


def request(
    db: Session,
    finding: Finding,
    target: HandoffTarget,
    *,
    actor_id: uuid.UUID | None,
    now: datetime | None = None,
) -> FindingHandoff:
    """Record the intent to hand one finding to one target. Does not commit.

    Returns the **existing** handoff if there is one, rather than raising: a
    second click, a retried request, and two analysts reaching the same
    conclusion are all the same event, and the honest answer to "hand this over"
    when it has already been handed over is the handoff itself.
    """
    if not target.enabled:
        raise HandoffRefused("that target is disabled")
    if not channel_wants(target, finding):
        # The target's own filter, the same one a notification channel applies.
        # Refused rather than silently dropped: an operator who pressed the
        # button is owed an answer about why nothing happened.
        raise HandoffRefused("that target does not accept findings of this severity or source")

    existing = _existing(db, target, finding)
    if existing is not None:
        return existing

    at = now or datetime.now(UTC)
    handoff = FindingHandoff(
        target_id=target.id,
        finding_id=finding.id,
        requested_by_id=actor_id,
        # Derived from the pair it is unique on, so it is reproducible from the
        # row and obviously stable across retries — a random value would work
        # equally well until somebody "helpfully" regenerated it.
        idempotency_key=f"iceberg-handoff-{target.id}-{finding.id}",
        status=HandoffStatus.PENDING,
        next_attempt_at=at,
    )
    db.add(handoff)
    logger.info(
        "handoff_requested",
        finding_id=str(finding.id),
        target=target.name,
        actor_id=str(actor_id) if actor_id else None,
    )
    return handoff


def _existing(db: Session, target: HandoffTarget, finding: Finding) -> FindingHandoff | None:
    """The hand-over of this finding to this target, if there already is one."""
    return db.exec(
        select(FindingHandoff)
        .where(col(FindingHandoff.target_id) == target.id)
        .where(col(FindingHandoff.finding_id) == finding.id)
    ).first()


def request_committed(
    db: Session,
    finding: Finding,
    target: HandoffTarget,
    *,
    actor_id: uuid.UUID | None,
    now: datetime | None = None,
) -> tuple[FindingHandoff, bool]:
    """:func:`request`, committed, and safe against the request it races with.

    Returns the hand-over and whether *this* call is the one that created it, so
    a route can answer 201 or 200 truthfully.

    :func:`request` looks for an existing row before inserting, which handles the
    ordinary second click. It cannot handle two requests in flight at once: both
    transactions can observe no row, both can insert, and the unique constraint
    then refuses the loser — correctly, but as an ``IntegrityError`` that would
    surface as a 500 (#181). The constraint doing its job is not an error the
    caller should ever see, and the honest answer to the loser is the one the
    second click already gets: the hand-over that exists.

    Only that specific conflict is swallowed. If the row is still missing after
    the rollback, something else failed and it is re-raised — a handler that
    turned every ``IntegrityError`` into a success would be a much worse bug than
    the one it was written to fix.
    """
    finding_id, target_name = finding.id, target.name
    handoff = request(db, finding, target, actor_id=actor_id, now=now)
    if handoff not in db.new:
        # `request` handed back a row that was already there.
        return handoff, False

    audit.record(
        db,
        actor_id=actor_id,
        action=AUDIT_HANDOFF_REQUESTED,
        target_type=AUDIT_TARGET_HANDOFF,
        target_id=handoff.id,
        to_value=target_name,
        # Where it went and which finding, never the finding's content: this trail
        # answers "who sent that secret's details to that system".
        detail={"finding_id": str(finding_id), "target_id": str(target.id)},
    )
    try:
        # The row and its audit event commit together: "the operator asked for
        # this" is either recorded with its reason or not recorded at all.
        db.commit()
    except IntegrityError:
        db.rollback()
        duplicate = _existing(db, target, finding)
        if duplicate is None:
            raise
        logger.info(
            "handoff_request_raced",
            finding_id=str(finding_id),
            target=target_name,
            handoff_id=str(duplicate.id),
        )
        return duplicate, False

    db.refresh(handoff)
    return handoff, True


def replay(handoff: FindingHandoff, *, now: datetime | None = None) -> None:
    """Put a failed hand-over back in the queue. Does not commit.

    The attempt counter is reset because an operator replaying a row is making a
    new decision — usually after fixing whatever the receiver was unhappy about —
    and carrying the old count forward would give that decision one attempt
    before it gave up again. The key is deliberately *not* reset: this is still
    the same hand-over of the same finding, and the receiver should still
    recognise it as one.
    """
    handoff.status = HandoffStatus.PENDING
    handoff.attempts = 0
    handoff.next_attempt_at = now or datetime.now(UTC)
    handoff.last_error = None


def deliver_pending(
    db: Session,
    settings: ApiSettings,
    store: SecretStore,
    *,
    sender: Sender | None = None,
    now: datetime | None = None,
) -> DeliveryOutcome:
    """Attempt every due hand-over, up to the configured batch size."""
    at = now or datetime.now(UTC)
    transport = sender if sender is not None else _default_sender(settings, store)

    due = list(
        db.exec(
            select(FindingHandoff)
            .where(
                col(FindingHandoff.status) == HandoffStatus.PENDING,
                col(FindingHandoff.next_attempt_at) <= at,
            )
            .order_by(col(FindingHandoff.next_attempt_at))
            .limit(settings.notification_batch_size)
        )
    )
    if not due:
        return DeliveryOutcome()

    delivered = retrying = failed = 0
    for handoff in due:
        result = _attempt(db, handoff, settings, transport, at=at)
        # Per row, not per batch: the outbox is at-least-once, and a crash after
        # N sends and before a batch-wide commit would re-send every one of them.
        db.commit()
        match result:
            case HandoffStatus.DELIVERED:
                delivered += 1
            case HandoffStatus.FAILED:
                failed += 1
            case _:
                retrying += 1

    logger.info(
        "handoffs_delivered",
        attempted=len(due),
        delivered=delivered,
        retrying=retrying,
        failed=failed,
    )
    return DeliveryOutcome(delivered=delivered, retrying=retrying, failed=failed)


def _attempt(
    db: Session,
    handoff: FindingHandoff,
    settings: ApiSettings,
    sender: Sender,
    *,
    at: datetime,
) -> HandoffStatus:
    """One attempt. Always leaves the row in a defensible state."""
    handoff.attempts += 1

    target = db.get(HandoffTarget, handoff.target_id)
    finding = db.get(Finding, handoff.finding_id)
    source = db.get(Source, finding.source_id) if finding is not None else None

    if target is None or finding is None or source is None:
        # Deleted between request and delivery. Nothing to hand over and nothing
        # to retry, so terminal rather than an error worth alarming on.
        return _fail(db, handoff, "referenced row no longer exists", at=at)
    if not target.enabled:
        # Disabling a target is an operator saying stop, including for what is
        # already queued.
        return _fail(db, handoff, "target disabled before delivery", at=at)

    # Inside the guard, and inside the try: a finding carrying something the
    # formatter chokes on would otherwise abort the round before its commit,
    # undoing the marks of every hand-over already sent — and re-sending all of
    # them on the next beat.
    try:
        payload = handoff_requested(
            handoff,
            finding,
            source=source,
            target=target,
            owner_group=(
                db.get(OwnerGroup, finding.owner_group_id)
                if finding.owner_group_id is not None
                else None
            ),
            remediations=remediation.actions_for(db, finding.id),
        )
        reply = sender.send(target, payload)
    except DeliveryError as exc:
        return _retry_or_fail(db, handoff, exc, settings, at=at)
    except Exception as exc:  # a formatter or transport bug must not strand the row
        logger.exception("handoff_attempt_crashed", handoff_id=str(handoff.id))
        return _retry_or_fail(
            db, handoff, DeliveryError(f"handoff error: {exc.__class__.__name__}"), settings, at=at
        )

    # What the receiver called it, if it said. Bounded, and never trusted beyond
    # being a display string: it came from somebody else's system.
    handoff.external_id = _bounded(reply.get("external_id"), 255)
    handoff.external_url = _bounded(reply.get("external_url"), 2048)
    handoff.status = HandoffStatus.DELIVERED
    handoff.delivered_at = at
    handoff.last_error = None
    db.add(handoff)
    logger.info(
        "handoff_delivered",
        handoff_id=str(handoff.id),
        target=target.name,
        external_id=handoff.external_id,
        attempts=handoff.attempts,
    )
    return HandoffStatus.DELIVERED


def _retry_or_fail(
    db: Session,
    handoff: FindingHandoff,
    error: DeliveryError,
    settings: ApiSettings,
    *,
    at: datetime,
) -> HandoffStatus:
    """Back off, or give up — the same ladder notification delivery uses."""
    if error.permanent or handoff.attempts >= settings.notification_max_attempts:
        return _fail(db, handoff, str(error), at=at)

    backoff = settings.notification_retry_backoff_seconds * (2 ** (handoff.attempts - 1))
    handoff.next_attempt_at = at + timedelta(seconds=backoff)
    handoff.last_error = _bounded(str(error), 500)
    db.add(handoff)
    logger.warning(
        "handoff_retrying",
        handoff_id=str(handoff.id),
        attempts=handoff.attempts,
        next_attempt_at=handoff.next_attempt_at.isoformat(),
    )
    return HandoffStatus.PENDING


def _fail(db: Session, handoff: FindingHandoff, reason: str, *, at: datetime) -> HandoffStatus:
    """Terminal, and kept. "What did we never manage to hand over?" is a query."""
    handoff.status = HandoffStatus.FAILED
    handoff.last_error = _bounded(reason, 500)
    handoff.next_attempt_at = at
    db.add(handoff)
    logger.warning("handoff_failed", handoff_id=str(handoff.id), error=handoff.last_error)
    return HandoffStatus.FAILED


def _bounded(value: object, limit: int) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text[:limit] or None


def _default_sender(settings: ApiSettings, store: SecretStore) -> Sender:
    """The webhook sender, built lazily so tests never need one."""
    from iceberg_api.handoff.transport import WebhookSender

    return WebhookSender(settings, store)
