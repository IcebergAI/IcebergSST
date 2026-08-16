"""Handing findings to an external workflow: the mechanism (#141).

Organised around the requirement the whole design exists to satisfy: **repeated
delivery creates one external work item.** Two separate mechanisms have to hold
for that — a constraint that stops a second row, and an idempotency key that
stops a second ticket when a request arrived and its reply did not — and each is
tested for on its own, because either alone leaves a duplicate path open.

The rest is what happens when delivery goes wrong. The API surface that drives
all of this, and its own tests, are in `test_handoff_api.py`.
"""

import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from iceberg_api.handoff import service
from iceberg_api.handoff.payload import EVENT_HANDOFF_REQUESTED, PAYLOAD_VERSION
from iceberg_api.notifications.transports import DeliveryError
from iceberg_core.config import ApiSettings
from iceberg_core.enums import (
    HandoffStatus,
    RemediationActionKind,
    Severity,
    UserRole,
)
from iceberg_core.models import (
    AuditEvent,
    Finding,
    FindingHandoff,
    HandoffTarget,
    OwnerGroup,
    RemediationAction,
    Source,
    User,
)
from pydantic import SecretStr
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, col, select

NOW = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)
PLAINTEXT_SECRET = "AKIAIOSFODNN7EXAMPLE"


@pytest.fixture(name="admin_headers")
def admin_headers_fixture(
    make_user: Callable[..., User], login_as: Callable[[User], dict[str, str]]
) -> dict[str, str]:
    return login_as(make_user(UserRole.ADMIN))


@pytest.fixture(name="dispatch_settings")
def dispatch_settings_fixture() -> ApiSettings:
    return ApiSettings(
        database_url="postgresql+psycopg://unused/unused",
        master_key=SecretStr("unused"),
        notification_max_attempts=3,
        notification_retry_backoff_seconds=60,
    )


class RecordingSender:
    """Stands in for the webhook. Records, or fails in a chosen way."""

    def __init__(self, error: DeliveryError | None = None, reply: dict[str, str] | None = None):
        self.error = error
        self.reply = reply if reply is not None else {}
        self.sent: list[tuple[HandoffTarget, dict[str, Any]]] = []

    def send(self, target: HandoffTarget, payload: dict[str, Any]) -> dict[str, str]:
        if self.error is not None:
            raise self.error
        self.sent.append((target, payload))
        return self.reply


def _target(session: Session, **fields: Any) -> HandoffTarget:
    defaults: dict[str, Any] = {
        "name": f"soar-{uuid.uuid4().hex[:6]}",
        "config": {"url": "https://soar.example.test/hooks/iceberg"},
        "event_filter": {},
        "enabled": True,
    }
    target = HandoffTarget(**(defaults | fields))
    session.add(target)
    session.commit()
    return target


def _deliver(
    session: Session,
    settings: ApiSettings,
    store: Any,
    sender: RecordingSender,
) -> service.DeliveryOutcome:
    return service.deliver_pending(session, settings, store, sender=sender, now=NOW)


def _actions(session: Session, target_type: str) -> list[str]:
    return [
        event.action
        for event in session.exec(
            select(AuditEvent).where(col(AuditEvent.target_type) == target_type)
        )
    ]


# ─── One finding, one work item ───────────────────────────────────────────────


def test_asking_twice_produces_one_handoff(
    session: Session,
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
) -> None:
    """A second click, a retried request, and two analysts reaching the same
    conclusion are the same event."""
    target = _target(session)
    finding = make_finding(make_source())

    first = service.request(session, finding, target, actor_id=None, now=NOW)
    session.commit()
    second = service.request(session, finding, target, actor_id=None, now=NOW)
    session.commit()

    assert first.id == second.id
    assert len(session.exec(select(FindingHandoff)).all()) == 1


def test_a_second_handoff_row_is_refused_by_the_database(
    session: Session,
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
) -> None:
    """The constraint itself, exercised rather than assumed. The check in
    `request` avoids the error in the ordinary path; this is what holds when two
    requests race."""
    target = _target(session)
    finding = make_finding(make_source())
    service.request(session, finding, target, actor_id=None, now=NOW)
    session.commit()

    session.add(
        FindingHandoff(
            target_id=target.id,
            finding_id=finding.id,
            idempotency_key="something-else-entirely",
            next_attempt_at=NOW,
        )
    )
    with pytest.raises(IntegrityError):
        session.commit()
    session.rollback()


def test_every_attempt_carries_the_same_idempotency_key(
    session: Session,
    dispatch_settings: ApiSettings,
    secret_store: Any,
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
) -> None:
    """Our constraint stops a second row. This is the half it cannot cover: a
    request that arrived whose reply was lost, retried — the receiver has to be
    able to recognise it as the same hand-over."""
    target = _target(session)
    finding = make_finding(make_source())
    handoff = service.request(session, finding, target, actor_id=None, now=NOW)
    session.commit()
    key = handoff.idempotency_key

    # Fail once, then succeed: two attempts, one key.
    _deliver(session, dispatch_settings, secret_store, RecordingSender(DeliveryError("down")))
    session.refresh(handoff)
    handoff.next_attempt_at = NOW
    session.add(handoff)
    session.commit()
    sender = RecordingSender()
    _deliver(session, dispatch_settings, secret_store, sender)

    session.refresh(handoff)
    assert handoff.attempts == 2
    assert handoff.idempotency_key == key
    assert sender.sent[0][1]["idempotency_key"] == key


def test_a_replay_keeps_the_key_and_resets_the_attempts(
    session: Session,
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
) -> None:
    """Replaying is a new decision, usually after fixing what the receiver was
    unhappy about — so it gets fresh attempts. It is *not* a new hand-over, so it
    keeps the key."""
    target = _target(session)
    handoff = service.request(session, make_finding(make_source()), target, actor_id=None, now=NOW)
    handoff.status = HandoffStatus.FAILED
    handoff.attempts = 3
    session.commit()
    key = handoff.idempotency_key

    service.replay(handoff, now=NOW)
    session.commit()

    assert (handoff.status, handoff.attempts, handoff.idempotency_key) == (
        HandoffStatus.PENDING,
        0,
        key,
    )


# ─── What crosses the boundary ────────────────────────────────────────────────


def test_the_payload_carries_the_context_a_ticket_needs(
    session: Session,
    dispatch_settings: ApiSettings,
    secret_store: Any,
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
) -> None:
    """Who owns it, when it is due, and what has already been tried — the person
    picking up the ticket is not looking at this console (#146, ADR 0012)."""
    target = _target(session)
    group = OwnerGroup(name="payments")
    session.add(group)
    session.commit()
    finding = make_finding(
        make_source(),
        owner_group_id=group.id,
        due_at=NOW + timedelta(days=1),
        severity=Severity.CRITICAL,
    )
    session.add(
        RemediationAction(
            finding_id=finding.id,
            kind=RemediationActionKind.ROTATE,
            evidence_links=[{"url": "https://vault.example.test/secret/42", "label": "vault"}],
        )
    )
    service.request(session, finding, target, actor_id=None, now=NOW)
    session.commit()
    sender = RecordingSender()

    _deliver(session, dispatch_settings, secret_store, sender)

    _target_sent, payload = sender.sent[0]
    assert payload["event"] == EVENT_HANDOFF_REQUESTED
    assert payload["version"] == PAYLOAD_VERSION
    assert payload["ownership"]["owner_group"]["name"] == "payments"
    assert payload["ownership"]["due_at"] is not None
    assert payload["remediation"][0]["kind"] == "rotate"


def test_the_payload_carries_evidence_labels_but_never_their_urls(
    session: Session,
    dispatch_settings: ApiSettings,
    secret_store: Any,
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
) -> None:
    """An evidence link's URL is analyst-only (ADR 0012), and a work item is read
    by people who are not — including, often, people outside the security team."""
    target = _target(session)
    finding = make_finding(make_source())
    session.add(
        RemediationAction(
            finding_id=finding.id,
            kind=RemediationActionKind.ROTATE,
            evidence_links=[{"url": "https://vault.example.test/secret/42", "label": "vault"}],
        )
    )
    service.request(session, finding, target, actor_id=None, now=NOW)
    session.commit()
    sender = RecordingSender()

    _deliver(session, dispatch_settings, secret_store, sender)

    _target_sent, payload = sender.sent[0]
    assert payload["remediation"][0]["evidence"] == ["vault"]
    assert "vault.example.test" not in str(payload)


def test_the_payload_never_carries_the_secret_or_analyst_notes(
    session: Session,
    dispatch_settings: ApiSettings,
    secret_store: Any,
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
) -> None:
    """The assertion that would matter most if it ever failed (ADR 0004), plus
    the one about triage state written in the expectation of being internal."""
    target = _target(session)
    finding = make_finding(
        make_source(),
        redacted_snippet="AKIA****************",
        notes="rotated by hand, ask Dana before closing",
    )
    service.request(session, finding, target, actor_id=None, now=NOW)
    session.commit()
    sender = RecordingSender()

    _deliver(session, dispatch_settings, secret_store, sender)

    _target_sent, payload = sender.sent[0]
    assert PLAINTEXT_SECRET not in str(payload)
    assert "Dana" not in str(payload)
    assert "secret_hash" not in payload["finding"]


# ─── When it goes wrong ───────────────────────────────────────────────────────


def test_a_transient_failure_is_retried_with_backoff(
    session: Session,
    dispatch_settings: ApiSettings,
    secret_store: Any,
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
) -> None:
    target = _target(session)
    handoff = service.request(session, make_finding(make_source()), target, actor_id=None, now=NOW)
    session.commit()

    outcome = _deliver(
        session, dispatch_settings, secret_store, RecordingSender(DeliveryError("receiver down"))
    )

    assert outcome.retrying == 1
    session.refresh(handoff)
    assert handoff.status is HandoffStatus.PENDING
    # SQLite hands the timestamp back naive; the stored value is UTC either way.
    assert handoff.next_attempt_at.replace(tzinfo=UTC) > NOW
    assert handoff.last_error is not None


def test_a_permanent_failure_gives_up_at_once_and_says_why(
    session: Session,
    dispatch_settings: ApiSettings,
    secret_store: Any,
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
) -> None:
    """Terminal means give up, not lost: the row stays with the reason, so "what
    did we never manage to hand over?" is a query rather than a log search."""
    target = _target(session)
    handoff = service.request(session, make_finding(make_source()), target, actor_id=None, now=NOW)
    session.commit()

    outcome = _deliver(
        session,
        dispatch_settings,
        secret_store,
        RecordingSender(DeliveryError("bad request", permanent=True)),
    )

    assert outcome.failed == 1
    session.refresh(handoff)
    assert handoff.status is HandoffStatus.FAILED
    assert "bad request" in (handoff.last_error or "")


def test_a_target_disabled_after_the_request_stops_the_delivery(
    session: Session,
    dispatch_settings: ApiSettings,
    secret_store: Any,
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
) -> None:
    """Disabling a target is an operator saying stop, including for what is
    already queued."""
    target = _target(session)
    handoff = service.request(session, make_finding(make_source()), target, actor_id=None, now=NOW)
    session.commit()
    target.enabled = False
    session.add(target)
    session.commit()
    sender = RecordingSender()

    _deliver(session, dispatch_settings, secret_store, sender)

    assert sender.sent == []
    session.refresh(handoff)
    assert handoff.status is HandoffStatus.FAILED


def test_the_receivers_work_item_is_recorded(
    session: Session,
    dispatch_settings: ApiSettings,
    secret_store: Any,
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
) -> None:
    """The whole difference between announcing something and handing it over: the
    reply names an object an analyst can go and look at."""
    target = _target(session)
    handoff = service.request(session, make_finding(make_source()), target, actor_id=None, now=NOW)
    session.commit()

    _deliver(
        session,
        dispatch_settings,
        secret_store,
        RecordingSender(reply={"external_id": "SEC-1234", "external_url": "https://soar/SEC-1234"}),
    )

    session.refresh(handoff)
    assert handoff.status is HandoffStatus.DELIVERED
    assert (handoff.external_id, handoff.external_url) == ("SEC-1234", "https://soar/SEC-1234")


def test_a_redirect_is_not_a_delivery(
    session: Session,
    dispatch_settings: ApiSettings,
    secret_store: Any,
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
) -> None:
    """Redirects are deliberately not followed, so a 3xx means the request never
    reached whatever would have created the work item. Recording it as delivered
    — which "anything below 400" quietly did — would mean a DELIVERED row for a
    ticket that does not exist, and that is the one thing the status must never
    mean.

    Exercised through the real `WebhookSender` against a stub transport, because
    the bug lived in its status handling rather than anywhere a fake sender
    reaches.
    """
    import httpx2
    from iceberg_api.handoff.transport import WebhookSender

    target = _target(session)
    handoff = service.request(session, make_finding(make_source()), target, actor_id=None, now=NOW)
    session.commit()

    def redirect(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(308, headers={"Location": "https://elsewhere.example.test/hooks"})

    sender = WebhookSender(
        dispatch_settings, secret_store, transport=httpx2.MockTransport(redirect)
    )
    outcome = service.deliver_pending(
        session, dispatch_settings, secret_store, sender=sender, now=NOW
    )

    assert outcome.delivered == 0
    session.refresh(handoff)
    assert handoff.status is HandoffStatus.FAILED
    assert "redirected" in (handoff.last_error or "")


def test_a_2xx_through_the_real_sender_is_a_delivery(
    session: Session,
    dispatch_settings: ApiSettings,
    secret_store: Any,
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
) -> None:
    """The other side of the test above: the status split must not have made
    every reply a failure."""
    import httpx2
    from iceberg_api.handoff.transport import WebhookSender

    target = _target(session)
    handoff = service.request(session, make_finding(make_source()), target, actor_id=None, now=NOW)
    session.commit()

    def created(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(201, json={"external_id": "SEC-1"})

    sender = WebhookSender(dispatch_settings, secret_store, transport=httpx2.MockTransport(created))
    service.deliver_pending(session, dispatch_settings, secret_store, sender=sender, now=NOW)

    session.refresh(handoff)
    assert handoff.status is HandoffStatus.DELIVERED
    assert handoff.external_id == "SEC-1"


def test_a_reply_that_says_nothing_is_still_a_successful_handoff(
    session: Session,
    dispatch_settings: ApiSettings,
    secret_store: Any,
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
) -> None:
    """The 2xx said the work item was created. Failing over a missing field would
    retry a create that already succeeded — which is the duplicate this whole
    design exists to prevent."""
    target = _target(session)
    handoff = service.request(session, make_finding(make_source()), target, actor_id=None, now=NOW)
    session.commit()

    _deliver(session, dispatch_settings, secret_store, RecordingSender(reply={}))

    session.refresh(handoff)
    assert handoff.status is HandoffStatus.DELIVERED
    assert handoff.external_id is None
