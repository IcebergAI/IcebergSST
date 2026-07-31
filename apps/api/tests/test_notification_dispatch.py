"""Notification dispatch (#60).

Three properties matter here, and they are what these tests are organised around.

**Nothing is announced that should not be.** The event filter, disabled channels
and suppressions all have to be honoured before a row is written, because once it
is written something will try very hard to deliver it.

**Nothing is lost, and nothing is sent twice.** The outbox row commits with the
scan; a failure schedules a retry rather than disappearing; giving up is recorded
as ``failed`` with the reason. Re-running enqueue — which the stalled-scan sweep
does routinely — must not announce the same secret again.

**Nothing leaks.** The payload is a fixed field list, and the assertion that the
plaintext secret is absent is the one that would matter most if it ever failed.
"""

import json
import threading
import uuid
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from socketserver import StreamRequestHandler, ThreadingTCPServer
from typing import Any

import httpx2
import pytest
from iceberg_api.notifications import dispatch
from iceberg_api.notifications.payload import PAYLOAD_VERSION, finding_opened
from iceberg_api.notifications.transports import (
    SIGNATURE_HEADER,
    TIMESTAMP_HEADER,
    DeliveryError,
    SmtpTransport,
    WebhookTransport,
    sign,
)
from iceberg_core.config import ApiSettings
from iceberg_core.enums import (
    FindingEventKind,
    FindingState,
    NotificationChannelType,
    NotificationDeliveryStatus,
    ScanStatus,
    ScanTrigger,
    Severity,
    SourceType,
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
from pydantic import SecretStr
from sqlmodel import Session, col, select

PLAINTEXT_SECRET = "AKIAIOSFODNN7EXAMPLE"


def _utc(value: datetime) -> datetime:
    """SQLite hands timestamps back without a zone; Postgres keeps it.

    Same helper as ``test_scheduler.py``. Comparisons in application code happen
    in SQL, where the driver binds consistently — this is only needed to compare a
    value read back in Python.
    """
    return value if value.tzinfo else value.replace(tzinfo=UTC)


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture(name="source")
def source_fixture(session: Session) -> Source:
    source = Source(
        name=f"confluence-{uuid.uuid4().hex[:6]}",
        type=SourceType.CONFLUENCE,
        connection={"base_url": "https://example.atlassian.net/wiki"},
    )
    session.add(source)
    session.commit()
    return source


@pytest.fixture(name="scan")
def scan_fixture(session: Session, source: Source) -> Scan:
    scan = Scan(source_id=source.id, trigger=ScanTrigger.MANUAL, status=ScanStatus.COMPLETED)
    session.add(scan)
    session.commit()
    return scan


@pytest.fixture(name="make_open_finding")
def make_open_finding_fixture(
    session: Session, source: Source, scan: Scan
) -> Callable[..., Finding]:
    """A finding this scan opened — the thing dispatch announces."""

    def factory(**fields: Any) -> Finding:
        defaults: dict[str, Any] = {
            "fingerprint": uuid.uuid4().hex,
            "rule_id": "aws-access-key",
            "rulepack_version": "2026.07.1",
            "resource_locator": {"path": "/space/DOCS/page-1"},
            "redacted_snippet": "AKIA****************",
            "secret_hash": uuid.uuid4().hex,
            "severity": Severity.HIGH,
            "confidence": 0.9,
            "state": FindingState.OPEN,
        }
        finding = Finding(
            source_id=source.id,
            first_seen_scan_id=scan.id,
            last_seen_scan_id=scan.id,
            **(defaults | fields),
        )
        session.add(finding)
        session.commit()
        return finding

    return factory


@pytest.fixture(name="make_channel")
def make_channel_fixture(session: Session) -> Callable[..., NotificationChannel]:
    def factory(**fields: Any) -> NotificationChannel:
        defaults: dict[str, Any] = {
            "name": f"channel-{uuid.uuid4().hex[:6]}",
            "type": NotificationChannelType.WEBHOOK,
            "config": {"url": "https://receiver.example.com/hook"},
            "event_filter": {},
            "enabled": True,
        }
        channel = NotificationChannel(**(defaults | fields))
        session.add(channel)
        session.commit()
        return channel

    return factory


class RecordingTransport:
    """Stands in for SMTP/HTTP. Records what it was asked to send, or fails."""

    def __init__(self, error: DeliveryError | None = None) -> None:
        self.error = error
        self.sent: list[tuple[NotificationChannel, dict[str, Any], str]] = []

    def send(self, channel: NotificationChannel, payload: dict[str, Any], *, subject: str) -> None:
        if self.error is not None:
            raise self.error
        self.sent.append((channel, payload, subject))


@pytest.fixture(name="dispatch_settings")
def dispatch_settings_fixture() -> ApiSettings:
    return ApiSettings(
        database_url="postgresql+psycopg://unused/unused",
        master_key=SecretStr("unused"),
        notification_max_attempts=3,
        notification_retry_backoff_seconds=60,
    )


def _transports(transport: RecordingTransport) -> dict[NotificationChannelType, Any]:
    return dict.fromkeys(NotificationChannelType, transport)


# ── Who gets told ─────────────────────────────────────────────────────────────


def test_a_new_finding_is_queued_for_an_enabled_channel(
    session: Session,
    scan: Scan,
    make_open_finding: Callable[..., Finding],
    make_channel: Callable[..., NotificationChannel],
) -> None:
    channel = make_channel()
    finding = make_open_finding()

    queued = dispatch.enqueue_for_scan(session, scan)
    session.commit()

    assert queued == 1
    delivery = session.exec(select(NotificationDelivery)).one()
    assert delivery.channel_id == channel.id
    assert delivery.finding_id == finding.id
    assert delivery.scan_id == scan.id
    assert delivery.status is NotificationDeliveryStatus.PENDING
    assert delivery.attempts == 0


def test_a_finding_below_the_channel_minimum_severity_is_not_queued(
    session: Session,
    scan: Scan,
    make_open_finding: Callable[..., Finding],
    make_channel: Callable[..., NotificationChannel],
) -> None:
    make_channel(event_filter={"min_severity": Severity.CRITICAL.value})
    make_open_finding(severity=Severity.HIGH)

    assert dispatch.enqueue_for_scan(session, scan) == 0


def test_a_channel_scoped_to_other_sources_is_not_queued(
    session: Session,
    scan: Scan,
    make_open_finding: Callable[..., Finding],
    make_channel: Callable[..., NotificationChannel],
) -> None:
    make_channel(event_filter={"source_ids": [str(uuid.uuid4())]})
    make_open_finding()

    assert dispatch.enqueue_for_scan(session, scan) == 0


def test_a_disabled_channel_is_not_queued(
    session: Session,
    scan: Scan,
    make_open_finding: Callable[..., Finding],
    make_channel: Callable[..., NotificationChannel],
) -> None:
    make_channel(enabled=False)
    make_open_finding()

    assert dispatch.enqueue_for_scan(session, scan) == 0


def test_a_suppressed_finding_is_not_announced(
    session: Session,
    scan: Scan,
    make_open_finding: Callable[..., Finding],
    make_channel: Callable[..., NotificationChannel],
) -> None:
    """A suppression is an analyst saying stop telling me about this (ADR 0008).

    Honouring it in the console and mailing them anyway would be worse than not
    having suppressions at all.
    """
    make_channel()
    make_open_finding(suppressed_at=datetime.now(UTC))

    assert dispatch.enqueue_for_scan(session, scan) == 0


def test_a_finding_this_scan_did_not_open_is_not_announced(
    session: Session,
    source: Source,
    scan: Scan,
    make_open_finding: Callable[..., Finding],
    make_channel: Callable[..., NotificationChannel],
) -> None:
    """Only what this scan opened. An operator told weekly about the same secret
    stops reading the alerts."""
    make_channel()
    earlier = Scan(source_id=source.id, trigger=ScanTrigger.MANUAL, status=ScanStatus.COMPLETED)
    session.add(earlier)
    session.commit()
    finding = make_open_finding()
    finding.first_seen_scan_id = earlier.id
    session.add(finding)
    session.commit()

    assert dispatch.enqueue_for_scan(session, scan) == 0


def test_a_reopened_finding_is_announced_again(
    session: Session,
    source: Source,
    scan: Scan,
    make_open_finding: Callable[..., Finding],
    make_channel: Callable[..., NotificationChannel],
) -> None:
    """A secret that came back is news, even though the finding is not new."""
    make_channel()
    earlier = Scan(source_id=source.id, trigger=ScanTrigger.MANUAL, status=ScanStatus.COMPLETED)
    session.add(earlier)
    session.commit()

    finding = make_open_finding()
    finding.first_seen_scan_id = earlier.id
    session.add(finding)
    session.add(
        FindingEvent(
            finding_id=finding.id,
            kind=FindingEventKind.REOPENED,
            from_value=FindingState.RESOLVED.value,
            to_value=FindingState.OPEN.value,
            comment=f"seen again by scan {scan.id}",
        )
    )
    session.commit()

    assert dispatch.enqueue_for_scan(session, scan) == 1


def test_enqueueing_the_same_scan_twice_announces_once(
    session: Session,
    scan: Scan,
    make_open_finding: Callable[..., Finding],
    make_channel: Callable[..., NotificationChannel],
) -> None:
    """The stalled-scan sweep re-finalizes scans; it must not re-announce them."""
    make_channel()
    make_open_finding()

    dispatch.enqueue_for_scan(session, scan)
    session.commit()
    second = dispatch.enqueue_for_scan(session, scan)
    session.commit()

    assert second == 0
    assert len(list(session.exec(select(NotificationDelivery)))) == 1


# ── Delivery, retry, and giving up ────────────────────────────────────────────


def test_a_due_delivery_is_sent_and_marked_delivered(
    session: Session,
    scan: Scan,
    dispatch_settings: ApiSettings,
    secret_store: SecretStore,
    make_open_finding: Callable[..., Finding],
    make_channel: Callable[..., NotificationChannel],
) -> None:
    make_channel()
    make_open_finding()
    dispatch.enqueue_for_scan(session, scan)
    session.commit()
    transport = RecordingTransport()

    outcome = dispatch.deliver_pending(
        session, dispatch_settings, secret_store, transports=_transports(transport)
    )

    assert outcome.delivered == 1
    assert len(transport.sent) == 1
    delivery = session.exec(select(NotificationDelivery)).one()
    assert delivery.status is NotificationDeliveryStatus.DELIVERED
    assert delivery.delivered_at is not None
    assert delivery.last_error is None


def test_a_delivered_row_is_not_sent_again(
    session: Session,
    scan: Scan,
    dispatch_settings: ApiSettings,
    secret_store: SecretStore,
    make_open_finding: Callable[..., Finding],
    make_channel: Callable[..., NotificationChannel],
) -> None:
    make_channel()
    make_open_finding()
    dispatch.enqueue_for_scan(session, scan)
    session.commit()
    transport = RecordingTransport()
    transports = _transports(transport)

    dispatch.deliver_pending(session, dispatch_settings, secret_store, transports=transports)
    dispatch.deliver_pending(session, dispatch_settings, secret_store, transports=transports)

    assert len(transport.sent) == 1


def test_a_transient_failure_schedules_a_retry_and_keeps_the_row(
    session: Session,
    scan: Scan,
    dispatch_settings: ApiSettings,
    secret_store: SecretStore,
    make_open_finding: Callable[..., Finding],
    make_channel: Callable[..., NotificationChannel],
) -> None:
    make_channel()
    make_open_finding()
    dispatch.enqueue_for_scan(session, scan)
    session.commit()
    at = datetime.now(UTC)
    transport = RecordingTransport(error=DeliveryError("receiver is down"))

    outcome = dispatch.deliver_pending(
        session,
        dispatch_settings,
        secret_store,
        now=at,
        transports=_transports(transport),
    )

    assert outcome.retrying == 1
    delivery = session.exec(select(NotificationDelivery)).one()
    assert delivery.status is NotificationDeliveryStatus.PENDING
    assert delivery.attempts == 1
    assert delivery.last_error == "receiver is down"
    # Backoff pushed it out of the current round, so the next beat does not
    # hammer a receiver that is restarting.
    assert _utc(delivery.next_attempt_at) == at + timedelta(
        seconds=dispatch_settings.notification_retry_backoff_seconds
    )


def test_a_retry_is_not_attempted_before_it_is_due(
    session: Session,
    scan: Scan,
    dispatch_settings: ApiSettings,
    secret_store: SecretStore,
    make_open_finding: Callable[..., Finding],
    make_channel: Callable[..., NotificationChannel],
) -> None:
    make_channel()
    make_open_finding()
    dispatch.enqueue_for_scan(session, scan)
    session.commit()
    at = datetime.now(UTC)
    failing = RecordingTransport(error=DeliveryError("receiver is down"))
    dispatch.deliver_pending(
        session, dispatch_settings, secret_store, now=at, transports=_transports(failing)
    )

    recovered = RecordingTransport()
    dispatch.deliver_pending(
        session,
        dispatch_settings,
        secret_store,
        now=at + timedelta(seconds=1),
        transports=_transports(recovered),
    )

    assert recovered.sent == []


def test_giving_up_is_recorded_rather_than_silent(
    session: Session,
    scan: Scan,
    dispatch_settings: ApiSettings,
    secret_store: SecretStore,
    make_open_finding: Callable[..., Finding],
    make_channel: Callable[..., NotificationChannel],
) -> None:
    """After the attempt ceiling the row goes `failed` — and stays, with the error.

    "Never lost silently" means an operator can ask what was never delivered and
    get an answer, which is a query against these rows.
    """
    make_channel()
    make_open_finding()
    dispatch.enqueue_for_scan(session, scan)
    session.commit()
    transport = RecordingTransport(error=DeliveryError("receiver is down"))

    at = datetime.now(UTC)
    for attempt in range(dispatch_settings.notification_max_attempts):
        dispatch.deliver_pending(
            session,
            dispatch_settings,
            secret_store,
            # Far enough ahead that each round finds the row due again.
            now=at + timedelta(hours=attempt),
            transports=_transports(transport),
        )

    delivery = session.exec(select(NotificationDelivery)).one()
    assert delivery.status is NotificationDeliveryStatus.FAILED
    assert delivery.attempts == dispatch_settings.notification_max_attempts
    assert delivery.last_error == "receiver is down"


def test_a_row_whose_payload_cannot_be_built_fails_alone(
    session: Session,
    scan: Scan,
    dispatch_settings: ApiSettings,
    secret_store: SecretStore,
    make_open_finding: Callable[..., Finding],
    make_channel: Callable[..., NotificationChannel],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One unformattable finding must not wedge the queue behind it.

    Built outside the error guard, a payload that raises aborted the round before
    its commit — undoing the marks and counters of every row already sent, and
    re-sending all of them on the next beat, forever, because nothing about them
    had changed.
    """
    make_channel()
    poisoned = make_open_finding()
    healthy = make_open_finding()
    dispatch.enqueue_for_scan(session, scan)
    session.commit()
    transport = RecordingTransport()

    def refuse_the_poisoned_one(finding: Finding, **kwargs: Any) -> dict[str, Any]:
        if finding.id == poisoned.id:
            raise ValueError("locator is not a mapping")
        return finding_opened(finding, **kwargs)

    monkeypatch.setattr(dispatch, "finding_opened", refuse_the_poisoned_one)

    outcome = dispatch.deliver_pending(
        session, dispatch_settings, secret_store, transports=_transports(transport)
    )

    assert outcome.delivered == 1
    assert [sent[1]["finding"]["id"] for sent in transport.sent] == [str(healthy.id)]
    poisoned_row = session.exec(
        select(NotificationDelivery).where(col(NotificationDelivery.finding_id) == poisoned.id)
    ).one()
    assert poisoned_row.attempts == 1
    assert poisoned_row.last_error == "delivery error: ValueError"


def test_a_crash_mid_round_keeps_what_was_already_sent(
    session: Session,
    scan: Scan,
    dispatch_settings: ApiSettings,
    secret_store: SecretStore,
    make_open_finding: Callable[..., Finding],
    make_channel: Callable[..., NotificationChannel],
) -> None:
    """Committed per delivery, not per batch.

    The outbox is at-least-once by design, but a restart or an OOM between the
    first send and a batch-wide commit would leave every already-sent row pending
    with a past due time — turning one duplicate into a whole batch of them.
    """
    make_channel()
    make_open_finding()
    make_open_finding()
    dispatch.enqueue_for_scan(session, scan)
    session.commit()

    class DiesOnTheSecondSend(RecordingTransport):
        def send(
            self, channel: NotificationChannel, payload: dict[str, Any], *, subject: str
        ) -> None:
            if self.sent:
                # Not an Exception: the point is a process that stops, not an
                # error the dispatcher is meant to handle.
                raise KeyboardInterrupt("the pod went away")
            super().send(channel, payload, subject=subject)

    with pytest.raises(KeyboardInterrupt):
        dispatch.deliver_pending(
            session, dispatch_settings, secret_store, transports=_transports(DiesOnTheSecondSend())
        )
    session.rollback()

    # Which of the two went first is the delivery loop's business; that exactly one
    # survived the rollback is the property under test.
    statuses = [row.status.value for row in session.exec(select(NotificationDelivery)).all()]
    assert sorted(statuses) == ["delivered", "pending"]


def test_a_permanent_failure_is_not_retried(
    session: Session,
    scan: Scan,
    dispatch_settings: ApiSettings,
    secret_store: SecretStore,
    make_open_finding: Callable[..., Finding],
    make_channel: Callable[..., NotificationChannel],
) -> None:
    """A malformed URL fails identically forever; five attempts only delay the news."""
    make_channel()
    make_open_finding()
    dispatch.enqueue_for_scan(session, scan)
    session.commit()
    transport = RecordingTransport(error=DeliveryError("no url", permanent=True))

    outcome = dispatch.deliver_pending(
        session, dispatch_settings, secret_store, transports=_transports(transport)
    )

    assert outcome.failed == 1
    delivery = session.exec(select(NotificationDelivery)).one()
    assert delivery.status is NotificationDeliveryStatus.FAILED
    assert delivery.attempts == 1


def test_a_channel_disabled_after_queueing_is_not_delivered(
    session: Session,
    scan: Scan,
    dispatch_settings: ApiSettings,
    secret_store: SecretStore,
    make_open_finding: Callable[..., Finding],
    make_channel: Callable[..., NotificationChannel],
) -> None:
    channel = make_channel()
    make_open_finding()
    dispatch.enqueue_for_scan(session, scan)
    session.commit()
    channel.enabled = False
    session.add(channel)
    session.commit()
    transport = RecordingTransport()

    dispatch.deliver_pending(
        session, dispatch_settings, secret_store, transports=_transports(transport)
    )

    assert transport.sent == []
    delivery = session.exec(select(NotificationDelivery)).one()
    assert delivery.status is NotificationDeliveryStatus.FAILED


def test_a_transport_that_crashes_does_not_strand_the_row(
    session: Session,
    scan: Scan,
    dispatch_settings: ApiSettings,
    secret_store: SecretStore,
    make_open_finding: Callable[..., Finding],
    make_channel: Callable[..., NotificationChannel],
) -> None:
    """A bug in a transport is a failed attempt, not a lost announcement."""

    class Exploding:
        def send(self, channel: object, payload: object, *, subject: str) -> None:
            raise RuntimeError("boom")

    make_channel()
    make_open_finding()
    dispatch.enqueue_for_scan(session, scan)
    session.commit()

    outcome = dispatch.deliver_pending(
        session,
        dispatch_settings,
        secret_store,
        transports=dict.fromkeys(NotificationChannelType, Exploding()),
    )

    assert outcome.retrying == 1
    delivery = session.exec(select(NotificationDelivery)).one()
    assert delivery.status is NotificationDeliveryStatus.PENDING
    assert delivery.last_error is not None and "RuntimeError" in delivery.last_error


# ── The payload ───────────────────────────────────────────────────────────────


def test_the_payload_carries_no_secret_and_a_documented_shape(
    session: Session,
    source: Source,
    scan: Scan,
    make_open_finding: Callable[..., Finding],
    make_channel: Callable[..., NotificationChannel],
) -> None:
    channel = make_channel()
    finding = make_open_finding(redacted_snippet="AKIA****************")

    payload = finding_opened(finding, source=source, scan=scan, channel=channel)

    assert payload["version"] == PAYLOAD_VERSION
    assert payload["event"] == "finding.opened"
    assert set(payload) == {"version", "event", "channel", "finding", "source", "scan"}
    assert payload["finding"]["severity"] == Severity.HIGH.value
    assert payload["finding"]["redacted_snippet"] == "AKIA****************"
    # The property that matters most: nothing reversible leaves the deployment.
    assert PLAINTEXT_SECRET not in json.dumps(payload)
    # Internal triage state is not somebody else's business.
    assert "notes" not in payload["finding"]
    assert "assignee_id" not in payload["finding"]


def test_the_payload_never_carries_analyst_notes(
    session: Session,
    source: Source,
    scan: Scan,
    make_open_finding: Callable[..., Finding],
    make_channel: Callable[..., NotificationChannel],
) -> None:
    channel = make_channel()
    finding = make_open_finding(notes="contact bob@example.com, rotate in prod")

    payload = finding_opened(finding, source=source, scan=scan, channel=channel)

    assert "bob@example.com" not in json.dumps(payload)


# ── The webhook transport ─────────────────────────────────────────────────────


def _webhook_channel(url: str = "https://receiver.example.com/hook") -> NotificationChannel:
    return NotificationChannel(
        name="hook",
        type=NotificationChannelType.WEBHOOK,
        config={"url": url},
    )


def test_the_webhook_posts_json_and_signs_it(
    dispatch_settings: ApiSettings, secret_store: SecretStore
) -> None:
    seen: dict[str, Any] = {}

    def handler(request: httpx2.Request) -> httpx2.Response:
        seen["headers"] = dict(request.headers)
        seen["body"] = request.read()
        return httpx2.Response(204)

    ref = secret_store.seal("payload-signing-secret")
    channel = _webhook_channel()
    channel.config = {**channel.config, "secret_ref": ref}
    transport = WebhookTransport(
        dispatch_settings, secret_store, transport=httpx2.MockTransport(handler)
    )

    transport.send(channel, {"event": "finding.opened"}, subject="ignored")

    assert seen["headers"]["content-type"] == "application/json"
    signature = seen["headers"][SIGNATURE_HEADER.lower()]
    timestamp = seen["headers"][TIMESTAMP_HEADER.lower()]
    assert signature == sign(seen["body"], "payload-signing-secret", timestamp)


def test_an_unsigned_channel_sends_no_signature_header(
    dispatch_settings: ApiSettings, secret_store: SecretStore
) -> None:
    seen: dict[str, Any] = {}

    def handler(request: httpx2.Request) -> httpx2.Response:
        seen["headers"] = dict(request.headers)
        return httpx2.Response(200)

    transport = WebhookTransport(
        dispatch_settings, secret_store, transport=httpx2.MockTransport(handler)
    )

    transport.send(_webhook_channel(), {"event": "finding.opened"}, subject="ignored")

    assert SIGNATURE_HEADER.lower() not in seen["headers"]


@pytest.mark.parametrize(
    ("status_code", "permanent"),
    [(500, False), (429, False), (503, False), (401, True), (403, True), (400, True)],
)
def test_webhook_status_codes_are_classified(
    dispatch_settings: ApiSettings,
    secret_store: SecretStore,
    status_code: int,
    permanent: bool,
) -> None:
    """A 5xx or a 429 is worth retrying; an auth failure is configuration."""
    transport = WebhookTransport(
        dispatch_settings,
        secret_store,
        transport=httpx2.MockTransport(lambda request: httpx2.Response(status_code)),
    )

    with pytest.raises(DeliveryError) as raised:
        transport.send(_webhook_channel(), {"event": "x"}, subject="ignored")

    assert raised.value.permanent is permanent


def test_the_webhook_does_not_follow_a_redirect(
    dispatch_settings: ApiSettings, secret_store: SecretStore
) -> None:
    """A 302 would be a way to move where findings are sent without touching the
    channel, so the redirect is a failed delivery rather than a followed one."""
    visited: list[str] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        visited.append(str(request.url))
        return httpx2.Response(302, headers={"Location": "https://attacker.example.com/collect"})

    transport = WebhookTransport(
        dispatch_settings, secret_store, transport=httpx2.MockTransport(handler)
    )

    transport.send(_webhook_channel(), {"event": "x"}, subject="ignored")

    assert visited == ["https://receiver.example.com/hook"]


# ── The SMTP transport, against a server that speaks SMTP ─────────────────────


class _CapturingSmtpHandler(StreamRequestHandler):
    """Enough of RFC 5321 to accept one message and hand it back."""

    def handle(self) -> None:
        received: list[str] = []
        self.wfile.write(b"220 fake.test ESMTP\r\n")
        while True:
            line = self.rfile.readline()
            if not line:
                return
            command = line.decode(errors="replace").strip()
            upper = command.upper()
            if upper.startswith(("EHLO", "HELO")):
                # No STARTTLS advertised: the test relay is a localhost stand-in.
                self.wfile.write(b"250-fake.test\r\n250 SIZE 10240000\r\n")
            elif upper.startswith(("MAIL FROM", "RCPT TO")):
                received.append(command)
                self.wfile.write(b"250 OK\r\n")
            elif upper == "DATA":
                self.wfile.write(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                body: list[str] = []
                while True:
                    data_line = self.rfile.readline().decode(errors="replace")
                    if data_line in {".\r\n", ".\n", ""}:
                        break
                    body.append(data_line)
                received.append("".join(body))
                self.wfile.write(b"250 OK\r\n")
            elif upper == "QUIT":
                self.wfile.write(b"221 Bye\r\n")
                break
            else:
                self.wfile.write(b"250 OK\r\n")
        self.server.captured.append(received)  # type: ignore[attr-defined]


class _FakeSmtpServer(ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), _CapturingSmtpHandler)
        self.captured: list[list[str]] = []


@pytest.fixture(name="smtp_server")
def smtp_server_fixture() -> Iterator[_FakeSmtpServer]:
    server = _FakeSmtpServer()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_an_email_is_sent_to_the_channel_recipients(smtp_server: _FakeSmtpServer) -> None:
    """The SMTP path, end to end against a server that actually speaks SMTP."""
    settings = ApiSettings(
        database_url="postgresql+psycopg://unused/unused",
        master_key=SecretStr("unused"),
        smtp_host="127.0.0.1",
        smtp_port=smtp_server.server_address[1],
        # The stand-in relay is on localhost and speaks no TLS — the one case the
        # setting exists for.
        smtp_starttls=False,
        smtp_from="iceberg@example.com",
        smtp_timeout_seconds=5.0,
    )
    channel = NotificationChannel(
        name="secops",
        type=NotificationChannelType.EMAIL,
        config={"recipients": ["secops@example.com", "oncall@example.com"]},
    )
    payload = {
        "finding": {
            "severity": "high",
            "rule_id": "aws-access-key",
            "rulepack_version": "2026.07.1",
            "confidence": 0.9,
            "fingerprint": "abc123",
            "resource_locator": {"path": "/space/DOCS/page-1"},
            "redacted_snippet": "AKIA****************",
            "url": None,
        },
        "source": {"name": "confluence-prod", "type": "confluence"},
    }

    SmtpTransport(settings).send(channel, payload, subject="[IcebergSST] HIGH secret")

    conversation = smtp_server.captured[0]
    assert any("secops@example.com" in line for line in conversation)
    assert any("oncall@example.com" in line for line in conversation)
    message = conversation[-1]
    assert "[IcebergSST] HIGH secret" in message
    assert "AKIA****************" in message
    assert PLAINTEXT_SECRET not in message


def test_email_without_a_configured_relay_fails_loudly() -> None:
    """A configured channel and an unconfigured deployment should say so, not
    silently drop the mail."""
    settings = ApiSettings(
        database_url="postgresql+psycopg://unused/unused",
        master_key=SecretStr("unused"),
        smtp_host=None,
    )
    channel = NotificationChannel(
        name="secops",
        type=NotificationChannelType.EMAIL,
        config={"recipients": ["secops@example.com"]},
    )

    with pytest.raises(DeliveryError) as raised:
        SmtpTransport(settings).send(channel, {}, subject="x")

    assert raised.value.permanent is True
    assert "ICEBERG_SMTP_HOST" in str(raised.value)


def test_pending_count_reports_what_is_queued(
    session: Session,
    scan: Scan,
    make_open_finding: Callable[..., Finding],
    make_channel: Callable[..., NotificationChannel],
) -> None:
    channel = make_channel()
    make_open_finding()
    make_open_finding()
    dispatch.enqueue_for_scan(session, scan)
    session.commit()

    assert dispatch.pending_count(session) == 2
    assert dispatch.pending_count(session, channel_id=channel.id) == 2
    assert dispatch.pending_count(session, channel_id=uuid.uuid4()) == 0


def test_deliveries_are_removed_with_their_finding(
    session: Session,
    scan: Scan,
    make_open_finding: Callable[..., Finding],
    make_channel: Callable[..., NotificationChannel],
) -> None:
    """CASCADE, so retention pruning findings (#73) is not blocked by delivery rows."""
    make_channel()
    finding = make_open_finding()
    dispatch.enqueue_for_scan(session, scan)
    session.commit()

    session.delete(finding)
    session.commit()

    remaining = session.exec(
        select(NotificationDelivery).where(col(NotificationDelivery.finding_id) == finding.id)
    ).all()
    assert remaining == []
