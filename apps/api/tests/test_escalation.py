"""Escalating findings that miss their response target (#146).

The property this is organised around: **an escalation is a message to the people
accountable, once per deadline.** Everything below is one of the two ways that can
go wrong — telling the wrong people, or telling the right people repeatedly.

Reuses the outbox the opened-finding announcements already ride on, so retry,
backoff and the never-lost guarantee come from #60 rather than being rebuilt.
"""

import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from iceberg_api.notifications import dispatch
from iceberg_api.notifications.payload import PAYLOAD_VERSION, email_body
from iceberg_core.config import ApiSettings
from iceberg_core.enums import (
    FindingState,
    NotificationChannelType,
    NotificationDeliveryStatus,
    NotificationEventKind,
    ScanStatus,
    ScanTrigger,
    Severity,
    SourceType,
)
from iceberg_core.models import (
    Finding,
    NotificationChannel,
    NotificationDelivery,
    OwnerGroup,
    Scan,
    Source,
)
from pydantic import SecretStr
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, col, select

NOW = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)
LATE = NOW - timedelta(hours=30)
PLAINTEXT_SECRET = "AKIAIOSFODNN7EXAMPLE"


@pytest.fixture(name="source")
def source_fixture(session: Session) -> Source:
    source = Source(
        name="confluence-prod",
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


@pytest.fixture(name="make_group")
def make_group_fixture(session: Session) -> Callable[..., OwnerGroup]:
    def factory(name: str = "payments", **fields: Any) -> OwnerGroup:
        group = OwnerGroup(name=name, **fields)
        session.add(group)
        session.commit()
        return group

    return factory


@pytest.fixture(name="make_finding")
def make_finding_fixture(session: Session, source: Source, scan: Scan) -> Callable[..., Finding]:
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
            "due_at": LATE,
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


class RecordingTransport:
    """Stands in for SMTP/HTTP. Records what it was asked to send."""

    def __init__(self) -> None:
        self.sent: list[tuple[NotificationChannel, dict[str, Any], str]] = []

    def send(self, channel: NotificationChannel, payload: dict[str, Any], *, subject: str) -> None:
        self.sent.append((channel, payload, subject))


@pytest.fixture(name="dispatch_settings")
def dispatch_settings_fixture() -> ApiSettings:
    return ApiSettings(
        database_url="postgresql+psycopg://unused/unused",
        master_key=SecretStr("unused"),
        notification_max_attempts=3,
        notification_retry_backoff_seconds=60,
    )


def _escalations(session: Session) -> list[NotificationDelivery]:
    return list(
        session.exec(
            select(NotificationDelivery).where(
                col(NotificationDelivery.kind) == NotificationEventKind.FINDING_OVERDUE
            )
        )
    )


# ─── Who hears about it ───────────────────────────────────────────────────────


def test_an_overdue_finding_escalates_to_its_own_team(
    session: Session,
    make_channel: Callable[..., NotificationChannel],
    make_group: Callable[..., OwnerGroup],
    make_finding: Callable[..., Finding],
) -> None:
    """An escalation is a message to the people accountable, not a broadcast."""
    theirs, mine = make_channel(name="everything"), make_channel(name="payments-oncall")
    group = make_group(notification_channel_id=mine.id)
    finding = make_finding(owner_group_id=group.id)

    queued = dispatch.escalate_overdue(session, now=NOW)
    session.commit()

    assert queued == 1
    escalation = _escalations(session)[0]
    assert (escalation.channel_id, escalation.finding_id) == (mine.id, finding.id)
    assert theirs.id != escalation.channel_id


def test_a_team_with_no_channel_is_silent_by_choice(
    session: Session,
    make_channel: Callable[..., NotificationChannel],
    make_group: Callable[..., OwnerGroup],
    make_finding: Callable[..., Finding],
) -> None:
    """Escalating to every channel instead would punish configuring a team at all.
    The console's overdue queue is still the record."""
    make_channel()
    group = make_group()
    make_finding(owner_group_id=group.id)

    assert dispatch.escalate_overdue(session, now=NOW) == 0


def test_an_unowned_overdue_finding_escalates_to_the_channels_that_would_have_announced_it(
    session: Session,
    make_channel: Callable[..., NotificationChannel],
    make_finding: Callable[..., Finding],
) -> None:
    """Late *and* nobody has picked it up is the state most worth saying out loud,
    and it is exactly the state with no team to tell. Those channels already hear
    about this class of finding when it opens."""
    make_channel(name="a")
    make_channel(name="b")
    make_finding(owner_group_id=None)

    queued = dispatch.escalate_overdue(session, now=NOW)
    session.commit()

    assert queued == 2


def test_an_unowned_escalation_still_honours_the_channel_filter(
    session: Session,
    make_channel: Callable[..., NotificationChannel],
    make_finding: Callable[..., Finding],
) -> None:
    """A channel that asked only for criticals did not ask to hear about a
    medium being late."""
    make_channel(event_filter={"min_severity": Severity.CRITICAL.value})
    make_finding(severity=Severity.MEDIUM, owner_group_id=None)

    assert dispatch.escalate_overdue(session, now=NOW) == 0


def test_work_stranded_on_a_disbanded_team_escalates_loudly(
    session: Session,
    make_channel: Callable[..., NotificationChannel],
    make_group: Callable[..., OwnerGroup],
    make_finding: Callable[..., Finding],
) -> None:
    """Nobody is reading that team's channel. Falling back to the channels that
    would have announced the finding is the same reasoning as the unowned case —
    which is what this effectively is."""
    make_channel(name="a")
    make_channel(name="b")
    gone = make_group(disabled=True, notification_channel_id=None)
    make_finding(owner_group_id=gone.id)

    assert dispatch.escalate_overdue(session, now=NOW) == 2


def test_a_disabled_channel_is_never_a_target(
    session: Session,
    make_channel: Callable[..., NotificationChannel],
    make_group: Callable[..., OwnerGroup],
    make_finding: Callable[..., Finding],
) -> None:
    """Disabling a channel is an operator saying stop, including for a team that
    still names it."""
    off = make_channel(enabled=False)
    group = make_group(notification_channel_id=off.id)
    make_finding(owner_group_id=group.id)

    assert dispatch.escalate_overdue(session, now=NOW) == 0


# ─── What is and is not overdue ───────────────────────────────────────────────


@pytest.mark.parametrize(
    ("fields", "expected"),
    [
        ({}, 1),
        ({"due_at": NOW + timedelta(days=1)}, 0),
        ({"due_at": None}, 0),
        ({"state": FindingState.RESOLVED}, 0),
        ({"state": FindingState.FALSE_POSITIVE}, 0),
        ({"suppressed_at": LATE}, 0),
    ],
)
def test_only_actionable_overdue_work_escalates(
    session: Session,
    make_channel: Callable[..., NotificationChannel],
    make_finding: Callable[..., Finding],
    fields: dict[str, Any],
    expected: int,
) -> None:
    """The same definition the queue and the badge use. A suppressed finding keeps
    its date — the suppression can lapse — but mailing somebody about it would
    honour "stop telling me" in the console and ignore it in their inbox."""
    make_channel()
    make_finding(owner_group_id=None, **fields)

    assert dispatch.escalate_overdue(session, now=NOW) == expected


def test_a_deployment_with_no_channels_does_no_work(
    session: Session, make_finding: Callable[..., Finding]
) -> None:
    make_finding(owner_group_id=None)

    assert dispatch.escalate_overdue(session, now=NOW) == 0


def test_a_backlog_larger_than_one_beat_drains_across_beats(
    session: Session,
    make_channel: Callable[..., NotificationChannel],
    make_finding: Callable[..., Finding],
) -> None:
    """The bound must not become a wall. Excluding already-escalated findings has
    to happen *before* the limit: filtering afterwards would re-select the same
    oldest page every beat, skip all of it, and never reach the rest — a backlog
    that stalls permanently, silently, exactly when it is largest."""
    make_channel()
    for index in range(5):
        make_finding(owner_group_id=None, due_at=LATE + timedelta(minutes=index))

    beats = [dispatch.escalate_overdue(session, now=NOW, limit=2) for _ in range(4)]
    session.commit()

    assert beats == [2, 2, 1, 0]
    assert len(_escalations(session)) == 5


def test_a_beat_is_bounded_so_a_backlog_does_not_arrive_at_once(
    session: Session,
    make_channel: Callable[..., NotificationChannel],
    make_finding: Callable[..., Finding],
) -> None:
    """Turning escalation on after months of backlog should not try to mail the
    whole history in one round; the rest go out on the next beat."""
    make_channel()
    for _ in range(5):
        make_finding(owner_group_id=None)

    assert dispatch.escalate_overdue(session, now=NOW, limit=2) == 2
    assert len(_escalations(session)) == 2


# ─── Once per deadline ────────────────────────────────────────────────────────


def test_a_second_beat_escalates_nothing_new(
    session: Session,
    make_channel: Callable[..., NotificationChannel],
    make_finding: Callable[..., Finding],
) -> None:
    """The loop runs every minute. Without this an operator would be mailed about
    the same late finding once a minute until they fixed it."""
    make_channel()
    make_finding(owner_group_id=None)
    dispatch.escalate_overdue(session, now=NOW)
    session.commit()

    again = dispatch.escalate_overdue(session, now=NOW + timedelta(minutes=1))
    session.commit()

    assert again == 0
    assert len(_escalations(session)) == 1


def test_a_duplicate_escalation_is_refused_by_the_database(
    session: Session,
    make_channel: Callable[..., NotificationChannel],
    make_finding: Callable[..., Finding],
) -> None:
    """The constraint itself, exercised rather than assumed. `scan_id` is NULL on
    these rows, so the existing unique constraint cannot dedupe them — NULLs do
    not collide — and a partial index over the deadline does."""
    channel = make_channel()
    finding = make_finding(owner_group_id=None)
    dispatch.escalate_overdue(session, now=NOW)
    session.commit()

    session.add(
        NotificationDelivery(
            channel_id=channel.id,
            finding_id=finding.id,
            kind=NotificationEventKind.FINDING_OVERDUE,
            scan_id=None,
            due_at=finding.due_at,
            status=NotificationDeliveryStatus.PENDING,
            next_attempt_at=NOW,
        )
    )
    with pytest.raises(IntegrityError):
        session.commit()
    session.rollback()


def test_a_new_deadline_escalates_again(
    session: Session,
    make_channel: Callable[..., NotificationChannel],
    make_finding: Callable[..., Finding],
) -> None:
    """A reopened finding gets a fresh clock. Missing the *new* target is a new
    fact, and a team that already heard about the old one should hear about it —
    which is why the row carries the deadline rather than just the finding."""
    make_channel()
    finding = make_finding(owner_group_id=None)
    dispatch.escalate_overdue(session, now=NOW)
    session.commit()

    finding.due_at = NOW - timedelta(hours=1)
    session.add(finding)
    session.commit()

    assert dispatch.escalate_overdue(session, now=NOW) == 1
    assert len(_escalations(session)) == 2


def test_an_escalation_does_not_collide_with_the_announcement_of_the_same_finding(
    session: Session,
    scan: Scan,
    make_channel: Callable[..., NotificationChannel],
    make_finding: Callable[..., Finding],
) -> None:
    """Two different messages about one finding to one channel: "this appeared"
    and "nobody fixed it". The two dedup keys must not fight."""
    make_channel()
    make_finding(owner_group_id=None)

    dispatch.enqueue_for_scan(session, scan, now=NOW)
    dispatch.escalate_overdue(session, now=NOW)
    session.commit()

    kinds = sorted(
        delivery.kind.value for delivery in session.exec(select(NotificationDelivery)).all()
    )
    assert kinds == ["finding_opened", "finding_overdue"]


def test_a_retried_escalation_reports_the_deadline_it_was_queued_for(
    session: Session,
    dispatch_settings: ApiSettings,
    secret_store: Any,
    make_channel: Callable[..., NotificationChannel],
    make_finding: Callable[..., Finding],
) -> None:
    """A delivery can be queued now and sent later. If the finding is resolved and
    reopened in between it gets a *fresh* deadline — and the pending message would
    then announce a deadline that has not passed yet, about an escalation queued
    for one that had. The row records which event this is."""
    make_channel()
    finding = make_finding(owner_group_id=None)
    dispatch.escalate_overdue(session, now=NOW)
    session.commit()

    # Reopened before the delivery went out: a new clock, a later deadline.
    finding.due_at = NOW + timedelta(days=7)
    session.add(finding)
    session.commit()
    transport = RecordingTransport()

    dispatch.deliver_pending(
        session,
        dispatch_settings,
        secret_store,
        now=NOW,
        transports=dict.fromkeys(NotificationChannelType, transport),
    )

    _channel, payload, _subject = transport.sent[0]
    assert payload["escalation"]["due_at"] == LATE.isoformat()
    assert payload["escalation"]["overdue_by_hours"] == 30


# ─── What goes out ────────────────────────────────────────────────────────────


def test_the_payload_names_the_deadline_the_team_and_how_late_it_is(
    session: Session,
    dispatch_settings: ApiSettings,
    secret_store: Any,
    make_channel: Callable[..., NotificationChannel],
    make_group: Callable[..., OwnerGroup],
    make_finding: Callable[..., Finding],
) -> None:
    channel = make_channel()
    group = make_group(notification_channel_id=channel.id)
    make_finding(owner_group_id=group.id)
    dispatch.escalate_overdue(session, now=NOW)
    session.commit()
    transport = RecordingTransport()

    dispatch.deliver_pending(
        session,
        dispatch_settings,
        secret_store,
        now=NOW,
        transports=dict.fromkeys(NotificationChannelType, transport),
    )

    _channel, payload, subject = transport.sent[0]
    assert payload["event"] == "finding.overdue"
    assert payload["version"] == PAYLOAD_VERSION
    assert payload["escalation"]["overdue_by_hours"] == 30
    assert payload["escalation"]["owner_group"]["name"] == "payments"
    assert "OVERDUE" in subject
    # No scan block: nothing scanned. A deadline passed.
    assert "scan" not in payload


def test_an_escalation_carries_the_same_finding_shape_as_an_announcement(
    session: Session,
    dispatch_settings: ApiSettings,
    secret_store: Any,
    scan: Scan,
    make_channel: Callable[..., NotificationChannel],
    make_finding: Callable[..., Finding],
) -> None:
    """A receiver should parse one shape and switch on `event`."""
    make_channel()
    make_finding(owner_group_id=None)
    dispatch.enqueue_for_scan(session, scan, now=NOW)
    dispatch.escalate_overdue(session, now=NOW)
    session.commit()
    transport = RecordingTransport()

    dispatch.deliver_pending(
        session,
        dispatch_settings,
        secret_store,
        now=NOW,
        transports=dict.fromkeys(NotificationChannelType, transport),
    )

    shapes = [sorted(payload["finding"]) for _channel, payload, _subject in transport.sent]
    assert len(shapes) == 2
    assert shapes[0] == shapes[1]


def test_an_escalation_never_carries_the_secret(
    session: Session,
    dispatch_settings: ApiSettings,
    secret_store: Any,
    make_channel: Callable[..., NotificationChannel],
    make_finding: Callable[..., Finding],
) -> None:
    """The assertion that would matter most if it ever failed (ADR 0004)."""
    make_channel()
    make_finding(owner_group_id=None, redacted_snippet="AKIA****************")
    dispatch.escalate_overdue(session, now=NOW)
    session.commit()
    transport = RecordingTransport()

    dispatch.deliver_pending(
        session,
        dispatch_settings,
        secret_store,
        now=NOW,
        transports=dict.fromkeys(NotificationChannelType, transport),
    )

    _channel, payload, _subject = transport.sent[0]
    body = email_body(payload)
    assert PLAINTEXT_SECRET not in str(payload)
    assert PLAINTEXT_SECRET not in body
    assert "passed its response target" in body


def test_an_escalation_is_delivered_and_marked_like_any_other(
    session: Session,
    dispatch_settings: ApiSettings,
    secret_store: Any,
    make_channel: Callable[..., NotificationChannel],
    make_finding: Callable[..., Finding],
) -> None:
    """Reusing the outbox is the point: retry, backoff and "never lost silently"
    come from #60 rather than being rebuilt for escalations."""
    make_channel()
    make_finding(owner_group_id=None)
    dispatch.escalate_overdue(session, now=NOW)
    session.commit()

    outcome = dispatch.deliver_pending(
        session,
        dispatch_settings,
        secret_store,
        now=NOW,
        transports=dict.fromkeys(NotificationChannelType, RecordingTransport()),
    )

    assert outcome.delivered == 1
    escalation = _escalations(session)[0]
    assert escalation.status is NotificationDeliveryStatus.DELIVERED
    assert escalation.scan_id is None


def test_a_team_with_no_channel_does_not_block_everyone_elses_escalations(
    session: Session,
    make_channel: Callable[..., NotificationChannel],
    make_group: Callable[..., OwnerGroup],
    make_finding: Callable[..., Finding],
) -> None:
    """A finding with no escalation target writes no row, so the SQL exclusion —
    which asks "has this been escalated?" — never stops selecting it. Ordered by
    deadline, the oldest silent findings hold the front of the page for good, and
    nothing behind them is ever escalated (#190).

    The team here is silent by choice, which is allowed. What is not allowed is
    their silence costing everybody else their escalations.
    """
    channel = make_channel()
    silent_team = make_group(name="no-channel-team")
    for index in range(3):
        make_finding(owner_group_id=silent_team.id, due_at=LATE + timedelta(minutes=index))
    # Later deadline, so it sorts behind every silent finding above.
    heard = make_finding(owner_group_id=None, due_at=LATE + timedelta(hours=1))

    for _ in range(5):
        dispatch.escalate_overdue(session, now=NOW, limit=2)
        session.commit()

    escalated = {delivery.finding_id for delivery in _escalations(session)}
    assert heard.id in escalated, "a finding behind the silent ones was never escalated"
    assert escalated == {heard.id}
    assert [delivery.channel_id for delivery in _escalations(session)] == [channel.id]


@pytest.mark.parametrize(
    "event_filter",
    [
        {},
        {"min_severity": "high"},
        {"min_severity": "critical"},
        {"source_ids": []},
    ],
)
def test_the_two_readings_of_a_channel_filter_agree(
    session: Session,
    source: Source,
    make_channel: Callable[..., NotificationChannel],
    make_finding: Callable[..., Finding],
    event_filter: dict[str, Any],
) -> None:
    """`channel_wants` answers for one finding in Python; `_wanted_by` answers for
    every finding at once in SQL. They are two readings of one filter, and the
    escalation query is only correct while they agree — so they are checked
    against each other rather than trusted to stay in step (#190).
    """
    channel = make_channel(event_filter=event_filter)
    findings = [make_finding(severity=severity) for severity in Severity]

    in_python = {finding.id for finding in findings if dispatch.channel_wants(channel, finding)}
    in_sql = set(session.exec(select(Finding.id).where(dispatch._wanted_by(channel))).all())

    assert in_python == in_sql


def test_the_two_readings_agree_on_a_source_filter(
    session: Session,
    source: Source,
    make_channel: Callable[..., NotificationChannel],
    make_finding: Callable[..., Finding],
) -> None:
    """The other half of the filter vocabulary, which needs a real source id."""
    channel = make_channel(event_filter={"source_ids": [str(source.id)]})
    wanted = make_finding()
    other = Source(
        name="jira-prod",
        type=SourceType.JIRA,
        connection={"base_url": "https://example.atlassian.net"},
    )
    session.add(other)
    session.commit()
    unwanted = Finding(
        source_id=other.id,
        first_seen_scan_id=wanted.first_seen_scan_id,
        last_seen_scan_id=wanted.last_seen_scan_id,
        fingerprint=uuid.uuid4().hex,
        rule_id="aws-access-key",
        rulepack_version="2026.07.1",
        resource_locator={"path": "/browse/OPS-1"},
        redacted_snippet="AKIA****************",
        secret_hash=uuid.uuid4().hex,
        severity=Severity.HIGH,
        confidence=0.9,
        state=FindingState.OPEN,
        due_at=LATE,
    )
    session.add(unwanted)
    session.commit()

    in_python = {
        finding.id for finding in (wanted, unwanted) if dispatch.channel_wants(channel, finding)
    }
    in_sql = set(session.exec(select(Finding.id).where(dispatch._wanted_by(channel))).all())

    assert in_python == in_sql == {wanted.id}
