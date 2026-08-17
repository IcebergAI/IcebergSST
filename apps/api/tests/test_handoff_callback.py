"""What comes back from the receiving system (#141).

The inbound half, and every test here is really about one decision: **a callback
records what the receiver said and never writes it onto the finding.**

A finding's state is a decision made by a named analyst through a state machine
that enforces the legal moves and the evidence policy. A receiver is not a
person, so the only honest thing to do with a disagreement is show it. That is
the epic's "conflicts surface for review instead of silently overwriting state",
and it is also the only option that does not require either forging an actor for
the audit trail or bypassing the evidence policy.
"""

import hashlib
import hmac
import json
import uuid
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi import HTTPException, status
from fastapi.testclient import TestClient
from iceberg_core.config import ApiSettings
from iceberg_core.enums import FindingState, HandoffExternalState, HandoffStatus, UserRole
from iceberg_core.models import (
    AUDIT_TARGET_HANDOFF,
    AuditEvent,
    Finding,
    FindingHandoff,
    Source,
    User,
)
from pydantic import SecretStr
from sqlmodel import Session, col, select

SECRET = "payload-signing-secret"

TARGET = {
    "name": "soar-prod",
    "type": "webhook",
    "config": {"url": "https://soar.example.test/hooks/iceberg"},
    "secret": SECRET,
    "event_filter": {},
}


def _signed(
    body: dict[str, Any], *, secret: str = SECRET, at: datetime | None = None
) -> tuple[bytes, dict[str, str]]:
    """The body and headers a receiver would send, signed the way we sign to it."""
    raw = json.dumps(body).encode()
    timestamp = str(int((at or datetime.now(UTC)).timestamp()))
    mac = hmac.new(secret.encode(), f"{timestamp}.".encode() + raw, hashlib.sha256)
    return raw, {
        "Content-Type": "application/json",
        "X-Iceberg-Timestamp": timestamp,
        "X-Iceberg-Signature": f"sha256={mac.hexdigest()}",
    }


@pytest.fixture(name="handed_over")
def handed_over_fixture(
    client: TestClient,
    api: str,
    session: Session,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
) -> tuple[Finding, FindingHandoff]:
    """One finding handed to one target, delivered — the state a callback arrives in."""
    admin_headers = login_as(make_user(UserRole.ADMIN))
    target = client.post(f"{api}/handoff/targets", json=TARGET, headers=admin_headers)
    assert target.status_code == 201, target.text
    analyst_headers = login_as(make_user(UserRole.ANALYST))
    finding = make_finding(make_source())
    requested = client.post(
        f"{api}/findings/{finding.id}/handoffs",
        json={"target_id": target.json()["id"]},
        headers=analyst_headers,
    )
    assert requested.status_code == 201, requested.text

    handoff = session.exec(select(FindingHandoff)).one()
    handoff.status = HandoffStatus.DELIVERED
    handoff.delivered_at = datetime.now(UTC)
    session.add(handoff)
    session.commit()
    return finding, handoff


def _actions(session: Session, target_type: str) -> list[str]:
    return [
        event.action
        for event in session.exec(
            select(AuditEvent).where(col(AuditEvent.target_type) == target_type)
        )
    ]


# ─── Authentication ───────────────────────────────────────────────────────────


def test_a_signed_callback_is_recorded(
    client: TestClient,
    api: str,
    session: Session,
    handed_over: tuple[Finding, FindingHandoff],
) -> None:
    """The same secret both ways: a receiver that can verify our signature can
    produce one, so there is no second credential to issue or leak."""
    _finding, handoff = handed_over
    raw, headers = _signed(
        {
            "idempotency_key": handoff.idempotency_key,
            "state": "in_progress",
            "external_id": "SEC-1234",
            "external_url": "https://soar.example.test/tickets/SEC-1234",
        }
    )

    response = client.post(f"{api}/handoff/callback", content=raw, headers=headers)

    # 202, not 200: this records what was said and deliberately changes no
    # finding, so claiming to have applied something would be a lie.
    assert response.status_code == 202, response.text
    session.expire_all()
    stored = session.get(FindingHandoff, handoff.id)
    assert stored is not None
    assert stored.external_state is HandoffExternalState.IN_PROGRESS
    assert stored.external_id == "SEC-1234"
    assert stored.last_callback_at is not None


@pytest.mark.parametrize(
    ("mutate", "why"),
    [
        ({"signature": "sha256=deadbeef"}, "a forged signature"),
        ({"signature": None}, "no signature at all"),
        ({"timestamp": None}, "no timestamp"),
        ({"secret": "the-wrong-secret"}, "the wrong secret"),
    ],
)
def test_an_unauthenticated_callback_is_refused(
    mutate: dict[str, Any],
    why: str,
    client: TestClient,
    api: str,
    session: Session,
    handed_over: tuple[Finding, FindingHandoff],
) -> None:
    """Every failure answers the same 401. Which one failed is not something an
    unauthenticated caller gets to learn by trying."""
    _finding, handoff = handed_over
    body = {"idempotency_key": handoff.idempotency_key, "state": "resolved"}
    raw, headers = _signed(body, secret=mutate.get("secret", SECRET))
    if "signature" in mutate:
        headers.pop("X-Iceberg-Signature") if mutate["signature"] is None else headers.update(
            {"X-Iceberg-Signature": mutate["signature"]}
        )
    if mutate.get("timestamp", "keep") is None:
        headers.pop("X-Iceberg-Timestamp")

    response = client.post(f"{api}/handoff/callback", content=raw, headers=headers)

    assert response.status_code == 401, f"{why}: {response.text}"
    assert response.json()["detail"] == "callback rejected"
    session.expire_all()
    stored = session.get(FindingHandoff, handoff.id)
    assert stored is not None
    assert stored.external_state is None


def test_a_replayed_callback_is_refused_once_it_is_stale(
    client: TestClient,
    api: str,
    handed_over: tuple[Finding, FindingHandoff],
) -> None:
    """The timestamp is inside the MAC, so it cannot be edited without breaking
    the signature — which is what stops a captured request being replayed for
    ever. The signature alone does not."""
    _finding, handoff = handed_over
    raw, headers = _signed(
        {"idempotency_key": handoff.idempotency_key, "state": "resolved"},
        at=datetime.now(UTC) - timedelta(hours=1),
    )

    response = client.post(f"{api}/handoff/callback", content=raw, headers=headers)

    assert response.status_code == 401


def test_a_callback_for_an_unknown_key_is_refused_like_a_bad_signature(
    client: TestClient,
    api: str,
    handed_over: tuple[Finding, FindingHandoff],
) -> None:
    """Same status and same body as a signature failure: the key is guessable
    enough to be worth not confirming."""
    raw, headers = _signed({"idempotency_key": "iceberg-handoff-nope", "state": "resolved"})

    response = client.post(f"{api}/handoff/callback", content=raw, headers=headers)

    assert response.status_code == 401
    assert response.json()["detail"] == "callback rejected"


def test_an_oversized_callback_body_is_refused_before_it_is_buffered(
    client: TestClient,
    api: str,
    handed_over: tuple[Finding, FindingHandoff],
) -> None:
    """This endpoint is reachable by anybody, so reading an unbounded body from
    an unauthenticated caller is the cheapest way there is to spend a worker's
    memory.

    Checked as it arrives rather than after the fact — checking afterwards is not
    a cap, it is a report on what was already spent. The same defect that was
    fixed on the outbound reply in #179, in the other direction.
    """
    from iceberg_api.handoff.callback import MAX_CALLBACK_BYTES

    _finding, handoff = handed_over
    raw, headers = _signed(
        {
            "idempotency_key": handoff.idempotency_key,
            "state": "open",
            "external_id": "x" * (MAX_CALLBACK_BYTES + 1),
        }
    )

    response = client.post(f"{api}/handoff/callback", content=raw, headers=headers)

    assert response.status_code == 413, response.text


def test_an_oversized_callback_is_refused_even_without_a_content_length(
    client: TestClient,
    api: str,
    handed_over: tuple[Finding, FindingHandoff],
) -> None:
    """A chunked request carries no length, and a dishonest one is why the
    streamed count exists rather than trusting the header."""
    from iceberg_api.handoff.callback import MAX_CALLBACK_BYTES

    _finding, handoff = handed_over
    _raw, headers = _signed({"idempotency_key": handoff.idempotency_key, "state": "open"})

    def chunked() -> Iterator[bytes]:
        for _ in range((MAX_CALLBACK_BYTES // 8192) + 2):
            yield b"x" * 8192

    response = client.post(f"{api}/handoff/callback", content=chunked(), headers=headers)

    assert response.status_code == 413, response.text


def test_a_callback_is_rate_limited_before_its_body_is_read(
    client: TestClient,
    api: str,
    monkeypatch: pytest.MonkeyPatch,
    handed_over: tuple[Finding, FindingHandoff],
) -> None:
    """Charged first, so an unauthenticated caller costs itself something before
    it costs us anything.

    The ordering *is* the control, so it is asserted directly rather than through
    the limiter's behaviour: a full bucket is staged, and an oversized body —
    which this route otherwise refuses with a 413 — must come back 429. Only the
    charge happening before the read can produce that.

    Driving it through the real limiter would prove nothing here: its store is
    unavailable under test and it fails open, so every request would be allowed
    and the test would pass whatever the order.
    """
    from iceberg_api import ratelimit
    from iceberg_api.handoff.callback import MAX_CALLBACK_BYTES

    def bucket_empty(*args: Any, **kwargs: Any) -> None:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "rate limited")

    monkeypatch.setattr(ratelimit, "enforce", bucket_empty)

    _finding, handoff = handed_over
    oversized, headers = _signed(
        {
            "idempotency_key": handoff.idempotency_key,
            "state": "open",
            "external_id": "x" * (MAX_CALLBACK_BYTES + 1),
        }
    )
    response = client.post(f"{api}/handoff/callback", content=oversized, headers=headers)

    assert response.status_code == 429, response.text


def test_a_callback_never_needs_a_session_or_a_csrf_token(
    client: TestClient,
    api: str,
    handed_over: tuple[Finding, FindingHandoff],
) -> None:
    """The caller is another system, not a browser. Requiring either would make
    the documented integration impossible."""
    _finding, handoff = handed_over
    raw, headers = _signed({"idempotency_key": handoff.idempotency_key, "state": "open"})
    client.cookies.clear()

    response = client.post(f"{api}/handoff/callback", content=raw, headers=headers)

    assert response.status_code == 202, response.text


# ─── What it is allowed to do ─────────────────────────────────────────────────


def test_a_callback_never_changes_the_findings_state(
    client: TestClient,
    api: str,
    session: Session,
    handed_over: tuple[Finding, FindingHandoff],
) -> None:
    """The invariant the whole design rests on. Triage demands a named actor and
    enforces the evidence policy; letting a receiver drive it would mean either
    forging an actor or going round the policy."""
    finding, handoff = handed_over
    assert finding.state is FindingState.OPEN
    raw, headers = _signed({"idempotency_key": handoff.idempotency_key, "state": "resolved"})

    client.post(f"{api}/handoff/callback", content=raw, headers=headers)

    session.expire_all()
    unchanged = session.get(Finding, finding.id)
    assert unchanged is not None
    assert unchanged.state is FindingState.OPEN


def test_a_resolved_work_item_on_an_open_finding_is_a_conflict(
    client: TestClient,
    api: str,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
    handed_over: tuple[Finding, FindingHandoff],
) -> None:
    """The loud direction: everyone over there has stopped, and the secret is
    still exposed as far as this deployment knows."""
    finding, handoff = handed_over
    raw, headers = _signed({"idempotency_key": handoff.idempotency_key, "state": "resolved"})
    client.post(f"{api}/handoff/callback", content=raw, headers=headers)

    listed = client.get(f"{api}/handoff/conflicts", headers=login_as(make_user(UserRole.ANALYST)))

    assert listed.status_code == 200, listed.text
    (conflict,) = listed.json()
    assert conflict["kind"] == "external_resolved_finding_open"
    assert conflict["finding_id"] == str(finding.id)
    assert conflict["external_state"] == "resolved"
    assert "still open" in conflict["reason"]


@pytest.mark.parametrize("state", ["rejected", "cancelled"])
def test_an_abandoned_work_item_on_an_open_finding_is_a_conflict(
    state: str,
    client: TestClient,
    api: str,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
    handed_over: tuple[Finding, FindingHandoff],
) -> None:
    """A hand-over the receiver refused achieved nothing, and nobody is coming.
    That is worth surfacing as loudly as a resolution we did not make."""
    _finding, handoff = handed_over
    raw, headers = _signed({"idempotency_key": handoff.idempotency_key, "state": state})
    client.post(f"{api}/handoff/callback", content=raw, headers=headers)

    listed = client.get(f"{api}/handoff/conflicts", headers=login_as(make_user(UserRole.ANALYST)))

    (conflict,) = listed.json()
    assert conflict["kind"] == f"external_{state}_finding_open"


def test_an_active_work_item_on_a_resolved_finding_is_a_conflict(
    client: TestClient,
    api: str,
    session: Session,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
    handed_over: tuple[Finding, FindingHandoff],
) -> None:
    """The quiet direction, and a real waste: somebody over there is working a
    ticket for something already decided here."""
    finding, handoff = handed_over
    finding.state = FindingState.RESOLVED
    session.add(finding)
    session.commit()
    raw, headers = _signed({"idempotency_key": handoff.idempotency_key, "state": "in_progress"})
    client.post(f"{api}/handoff/callback", content=raw, headers=headers)

    listed = client.get(f"{api}/handoff/conflicts", headers=login_as(make_user(UserRole.ANALYST)))

    (conflict,) = listed.json()
    assert conflict["kind"] == "finding_resolved_external_open"


def test_agreement_is_not_a_conflict(
    client: TestClient,
    api: str,
    session: Session,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
    handed_over: tuple[Finding, FindingHandoff],
) -> None:
    """Both systems say it is done, so there is nothing to review."""
    finding, handoff = handed_over
    finding.state = FindingState.RESOLVED
    session.add(finding)
    session.commit()
    raw, headers = _signed({"idempotency_key": handoff.idempotency_key, "state": "resolved"})
    client.post(f"{api}/handoff/callback", content=raw, headers=headers)

    listed = client.get(f"{api}/handoff/conflicts", headers=login_as(make_user(UserRole.ANALYST)))

    assert listed.json() == []


def test_a_conflict_clears_itself_when_an_analyst_triages_the_finding(
    client: TestClient,
    api: str,
    session: Session,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
    handed_over: tuple[Finding, FindingHandoff],
) -> None:
    """The reason a conflict is derived rather than stored.

    An analyst who agrees with the receiver resolves the finding through the
    ordinary triage route — with the legal moves and the evidence policy intact —
    and the disagreement stops existing because there is no longer one. No second
    path into triage, and nothing left behind to tidy up.
    """
    finding, handoff = handed_over
    raw, headers = _signed({"idempotency_key": handoff.idempotency_key, "state": "resolved"})
    client.post(f"{api}/handoff/callback", content=raw, headers=headers)
    analyst_headers = login_as(make_user(UserRole.ANALYST))
    assert client.get(f"{api}/handoff/conflicts", headers=analyst_headers).json() != []

    triaged = client.patch(
        f"{api}/findings/{finding.id}",
        json={"state": FindingState.RESOLVED.value},
        headers=analyst_headers,
    )

    assert triaged.status_code == 200, triaged.text
    assert client.get(f"{api}/handoff/conflicts", headers=analyst_headers).json() == []


# ─── Dismissal ────────────────────────────────────────────────────────────────


def test_an_analyst_can_dismiss_a_conflict(
    client: TestClient,
    api: str,
    session: Session,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
    handed_over: tuple[Finding, FindingHandoff],
) -> None:
    """ "I have looked, and these two may stay out of step" is a judgement worth
    recording, so it is audited."""
    finding, handoff = handed_over
    raw, headers = _signed({"idempotency_key": handoff.idempotency_key, "state": "rejected"})
    client.post(f"{api}/handoff/callback", content=raw, headers=headers)
    analyst_headers = login_as(make_user(UserRole.ANALYST))

    dismissed = client.post(
        f"{api}/findings/{finding.id}/handoffs/{handoff.id}/dismiss-conflict",
        headers=analyst_headers,
    )

    assert dismissed.status_code == 200, dismissed.text
    assert dismissed.json()["conflict"] is None
    assert client.get(f"{api}/handoff/conflicts", headers=analyst_headers).json() == []
    assert "handoff.conflict_dismissed" in _actions(session, AUDIT_TARGET_HANDOFF)


def test_a_dismissal_only_silences_the_state_it_was_made_about(
    client: TestClient,
    api: str,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
    handed_over: tuple[Finding, FindingHandoff],
) -> None:
    """A dismissal is a judgement about one situation, not a permanent exemption.
    When the receiver moves on, the question is a different one and gets asked
    again."""
    finding, handoff = handed_over
    raw, headers = _signed({"idempotency_key": handoff.idempotency_key, "state": "rejected"})
    client.post(f"{api}/handoff/callback", content=raw, headers=headers)
    analyst_headers = login_as(make_user(UserRole.ANALYST))
    client.post(
        f"{api}/findings/{finding.id}/handoffs/{handoff.id}/dismiss-conflict",
        headers=analyst_headers,
    )
    assert client.get(f"{api}/handoff/conflicts", headers=analyst_headers).json() == []

    moved_on, moved_headers = _signed(
        {"idempotency_key": handoff.idempotency_key, "state": "resolved"}
    )
    client.post(f"{api}/handoff/callback", content=moved_on, headers=moved_headers)

    (raised_again,) = client.get(f"{api}/handoff/conflicts", headers=analyst_headers).json()
    assert raised_again["external_state"] == "resolved"


def test_dismissing_a_handoff_that_is_not_in_conflict_is_refused(
    client: TestClient,
    api: str,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
    handed_over: tuple[Finding, FindingHandoff],
) -> None:
    """Nothing to dismiss is not a silent success: it usually means the caller is
    looking at a state that has already moved."""
    finding, handoff = handed_over

    response = client.post(
        f"{api}/findings/{finding.id}/handoffs/{handoff.id}/dismiss-conflict",
        headers=login_as(make_user(UserRole.ANALYST)),
    )

    assert response.status_code == 409
    assert "not in conflict" in response.json()["detail"]


def test_a_viewer_cannot_see_the_conflict_queue(
    client: TestClient,
    api: str,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """Same reasoning as the target list: which external systems hold this
    deployment's findings is not part of reading one."""
    headers = login_as(make_user(UserRole.VIEWER))

    assert client.get(f"{api}/handoff/conflicts", headers=headers).status_code == 403


# ─── Sync health ──────────────────────────────────────────────────────────────


def test_a_delivered_handoff_nobody_ever_reported_on_reads_as_silent(
    session: Session,
    secret_store: Any,
    handed_over: tuple[Finding, FindingHandoff],
) -> None:
    """A receiver with nothing to report looks exactly like one that has stopped
    calling back, and only a clock we control tells them apart."""
    from iceberg_api.handoff import callback

    _finding, handoff = handed_over
    settings = ApiSettings(
        database_url="postgresql+psycopg://unused/unused",
        master_key=SecretStr("unused"),
        handoff_silent_after_hours=72,
    )
    handoff.delivered_at = datetime.now(UTC) - timedelta(days=7)
    session.add(handoff)
    session.commit()

    silent = callback.stale_handoffs(session, settings)

    assert [row.id for row in silent] == [handoff.id]

    # And one that reported is not silent, however long ago it was delivered.
    callback.record(session, handoff, state=HandoffExternalState.IN_PROGRESS)
    session.commit()
    assert callback.stale_handoffs(session, settings) == []


def test_sync_health_reports_conflicts_and_silence(
    client: TestClient,
    api: str,
    session: Session,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
    handed_over: tuple[Finding, FindingHandoff],
) -> None:
    """The operator's view of both questions, and the reason `stale_handoffs`
    exists at all — a health signal nothing calls is a health signal nobody has."""
    _finding, handoff = handed_over
    handoff.delivered_at = datetime.now(UTC) - timedelta(days=7)
    session.add(handoff)
    session.commit()
    headers = login_as(make_user(UserRole.ANALYST))

    silent = client.get(f"{api}/handoff/health", headers=headers)

    assert silent.status_code == 200, silent.text
    body = silent.json()
    assert body["conflicts"] == 0
    assert body["silent_after_hours"] == 72
    assert [row["handoff_id"] for row in body["silent"]] == [str(handoff.id)]

    # One callback answers both questions at once: it is no longer silent, and
    # what it said disagrees with a finding that is still open.
    raw, callback_headers = _signed(
        {"idempotency_key": handoff.idempotency_key, "state": "resolved"}
    )
    client.post(f"{api}/handoff/callback", content=raw, headers=callback_headers)

    reported = client.get(f"{api}/handoff/health", headers=headers).json()
    assert reported["silent"] == []
    assert reported["conflicts"] == 1


def test_a_callback_that_arrives_out_of_order_does_not_move_the_state_backwards(
    client: TestClient,
    api: str,
    session: Session,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
    handed_over: tuple[Finding, FindingHandoff],
) -> None:
    """A retried `in_progress` overtaking the `resolved` that followed it is
    ordinary once anything queues or retries in between.

    Applying it would move the work item backwards and raise a conflict that
    stopped being true — so the receiver's own `state_at` orders them, because
    our arrival time is the very thing in question.
    """
    _finding, handoff = handed_over
    settled = datetime.now(UTC) - timedelta(minutes=1)
    current, current_headers = _signed(
        {
            "idempotency_key": handoff.idempotency_key,
            "state": "resolved",
            "state_at": settled.isoformat(),
        }
    )
    client.post(f"{api}/handoff/callback", content=current, headers=current_headers)

    delayed, delayed_headers = _signed(
        {
            "idempotency_key": handoff.idempotency_key,
            "state": "in_progress",
            "state_at": (settled - timedelta(minutes=30)).isoformat(),
        }
    )
    response = client.post(f"{api}/handoff/callback", content=delayed, headers=delayed_headers)

    # Accepted — it is a well-formed, authenticated report — but it does not win.
    assert response.status_code == 202, response.text
    session.expire_all()
    stored = session.get(FindingHandoff, handoff.id)
    assert stored is not None
    assert stored.external_state is HandoffExternalState.RESOLVED
    # And it still counts as the integration being alive, or a chatty receiver
    # whose messages arrive out of order would read as a silent one.
    assert stored.last_callback_at is not None


def test_without_a_state_at_the_newest_callback_wins(
    client: TestClient,
    api: str,
    session: Session,
    handed_over: tuple[Finding, FindingHandoff],
) -> None:
    """Only the receiver's own clock can order two reports. With nothing to
    compare, last-writer-wins is the honest answer rather than a guess dressed up
    as ordering."""
    _finding, handoff = handed_over
    for state in ("resolved", "in_progress"):
        raw, headers = _signed({"idempotency_key": handoff.idempotency_key, "state": state})
        client.post(f"{api}/handoff/callback", content=raw, headers=headers)

    session.expire_all()
    stored = session.get(FindingHandoff, handoff.id)
    assert stored is not None
    assert stored.external_state is HandoffExternalState.IN_PROGRESS


def test_a_callback_repairs_an_id_a_lost_reply_never_recorded(
    client: TestClient,
    api: str,
    session: Session,
    handed_over: tuple[Finding, FindingHandoff],
) -> None:
    """A delivery whose reply was lost has no external id. The callback is the
    evidence that repairs it — and a later callback that omits the fields does
    not blank them, because silence is not a retraction."""
    _finding, handoff = handed_over
    assert handoff.external_id is None
    named, named_headers = _signed(
        {
            "idempotency_key": handoff.idempotency_key,
            "state": "open",
            "external_id": "SEC-77",
            "external_url": "https://soar.example.test/tickets/SEC-77",
        }
    )
    client.post(f"{api}/handoff/callback", content=named, headers=named_headers)

    quiet, quiet_headers = _signed(
        {"idempotency_key": handoff.idempotency_key, "state": "in_progress"}
    )
    client.post(f"{api}/handoff/callback", content=quiet, headers=quiet_headers)

    session.expire_all()
    stored = session.get(FindingHandoff, handoff.id)
    assert stored is not None
    assert stored.external_id == "SEC-77"
    assert stored.external_url == "https://soar.example.test/tickets/SEC-77"


def test_a_callback_is_accepted_for_a_handoff_our_own_send_recorded_as_failed(
    client: TestClient,
    api: str,
    session: Session,
    handed_over: tuple[Finding, FindingHandoff],
) -> None:
    """The lost-reply case, from the other side: we gave up while the work item
    existed all along. Refusing the callback would throw away the better
    information in favour of our own worse record."""
    _finding, handoff = handed_over
    handoff.status = HandoffStatus.FAILED
    handoff.last_error = "handoff request failed: ReadTimeout"
    session.add(handoff)
    session.commit()
    raw, headers = _signed(
        {"idempotency_key": handoff.idempotency_key, "state": "open", "external_id": "SEC-9"}
    )

    response = client.post(f"{api}/handoff/callback", content=raw, headers=headers)

    assert response.status_code == 202, response.text
    session.expire_all()
    stored = session.get(FindingHandoff, handoff.id)
    assert stored is not None
    assert stored.external_id == "SEC-9"


def test_an_unknown_external_state_is_refused(
    client: TestClient,
    api: str,
    handed_over: tuple[Finding, FindingHandoff],
) -> None:
    """The vocabulary is closed on purpose: every platform has its own status
    names, and accepting them verbatim would make "is this being worked?"
    unanswerable without knowing which product each row came from."""
    _finding, handoff = handed_over
    raw, headers = _signed(
        {"idempotency_key": handoff.idempotency_key, "state": "AwaitingChangeBoard"}
    )

    response = client.post(f"{api}/handoff/callback", content=raw, headers=headers)

    assert response.status_code == 400


def test_a_callback_body_the_schema_does_not_model_is_refused(
    client: TestClient,
    api: str,
    handed_over: tuple[Finding, FindingHandoff],
) -> None:
    """Rather than silently dropped, so a receiver sending something it thinks
    matters finds out."""
    _finding, handoff = handed_over
    raw, headers = _signed(
        {
            "idempotency_key": handoff.idempotency_key,
            "state": "open",
            "assignee": "someone@example.test",
        }
    )

    response = client.post(f"{api}/handoff/callback", content=raw, headers=headers)

    assert response.status_code == 400


def test_a_findings_handoff_list_carries_the_inbound_state(
    client: TestClient,
    api: str,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
    handed_over: tuple[Finding, FindingHandoff],
) -> None:
    """ "Did this actually reach anybody, and what did they do with it?" answered
    in one place."""
    finding, handoff = handed_over
    raw, headers = _signed({"idempotency_key": handoff.idempotency_key, "state": "resolved"})
    client.post(f"{api}/handoff/callback", content=raw, headers=headers)

    listed = client.get(
        f"{api}/findings/{finding.id}/handoffs", headers=login_as(make_user(UserRole.ANALYST))
    )

    (body,) = listed.json()
    assert body["external_state"] == "resolved"
    assert body["last_callback_at"] is not None
    assert "still open" in body["conflict"]


def test_an_unknown_handoff_id_on_dismiss_is_a_404(
    client: TestClient,
    api: str,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
    handed_over: tuple[Finding, FindingHandoff],
) -> None:
    finding, _handoff = handed_over

    response = client.post(
        f"{api}/findings/{finding.id}/handoffs/{uuid.uuid4()}/dismiss-conflict",
        headers=login_as(make_user(UserRole.ANALYST)),
    )

    assert response.status_code == 404
