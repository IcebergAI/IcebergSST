"""The API that drives external hand-over (#141).

The mechanism — one finding, one work item — is tested in `test_handoff.py`.
These tests are about who may ask for one and what the answer is, which is where
the two review follow-ups from #179 live:

* **#180** — a target's URL is validated on the way in, on *both* paths. The
  create schema having a validator the update schema lacked is what let a working
  target be edited into something the sender cannot deliver to.
* **#181** — two requests in flight at once return the same hand-over rather than
  a 500. The constraint refusing the loser is correct; surfacing that refusal to
  the analyst who clicked is not.
"""

import uuid
from collections.abc import Callable
from typing import Any

import pytest
from fastapi.testclient import TestClient
from iceberg_core.enums import HandoffStatus, Severity, UserRole
from iceberg_core.models import (
    AUDIT_TARGET_HANDOFF,
    AUDIT_TARGET_HANDOFF_TARGET,
    AuditEvent,
    Finding,
    FindingHandoff,
    HandoffTarget,
    Source,
    User,
)
from sqlmodel import Session, col, select

TARGET = {
    "name": "soar-prod",
    "type": "webhook",
    "config": {"url": "https://soar.example.test/hooks/iceberg"},
    "secret": "payload-signing-secret",
    "event_filter": {},
}


def _create_target(
    client: TestClient, api: str, headers: dict[str, str], **overrides: object
) -> dict[str, Any]:
    response = client.post(f"{api}/handoff/targets", json=TARGET | overrides, headers=headers)
    assert response.status_code == 201, response.text
    created: dict[str, Any] = response.json()
    return created


def _actions(session: Session, target_type: str) -> list[str]:
    return [
        event.action
        for event in session.exec(
            select(AuditEvent).where(col(AuditEvent.target_type) == target_type)
        )
    ]


# ─── Targets are an admin's decision ──────────────────────────────────────────


def test_an_admin_can_approve_a_destination(
    client: TestClient,
    api: str,
    session: Session,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    headers = login_as(make_user(UserRole.ADMIN))

    body = _create_target(client, api, headers)

    assert body["name"] == "soar-prod"
    assert body["config"]["url"] == "https://soar.example.test/hooks/iceberg"
    assert body["has_secret"] is True
    # Sealed, and never echoed back in any form — not the plaintext, not the ref.
    assert "secret" not in body
    assert "secret_ref" not in body["config"]

    target = session.exec(select(HandoffTarget)).one()
    assert target.config["secret_ref"]
    assert "payload-signing-secret" not in str(target.config)
    assert _actions(session, AUDIT_TARGET_HANDOFF_TARGET) == [
        "handoff_target.created",
        "handoff_target.secret_set",
    ]


def test_an_analyst_cannot_approve_a_destination(
    client: TestClient,
    api: str,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """Admins decide where findings may go; analysts decide which findings go."""
    headers = login_as(make_user(UserRole.ANALYST))

    response = client.post(f"{api}/handoff/targets", json=TARGET, headers=headers)

    assert response.status_code == 403


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "ftp://soar.example.test/hooks",
        "   ",
        "https://soar.example.test/hooks\nX-Injected: 1",
        "not a url at all",
    ],
)
def test_a_destination_that_is_not_an_http_url_is_refused_on_create(
    url: str,
    client: TestClient,
    api: str,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    headers = login_as(make_user(UserRole.ADMIN))

    response = client.post(
        f"{api}/handoff/targets", json=TARGET | {"config": {"url": url}}, headers=headers
    )

    assert response.status_code == 422, response.text


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "ftp://soar.example.test/hooks",
        "   ",
        "https://soar.example.test/hooks\nX-Injected: 1",
        "not a url at all",
    ],
)
def test_a_target_url_cannot_be_edited_into_an_unsupported_scheme(
    url: str,
    client: TestClient,
    api: str,
    session: Session,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """#180. The update path used to declare its own `url` with no validator, so
    everything the create path refuses could be introduced by editing afterwards —
    and would only be discovered at delivery time, by which point an analyst has
    already been told their finding was handed over.

    Both paths now go through one definition, which is why this is the same list
    of values as the create test above rather than a subset somebody maintains.
    """
    headers = login_as(make_user(UserRole.ADMIN))
    target = _create_target(client, api, headers)

    response = client.patch(
        f"{api}/handoff/targets/{target['id']}", json={"config": {"url": url}}, headers=headers
    )

    assert response.status_code == 422, response.text
    stored = session.exec(select(HandoffTarget)).one()
    assert stored.config["url"] == "https://soar.example.test/hooks/iceberg"


def test_editing_a_targets_url_keeps_its_signing_key(
    client: TestClient,
    api: str,
    session: Session,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """Fixing a typo in a URL is not a request to drop the signing key."""
    headers = login_as(make_user(UserRole.ADMIN))
    target = _create_target(client, api, headers)
    sealed = session.exec(select(HandoffTarget)).one().config["secret_ref"]

    response = client.patch(
        f"{api}/handoff/targets/{target['id']}",
        json={"config": {"url": "https://soar.example.test/hooks/v2"}},
        headers=headers,
    )

    assert response.status_code == 200, response.text
    assert response.json()["has_secret"] is True
    session.expire_all()
    stored = session.exec(select(HandoffTarget)).one()
    assert stored.config == {"url": "https://soar.example.test/hooks/v2", "secret_ref": sealed}


def test_a_caller_cannot_point_a_target_at_someone_elses_sealed_secret(
    client: TestClient,
    api: str,
    session: Session,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """The ref is minted here when a secret is sealed. Accepting one from a
    request would make it a way to borrow another object's material."""
    headers = login_as(make_user(UserRole.ADMIN))

    body = _create_target(
        client,
        api,
        headers,
        config={"url": "https://soar.example.test/hooks", "secret_ref": "someone-elses-ref"},
        secret=None,
    )

    assert body["has_secret"] is False
    stored = session.exec(select(HandoffTarget)).one()
    assert "secret_ref" not in stored.config


def test_deleting_a_target_takes_its_handoffs_with_it(
    client: TestClient,
    api: str,
    session: Session,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
) -> None:
    """Which is why *disabling* exists, and is the operation for winding a
    destination down: it stops delivery and keeps the record of what was sent."""
    admin = make_user(UserRole.ADMIN)
    target = _create_target(client, api, login_as(admin))
    analyst_headers = login_as(make_user(UserRole.ANALYST))
    finding = make_finding(make_source())
    client.post(
        f"{api}/findings/{finding.id}/handoffs",
        json={"target_id": target["id"]},
        headers=analyst_headers,
    )
    assert session.exec(select(FindingHandoff)).all()

    # Back to the admin: `login_as` swaps the client's session, so the earlier
    # headers belong to a session the analyst login replaced.
    response = client.delete(f"{api}/handoff/targets/{target['id']}", headers=login_as(admin))

    assert response.status_code == 204
    session.expire_all()
    assert session.exec(select(FindingHandoff)).all() == []
    assert "handoff_target.deleted" in _actions(session, AUDIT_TARGET_HANDOFF_TARGET)


# ─── Requesting a hand-over is an analyst's decision ──────────────────────────


def test_an_analyst_can_hand_a_finding_over(
    client: TestClient,
    api: str,
    session: Session,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
) -> None:
    admin_headers = login_as(make_user(UserRole.ADMIN))
    target = _create_target(client, api, admin_headers)
    analyst = make_user(UserRole.ANALYST)
    headers = login_as(analyst)
    finding = make_finding(make_source())

    response = client.post(
        f"{api}/findings/{finding.id}/handoffs",
        json={"target_id": target["id"]},
        headers=headers,
    )

    assert response.status_code == 201, response.text
    body = response.json()
    assert body["status"] == HandoffStatus.PENDING.value
    assert body["target_name"] == "soar-prod"
    assert body["requested_by_id"] == str(analyst.id)
    # Nothing has been sent: this is an outbox row, and the maintenance round
    # delivers it. Nothing external is reachable from a request handler.
    assert body["attempts"] == 0
    assert body["external_id"] is None
    assert _actions(session, AUDIT_TARGET_HANDOFF) == ["handoff.requested"]


def test_a_viewer_cannot_hand_a_finding_over(
    client: TestClient,
    api: str,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
) -> None:
    admin_headers = login_as(make_user(UserRole.ADMIN))
    target = _create_target(client, api, admin_headers)
    headers = login_as(make_user(UserRole.VIEWER))
    finding = make_finding(make_source())

    response = client.post(
        f"{api}/findings/{finding.id}/handoffs",
        json={"target_id": target["id"]},
        headers=headers,
    )

    assert response.status_code == 403


def test_asking_twice_returns_the_same_handoff_and_says_so(
    client: TestClient,
    api: str,
    session: Session,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
) -> None:
    """A second click is the same event, so it gets the same hand-over — and a
    200 rather than a 201, because this call did not create anything."""
    admin_headers = login_as(make_user(UserRole.ADMIN))
    target = _create_target(client, api, admin_headers)
    headers = login_as(make_user(UserRole.ANALYST))
    finding = make_finding(make_source())
    body = {"target_id": target["id"]}

    first = client.post(f"{api}/findings/{finding.id}/handoffs", json=body, headers=headers)
    second = client.post(f"{api}/findings/{finding.id}/handoffs", json=body, headers=headers)

    assert (first.status_code, second.status_code) == (201, 200)
    assert first.json()["id"] == second.json()["id"]
    assert len(session.exec(select(FindingHandoff)).all()) == 1
    # And the audit trail records the decision once, not once per click.
    assert _actions(session, AUDIT_TARGET_HANDOFF) == ["handoff.requested"]


def test_a_racing_duplicate_request_returns_the_existing_handoff(
    client: TestClient,
    api: str,
    session: Session,
    monkeypatch: pytest.MonkeyPatch,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
) -> None:
    """#181. Two transactions can both observe no row and both insert; the unique
    constraint refuses the loser.

    Staged by making the existence check miss, which is exactly what the losing
    transaction observes — it ran its `SELECT` before the winner committed. The
    row is really inserted and the constraint really fires, so this exercises the
    recovery rather than a simulation of it.
    """
    from iceberg_api.handoff import service

    admin_headers = login_as(make_user(UserRole.ADMIN))
    target = _create_target(client, api, admin_headers)
    headers = login_as(make_user(UserRole.ANALYST))
    finding = make_finding(make_source())
    body = {"target_id": target["id"]}

    first = client.post(f"{api}/findings/{finding.id}/handoffs", json=body, headers=headers)
    assert first.status_code == 201, first.text

    real_existing = service._existing
    calls = {"n": 0}

    def blind_once(*args: Any, **kwargs: Any) -> Any:
        # Blind on the pre-insert check only; the post-rollback lookup must see
        # the winner's row, or there would be nothing to return.
        calls["n"] += 1
        return None if calls["n"] == 1 else real_existing(*args, **kwargs)

    monkeypatch.setattr(service, "_existing", blind_once)

    second = client.post(f"{api}/findings/{finding.id}/handoffs", json=body, headers=headers)

    assert second.status_code == 200, second.text
    assert second.json()["id"] == first.json()["id"]
    assert len(session.exec(select(FindingHandoff)).all()) == 1


def test_a_disabled_target_refuses_the_handoff_rather_than_dropping_it(
    client: TestClient,
    api: str,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
) -> None:
    """An operator who pressed the button is owed an answer about why nothing
    happened."""
    admin_headers = login_as(make_user(UserRole.ADMIN))
    target = _create_target(client, api, admin_headers, enabled=False)
    headers = login_as(make_user(UserRole.ANALYST))
    finding = make_finding(make_source())

    response = client.post(
        f"{api}/findings/{finding.id}/handoffs",
        json={"target_id": target["id"]},
        headers=headers,
    )

    assert response.status_code == 409
    assert "disabled" in response.json()["detail"]


def test_a_target_that_does_not_want_this_severity_refuses_it(
    client: TestClient,
    api: str,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
) -> None:
    """The target's own filter, the same one a notification channel applies."""
    admin_headers = login_as(make_user(UserRole.ADMIN))
    target = _create_target(client, api, admin_headers, event_filter={"min_severity": "critical"})
    headers = login_as(make_user(UserRole.ANALYST))
    finding = make_finding(make_source(), severity=Severity.LOW)

    response = client.post(
        f"{api}/findings/{finding.id}/handoffs",
        json={"target_id": target["id"]},
        headers=headers,
    )

    assert response.status_code == 409
    assert "severity" in response.json()["detail"]


def test_a_handoff_for_an_unknown_target_is_a_404(
    client: TestClient,
    api: str,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
) -> None:
    headers = login_as(make_user(UserRole.ANALYST))
    finding = make_finding(make_source())

    response = client.post(
        f"{api}/findings/{finding.id}/handoffs",
        json={"target_id": str(uuid.uuid4())},
        headers=headers,
    )

    assert response.status_code == 404


def test_the_handoffs_of_a_finding_are_listed_with_their_delivery_state(
    client: TestClient,
    api: str,
    session: Session,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
) -> None:
    """ "Did this actually reach anybody?" has to be answerable without a log."""
    admin_headers = login_as(make_user(UserRole.ADMIN))
    target = _create_target(client, api, admin_headers)
    headers = login_as(make_user(UserRole.ANALYST))
    finding = make_finding(make_source())
    client.post(
        f"{api}/findings/{finding.id}/handoffs",
        json={"target_id": target["id"]},
        headers=headers,
    )
    stored = session.exec(select(FindingHandoff)).one()
    stored.status = HandoffStatus.FAILED
    stored.attempts = 5
    stored.last_error = "handoff returned HTTP 500"
    session.add(stored)
    session.commit()

    response = client.get(f"{api}/findings/{finding.id}/handoffs", headers=headers)

    assert response.status_code == 200
    (body,) = response.json()
    assert body["status"] == HandoffStatus.FAILED.value
    assert body["attempts"] == 5
    assert body["last_error"] == "handoff returned HTTP 500"
    assert body["target_name"] == "soar-prod"


# ─── Replay ───────────────────────────────────────────────────────────────────


def test_a_failed_handoff_can_be_replayed(
    client: TestClient,
    api: str,
    session: Session,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
) -> None:
    """Replaying is a new decision, so it gets fresh attempts — and keeps the key,
    because it is still the same hand-over of the same finding."""
    admin_headers = login_as(make_user(UserRole.ADMIN))
    target = _create_target(client, api, admin_headers)
    headers = login_as(make_user(UserRole.ANALYST))
    finding = make_finding(make_source())
    client.post(
        f"{api}/findings/{finding.id}/handoffs",
        json={"target_id": target["id"]},
        headers=headers,
    )
    stored = session.exec(select(FindingHandoff)).one()
    stored.status = HandoffStatus.FAILED
    stored.attempts = 5
    stored.last_error = "receiver down"
    session.add(stored)
    session.commit()
    key = stored.idempotency_key

    replay = f"{api}/findings/{finding.id}/handoffs/{stored.id}/replay"
    response = client.post(replay, headers=headers)

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == HandoffStatus.PENDING.value
    assert body["attempts"] == 0
    assert body["last_error"] is None
    assert body["idempotency_key"] == key
    assert _actions(session, AUDIT_TARGET_HANDOFF) == ["handoff.requested", "handoff.replayed"]


@pytest.mark.parametrize("state", [HandoffStatus.PENDING, HandoffStatus.DELIVERED])
def test_only_a_failed_handoff_can_be_replayed(
    state: HandoffStatus,
    client: TestClient,
    api: str,
    session: Session,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
) -> None:
    """A pending one is already queued. A delivered one has a work item on the
    other side, and replaying it would be asking for the duplicate the whole
    design exists to prevent."""
    admin_headers = login_as(make_user(UserRole.ADMIN))
    target = _create_target(client, api, admin_headers)
    headers = login_as(make_user(UserRole.ANALYST))
    finding = make_finding(make_source())
    client.post(
        f"{api}/findings/{finding.id}/handoffs",
        json={"target_id": target["id"]},
        headers=headers,
    )
    stored = session.exec(select(FindingHandoff)).one()
    stored.status = state
    session.add(stored)
    session.commit()

    replay = f"{api}/findings/{finding.id}/handoffs/{stored.id}/replay"
    response = client.post(replay, headers=headers)

    assert response.status_code == 409
    assert state.value in response.json()["detail"]
