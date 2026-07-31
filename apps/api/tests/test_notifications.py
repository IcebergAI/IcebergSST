"""Notification-channel CRUD (#72).

A webhook channel is a deliberate egress path — it carries redacted snippets and
resource locations off the deployment — so these tests care about three things
above all: only an admin may configure one, the secret that signs its payloads is
sealed and never returned, and every change is in the audit trail with the
destination it went to.
"""

import uuid
from collections.abc import Callable
from typing import Any

import pytest
from fastapi.testclient import TestClient
from iceberg_core.enums import NotificationChannelType, UserRole
from iceberg_core.models import AUDIT_TARGET_CHANNEL, AuditEvent, NotificationChannel, User
from sqlmodel import Session, select

WEBHOOK = {
    "name": "security-alerts",
    "type": "webhook",
    "config": {"url": "https://chat.example.com/hooks/abc"},
    "secret": "payload-signing-secret",
    "event_filter": {"min_severity": "high"},
}


def _create(
    client: TestClient, api: str, headers: dict[str, str], **overrides: object
) -> dict[str, Any]:
    response = client.post(
        f"{api}/notifications/channels", json=WEBHOOK | overrides, headers=headers
    )
    assert response.status_code == 201, response.text
    created: dict[str, Any] = response.json()
    return created


def test_an_admin_can_create_a_webhook_channel(
    client: TestClient,
    api: str,
    session: Session,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    headers = login_as(make_user(UserRole.ADMIN))

    body = _create(client, api, headers)

    assert body["name"] == "security-alerts"
    assert body["type"] == NotificationChannelType.WEBHOOK.value
    assert body["config"]["url"] == "https://chat.example.com/hooks/abc"
    assert body["event_filter"]["min_severity"] == "high"
    assert body["has_secret"] is True

    channel = session.exec(select(NotificationChannel)).one()
    assert channel.config["secret_ref"]
    assert "payload-signing-secret" not in str(channel.config)


def test_no_response_carries_the_secret_or_its_sealed_ref(
    client: TestClient,
    api: str,
    session: Session,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """A ref plus a leaked master key is a credential; no client needs one."""
    headers = login_as(make_user(UserRole.ADMIN))
    created = _create(client, api, headers)
    ref = session.exec(select(NotificationChannel)).one().config["secret_ref"]

    listed = client.get(f"{api}/notifications/channels", headers=headers)
    read = client.get(f"{api}/notifications/channels/{created['id']}", headers=headers)

    for response in (listed, read):
        assert "payload-signing-secret" not in response.text
        assert ref not in response.text
        assert "secret_ref" not in response.text


@pytest.mark.parametrize("role", [UserRole.VIEWER, UserRole.ANALYST])
def test_only_an_admin_may_read_or_write_channels(
    client: TestClient,
    api: str,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
    role: UserRole,
) -> None:
    """Configuring an egress path is an operator action (ADR 0005)."""
    headers = login_as(make_user(role))

    assert client.get(f"{api}/notifications/channels", headers=headers).status_code == 403
    assert (
        client.post(f"{api}/notifications/channels", json=WEBHOOK, headers=headers).status_code
        == 403
    )


def test_an_unauthenticated_caller_gets_401_not_403(client: TestClient, api: str) -> None:
    assert client.get(f"{api}/notifications/channels").status_code == 401


def test_a_mutation_without_a_csrf_token_is_refused(
    client: TestClient,
    api: str,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    login_as(make_user(UserRole.ADMIN))

    response = client.post(f"{api}/notifications/channels", json=WEBHOOK)

    assert response.status_code == 403


def test_a_webhook_url_must_be_an_absolute_http_url(
    client: TestClient,
    api: str,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """A bad URL fails when the channel is saved, not at 3am on a critical finding."""
    headers = login_as(make_user(UserRole.ADMIN))

    response = client.post(
        f"{api}/notifications/channels",
        json=WEBHOOK | {"config": {"url": "chat.example.com/hooks/abc"}},
        headers=headers,
    )

    assert response.status_code == 422
    assert "http://" in response.text


def test_a_credential_carrying_header_is_refused_with_a_pointer_at_secret(
    client: TestClient,
    api: str,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """Headers are stored as plain JSON. A token in one is a plaintext secret at
    rest — the exact thing this product exists to find in other systems."""
    headers = login_as(make_user(UserRole.ADMIN))

    response = client.post(
        f"{api}/notifications/channels",
        json=WEBHOOK
        | {
            "config": {
                "url": "https://chat.example.com/hooks/abc",
                "headers": {"Authorization": "Bearer hunter2"},
            }
        },
        headers=headers,
    )

    assert response.status_code == 422
    assert "secret" in response.text


def test_a_header_value_cannot_smuggle_a_line_break(
    client: TestClient,
    api: str,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    headers = login_as(make_user(UserRole.ADMIN))

    response = client.post(
        f"{api}/notifications/channels",
        json=WEBHOOK
        | {
            "config": {
                "url": "https://chat.example.com/hooks/abc",
                "headers": {"X-Route": "a\r\nX-Injected: b"},
            }
        },
        headers=headers,
    )

    assert response.status_code == 422


def test_a_caller_supplied_secret_ref_is_dropped(
    client: TestClient,
    api: str,
    session: Session,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """The ref is minted here. Accepting one would let a caller point a channel
    at another object's sealed material."""
    headers = login_as(make_user(UserRole.ADMIN))

    _create(
        client,
        api,
        headers,
        config={"url": "https://chat.example.com/hooks/abc", "secret_ref": "somebody-elses-ref"},
        secret=None,
    )

    channel = session.exec(select(NotificationChannel)).one()
    assert "secret_ref" not in channel.config


def test_an_email_channel_validates_its_recipients(
    client: TestClient,
    api: str,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    headers = login_as(make_user(UserRole.ADMIN))

    good = client.post(
        f"{api}/notifications/channels",
        json={
            "name": "secops-mail",
            "type": "email",
            "config": {"recipients": ["secops@example.com"]},
        },
        headers=headers,
    )
    bad = client.post(
        f"{api}/notifications/channels",
        json={"name": "broken", "type": "email", "config": {"recipients": ["not-an-address"]}},
        headers=headers,
    )

    assert good.status_code == 201
    assert bad.status_code == 422


def test_a_duplicate_name_is_a_conflict(
    client: TestClient,
    api: str,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    headers = login_as(make_user(UserRole.ADMIN))
    _create(client, api, headers)

    response = client.post(f"{api}/notifications/channels", json=WEBHOOK, headers=headers)

    assert response.status_code == 409


def test_editing_the_config_keeps_the_sealed_secret(
    client: TestClient,
    api: str,
    session: Session,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """Fixing a typo in a URL is not a request to drop the signing key."""
    headers = login_as(make_user(UserRole.ADMIN))
    created = _create(client, api, headers)
    original_ref = session.exec(select(NotificationChannel)).one().config["secret_ref"]

    response = client.patch(
        f"{api}/notifications/channels/{created['id']}",
        json={"config": {"url": "https://chat.example.com/hooks/def"}},
        headers=headers,
    )

    assert response.status_code == 200
    assert response.json()["has_secret"] is True
    channel = session.exec(select(NotificationChannel)).one()
    assert channel.config["url"].endswith("/def")
    assert channel.config["secret_ref"] == original_ref


def test_supplying_a_secret_rotates_it_and_records_a_separate_event(
    client: TestClient,
    api: str,
    session: Session,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    headers = login_as(make_user(UserRole.ADMIN))
    created = _create(client, api, headers)
    original_ref = session.exec(select(NotificationChannel)).one().config["secret_ref"]

    response = client.patch(
        f"{api}/notifications/channels/{created['id']}",
        json={"secret": "a-rotated-secret"},
        headers=headers,
    )

    assert response.status_code == 200
    channel = session.exec(select(NotificationChannel)).one()
    assert channel.config["secret_ref"] != original_ref

    actions = [
        event.action
        for event in session.exec(
            select(AuditEvent).where(AuditEvent.target_type == AUDIT_TARGET_CHANNEL)
        )
    ]
    # "who changed this channel" and "who replaced its key" are different questions.
    assert actions.count("channel.secret_set") == 2


def test_a_channel_can_be_disabled_without_being_deleted(
    client: TestClient,
    api: str,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    headers = login_as(make_user(UserRole.ADMIN))
    created = _create(client, api, headers)

    response = client.patch(
        f"{api}/notifications/channels/{created['id']}", json={"enabled": False}, headers=headers
    )

    assert response.status_code == 200
    assert response.json()["enabled"] is False


def test_creating_and_deleting_records_the_destination_never_the_secret(
    client: TestClient,
    api: str,
    session: Session,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """ "Who pointed our findings at that URL" must always have an answer."""
    headers = login_as(make_user(UserRole.ADMIN))
    created = _create(client, api, headers)

    assert (
        client.delete(f"{api}/notifications/channels/{created['id']}", headers=headers).status_code
        == 204
    )

    events = list(
        session.exec(select(AuditEvent).where(AuditEvent.target_type == AUDIT_TARGET_CHANNEL))
    )
    actions = {event.action for event in events}
    assert {"channel.created", "channel.secret_set", "channel.deleted"} == actions
    destinations = {
        event.detail.get("destination") for event in events if "destination" in event.detail
    }
    assert destinations == {"https://chat.example.com/hooks/abc"}
    assert all("payload-signing-secret" not in str(event.detail) for event in events)


def test_reading_an_unknown_channel_is_a_404(
    client: TestClient,
    api: str,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    headers = login_as(make_user(UserRole.ADMIN))

    response = client.get(f"{api}/notifications/channels/{uuid.uuid4()}", headers=headers)

    assert response.status_code == 404
