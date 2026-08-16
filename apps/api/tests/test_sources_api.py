"""Source CRUD, credential storage, and the connectivity check (#31, #32)."""

from collections.abc import Callable

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from iceberg_api import audit
from iceberg_api.sources.routes import get_prober
from iceberg_api.sources.schemas import ConnectivityResult
from iceberg_core.enums import SourceType, UserRole
from iceberg_core.models import AUDIT_TARGET_SOURCE, Source, User
from iceberg_core.secrets import EnvKeyBackend
from pydantic import SecretStr
from sqlmodel import Session, select

SOURCES = "/api/v1/sources"
CREDENTIAL = "admin@example.test:confluence-api-token"
CONNECTION = {"base_url": "https://example.atlassian.net/wiki", "spaces": ["ENG"]}


def _payload(**overrides: object) -> dict[str, object]:
    return {
        "name": "confluence-prod",
        "type": "confluence",
        "connection": CONNECTION,
        "credential": CREDENTIAL,
    } | overrides


def _create(client: TestClient, headers: dict[str, str], **overrides: object) -> dict[str, object]:
    response = client.post(SOURCES, json=_payload(**overrides), headers=headers)
    assert response.status_code == 201, response.text
    body: dict[str, object] = response.json()
    return body


def test_an_admin_can_create_a_source(
    client: TestClient,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
    session: Session,
) -> None:
    headers = login_as(make_user(UserRole.ADMIN))

    body = _create(client, headers)

    assert body["name"] == "confluence-prod"
    assert body["type"] == "confluence"
    assert body["enabled"] is True
    assert body["has_credential"] is True
    stored = session.exec(select(Source)).one()
    assert stored.type is SourceType.CONFLUENCE
    assert stored.connection["spaces"] == ["ENG"]


def test_the_credential_is_sealed_and_never_returned(
    client: TestClient,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
    session: Session,
    secret_store: EnvKeyBackend,
) -> None:
    """The row keeps an opaque ref; no response carries either form (ADR 0007)."""
    headers = login_as(make_user(UserRole.ADMIN))

    created = client.post(SOURCES, json=_payload(), headers=headers)
    listed = client.get(SOURCES)
    detail = client.get(f"{SOURCES}/{created.json()['id']}")

    for response in (created, listed, detail):
        assert CREDENTIAL not in response.text
        assert "credential_ref" not in response.text

    stored = session.exec(select(Source)).one()
    assert stored.credential_ref is not None
    assert CREDENTIAL not in stored.credential_ref
    assert secret_store.open(stored.credential_ref).get_secret_value() == CREDENTIAL


def test_a_source_can_be_created_without_a_credential(
    client: TestClient,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    headers = login_as(make_user(UserRole.ADMIN))

    body = _create(client, headers, credential=None)

    assert body["has_credential"] is False


@pytest.mark.parametrize("role", [UserRole.ANALYST, UserRole.VIEWER])
def test_only_an_admin_can_create_a_source(
    client: TestClient,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
    role: UserRole,
) -> None:
    headers = login_as(make_user(role))

    assert client.post(SOURCES, json=_payload(), headers=headers).status_code == 403


def test_any_authenticated_role_can_read_sources(
    client: TestClient,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """An analyst triaging a finding needs to know where it came from."""
    admin_headers = login_as(make_user(UserRole.ADMIN))
    created = _create(client, admin_headers)

    login_as(make_user(UserRole.VIEWER))
    assert client.get(SOURCES).status_code == 200
    assert client.get(f"{SOURCES}/{created['id']}").status_code == 200


def test_reading_sources_requires_a_session(client: TestClient) -> None:
    assert client.get(SOURCES).status_code == 401


def test_creating_a_source_requires_a_csrf_token(
    client: TestClient,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
    session: Session,
) -> None:
    login_as(make_user(UserRole.ADMIN))

    assert client.post(SOURCES, json=_payload()).status_code == 403
    assert session.exec(select(Source)).all() == []


def test_duplicate_names_are_refused(
    client: TestClient,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    headers = login_as(make_user(UserRole.ADMIN))
    _create(client, headers)

    assert client.post(SOURCES, json=_payload(), headers=headers).status_code == 409


@pytest.mark.parametrize(
    "connection",
    [
        {"base_url": "example.atlassian.net"},  # no scheme
        {"base_url": "https://example.test", "spaces": ["ENG", "ENG"]},  # repeated
        {"base_url": "https://example.test", "spaces": ["DOCS", "docs"]},
        {"spaces": ["ENG"]},  # no base_url
        {"base_url": "https://example.test", "unexpected": True},  # typo'd key
    ],
)
def test_a_malformed_connection_is_refused_at_save_time(
    client: TestClient,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
    connection: dict[str, object],
) -> None:
    """A bad base_url should fail here, not hours later inside a scan task."""
    headers = login_as(make_user(UserRole.ADMIN))

    response = client.post(SOURCES, json=_payload(connection=connection), headers=headers)

    assert response.status_code == 422


def test_every_connection_key_the_connector_reads_is_storable(
    client: TestClient,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """The documented Cloud configuration — bare token, ``email`` in the blob —
    plus every scope toggle the connector honours. ``extra="forbid"`` means a key
    missing from the schema is one no admin can store, which for ``email`` made
    Cloud auth unconfigurable (docs/connectors.md § Auth)."""
    headers = login_as(make_user(UserRole.ADMIN))

    body = _create(
        client,
        headers,
        connection={
            "base_url": "https://example.atlassian.net/wiki",
            "email": "admin@example.test",
            "api_prefix": "/wiki/api/v2",
            "spaces": ["ENG"],
            "include_comments": False,
            "include_attachments": False,
            "include_personal_spaces": True,
        },
    )

    connection = body["connection"]
    assert isinstance(connection, dict)
    assert connection["email"] == "admin@example.test"
    assert connection["api_prefix"] == "/wiki/api/v2"
    assert connection["include_comments"] is False
    assert connection["include_personal_spaces"] is True


def test_an_api_prefix_missing_its_leading_slash_is_refused(
    client: TestClient,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """The client builds URLs as base_url + api_prefix + path; a relative prefix
    would fail hours later inside a scan task instead of at save time."""
    headers = login_as(make_user(UserRole.ADMIN))

    response = client.post(
        SOURCES,
        json=_payload(connection={"base_url": "https://example.test", "api_prefix": "wiki/api/v2"}),
        headers=headers,
    )

    assert response.status_code == 422


def test_a_trailing_slash_in_the_base_url_is_normalised(
    client: TestClient,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    headers = login_as(make_user(UserRole.ADMIN))

    body = _create(client, headers, connection={"base_url": "https://example.atlassian.net/wiki/"})

    assert body["connection"]["base_url"] == "https://example.atlassian.net"  # type: ignore[index]


def test_every_source_type_the_api_offers_has_a_connection_schema() -> None:
    """The refusal path below is for a type that has not shipped yet. Today every
    member has a model, and this is what fails on the day one does not — before an
    admin can create a source nothing is able to scan."""
    from iceberg_api.sources.schemas import CONNECTION_MODELS, SUPPORTED_SOURCE_TYPES

    assert set(CONNECTION_MODELS) == set(SourceType) == SUPPORTED_SOURCE_TYPES


def test_a_connector_that_has_not_shipped_is_refused_with_an_explanation(
    monkeypatch: pytest.MonkeyPatch,
    client: TestClient,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """A source nothing can scan is worse than a clear refusal. Every shipped type
    has a schema, so the unshipped one is simulated — the alternative is deleting
    the guard that will catch the next connector."""
    from iceberg_api.sources import schemas

    monkeypatch.delitem(schemas.CONNECTION_MODELS, SourceType.JIRA)
    headers = login_as(make_user(UserRole.ADMIN))

    response = client.post(SOURCES, json=_payload(type="jira"), headers=headers)

    assert response.status_code == 422
    assert "not available yet" in response.text


def test_a_jira_source_can_be_created_with_its_own_scope_options(
    client: TestClient,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    headers = login_as(make_user(UserRole.ADMIN))

    response = client.post(
        SOURCES,
        json=_payload(
            type="jira",
            connection={
                "base_url": "https://example.atlassian.net",
                "email": "scanner@example.test",
                "projects": ["ENG", "OPS"],
                "include_history": True,
            },
        ),
        headers=headers,
    )

    assert response.status_code == 201, response.text
    connection = response.json()["connection"]
    assert connection["projects"] == ["ENG", "OPS"]
    assert connection["include_history"] is True
    # Defaulted rather than omitted, so an engine never has to guess.
    assert connection["include_archived_projects"] is False


def test_a_jira_source_refuses_a_project_key_that_could_reach_jql(
    client: TestClient,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """A 422 at save time beats a failed scan hours later."""
    headers = login_as(make_user(UserRole.ADMIN))

    response = client.post(
        SOURCES,
        json=_payload(
            type="jira",
            connection={
                "base_url": "https://example.atlassian.net",
                "projects": ['ENG" OR project = "OPS'],
            },
        ),
        headers=headers,
    )

    assert response.status_code == 422


def test_a_jira_source_refuses_a_free_text_jql_field(
    client: TestClient,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """`extra="forbid"` is what keeps operator query text out of the scan's own
    query, which would break both discovery determinism and scope reconciliation."""
    headers = login_as(make_user(UserRole.ADMIN))

    response = client.post(
        SOURCES,
        json=_payload(
            type="jira",
            connection={
                "base_url": "https://example.atlassian.net",
                "jql_filter": "project = ENG",
            },
        ),
        headers=headers,
    )

    assert response.status_code == 422


def test_updating_a_source_records_what_changed(
    client: TestClient,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
    session: Session,
) -> None:
    admin = make_user(UserRole.ADMIN)
    headers = login_as(admin)
    created = _create(client, headers)

    response = client.patch(
        f"{SOURCES}/{created['id']}", json={"name": "renamed", "enabled": False}, headers=headers
    )

    assert response.status_code == 200
    assert response.json()["name"] == "renamed"
    assert response.json()["enabled"] is False

    events = audit.events_for(session, AUDIT_TARGET_SOURCE, session.exec(select(Source)).one().id)
    assert [event.action for event in events] == [
        "source.created",
        "source.credential_set",
        "source.updated",
    ]
    assert events[-1].to_value == "name,enabled"


def test_rotating_a_credential_is_its_own_audited_action(
    client: TestClient,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
    session: Session,
    secret_store: EnvKeyBackend,
) -> None:
    headers = login_as(make_user(UserRole.ADMIN))
    created = _create(client, headers)
    original_ref = session.exec(select(Source)).one().credential_ref

    response = client.patch(
        f"{SOURCES}/{created['id']}", json={"credential": "rotated-token"}, headers=headers
    )

    assert response.status_code == 200
    source = session.exec(select(Source)).one()
    session.refresh(source)
    assert source.credential_ref != original_ref
    assert source.credential_ref is not None
    assert secret_store.open(source.credential_ref).get_secret_value() == "rotated-token"

    actions = [event.action for event in audit.events_for(session, AUDIT_TARGET_SOURCE, source.id)]
    assert actions == ["source.created", "source.credential_set", "source.credential_rotated"]


def test_a_blank_credential_is_refused(
    client: TestClient,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    headers = login_as(make_user(UserRole.ADMIN))
    created = _create(client, headers)

    response = client.patch(
        f"{SOURCES}/{created['id']}", json={"credential": "   "}, headers=headers
    )

    assert response.status_code == 422


def test_deleting_a_source_is_audited(
    client: TestClient,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
    session: Session,
) -> None:
    headers = login_as(make_user(UserRole.ADMIN))
    created = _create(client, headers)
    source_id = session.exec(select(Source)).one().id

    response = client.delete(f"{SOURCES}/{created['id']}", headers=headers)

    assert response.status_code == 204
    assert session.exec(select(Source)).all() == []
    actions = [event.action for event in audit.events_for(session, AUDIT_TARGET_SOURCE, source_id)]
    assert actions[-1] == "source.deleted"


def test_unknown_sources_are_404(
    client: TestClient,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    headers = login_as(make_user(UserRole.ADMIN))
    missing = "00000000-0000-4000-8000-000000000000"

    assert client.get(f"{SOURCES}/{missing}").status_code == 404
    assert (
        client.patch(f"{SOURCES}/{missing}", json={"enabled": False}, headers=headers).status_code
        == 404
    )
    assert client.delete(f"{SOURCES}/{missing}", headers=headers).status_code == 404


def test_sources_paginate_with_a_stable_cursor(
    client: TestClient,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    headers = login_as(make_user(UserRole.ADMIN))
    for index in range(5):
        _create(client, headers, name=f"source-{index}")

    seen: list[str] = []
    cursor: str | None = None
    for _ in range(10):
        params = {"limit": 2} | ({"cursor": cursor} if cursor else {})
        body = client.get(SOURCES, params=params).json()
        seen.extend(item["id"] for item in body["items"])
        cursor = body["next_cursor"]
        if cursor is None:
            break

    assert len(seen) == len(set(seen)) == 5


@pytest.mark.parametrize(
    "cursor",
    [
        "not-base64!",
        "W10",  # base64 of `[]` — decodes, then fails subscripting
        "bnVsbA",  # base64 of `null`
    ],
)
def test_a_malformed_cursor_is_a_400_not_a_500(
    client: TestClient,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
    cursor: str,
) -> None:
    login_as(make_user(UserRole.VIEWER))

    response = client.get(SOURCES, params={"cursor": cursor})

    assert response.status_code == 400


def test_the_documented_base_url_is_the_site_root(
    client: TestClient,
    session: Session,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """The connector appends its own context path.

    `base_url` is stored verbatim and the Confluence client builds requests as
    ``base_url + api_prefix``, with ``/wiki/api/v2`` the Cloud default — so an
    operator following the field's documented example must be given the site
    root. The example used to carry ``/wiki`` and yielded ``/wiki/wiki/api/v2``.
    """
    headers = login_as(make_user(UserRole.ADMIN))

    response = client.post(
        SOURCES,
        json=_payload(connection={"base_url": "https://example.atlassian.net"}),
        headers=headers,
    )

    assert response.status_code == 201
    stored = session.exec(select(Source)).one()
    assert stored.connection["base_url"] == "https://example.atlassian.net"
    # Unset, so the connector's own default prefix applies exactly once.
    assert stored.connection["api_prefix"] is None


def test_the_connectivity_check_reports_success(
    client: TestClient,
    app: FastAPI,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    headers = login_as(make_user(UserRole.ADMIN))
    created = _create(client, headers)
    seen: list[str] = []

    async def fake_prober(source: Source, credential: SecretStr) -> ConnectivityResult:
        # Proves the route hands the prober the *decrypted* credential.
        seen.append(credential.get_secret_value())
        return ConnectivityResult(reachable=True, status_code=200, detail="ok")

    app.dependency_overrides[get_prober] = lambda: fake_prober

    response = client.post(f"{SOURCES}/{created['id']}/test", headers=headers)

    assert response.status_code == 200
    assert response.json()["reachable"] is True
    assert seen == [CREDENTIAL]


def test_the_connectivity_check_needs_a_stored_credential(
    client: TestClient,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    headers = login_as(make_user(UserRole.ADMIN))
    created = _create(client, headers, credential=None)

    response = client.post(f"{SOURCES}/{created['id']}/test", headers=headers)

    assert response.status_code == 409


@pytest.mark.parametrize("role", [UserRole.ANALYST, UserRole.VIEWER])
def test_the_connectivity_check_is_admin_only(
    client: TestClient,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
    session: Session,
    role: UserRole,
) -> None:
    """It sends a real credential to an operator-supplied URL."""
    admin_headers = login_as(make_user(UserRole.ADMIN))
    created = _create(client, admin_headers)

    headers = login_as(make_user(role))
    response = client.post(f"{SOURCES}/{created['id']}/test", headers=headers)

    assert response.status_code == 403


def test_a_credential_that_will_not_decrypt_is_reported_clearly(
    client: TestClient,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
    session: Session,
) -> None:
    """A rotated master key or a tampered row should say so, not 500 opaquely."""
    headers = login_as(make_user(UserRole.ADMIN))
    created = _create(client, headers)
    source = session.exec(select(Source)).one()
    source.credential_ref = "envkey:1:credential:this-will-not-open"
    session.commit()

    response = client.post(f"{SOURCES}/{created['id']}/test", headers=headers)

    assert response.status_code == 500
    assert "re-enter" in response.text
