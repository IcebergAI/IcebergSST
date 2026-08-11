"""Hermetic proof of the controlled Confluence pilot through real boundaries.

The only doubles are the systems outside IcebergSST: a signed OIDC provider, a
Confluence-shaped HTTP endpoint, the Redis dispatcher, and a webhook receiver.
Authentication, RBAC/CSRF, engine leases, connector/detection/redaction, API
ingest, SQLite persistence, triage/audit, and the notification outbox/transport
are the shipped components.
"""

import hmac
import json
import sys
import uuid
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import httpx2
from conftest import RecordingDispatcher
from fastapi import FastAPI
from fastapi.testclient import TestClient
from iceberg_api.auth.oidc import pkce_challenge
from iceberg_api.notifications import dispatch
from iceberg_api.notifications.transports import (
    SIGNATURE_HEADER,
    TIMESTAMP_HEADER,
    WebhookTransport,
    sign,
)
from iceberg_core.config import ApiSettings
from iceberg_core.enums import (
    FindingState,
    NotificationChannelType,
    NotificationDeliveryStatus,
    ScanStatus,
)
from iceberg_core.models import (
    AuditEvent,
    Finding,
    FindingEvent,
    NotificationDelivery,
    Scan,
    User,
)
from iceberg_core.secrets import EnvKeyBackend
from iceberg_detect import load_named_pack
from iceberg_engine.api_client import EngineClient
from iceberg_engine.runner import run_task
from oidc_provider import BOOTSTRAP_SUBJECT, FakeProvider
from sqlmodel import Session, col, select
from structlog.testing import capture_logs

sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[3] / "packages/connectors/tests"),
)

from confluence_server import (  # after the connector-fixture path insert
    API_TOKEN,
    EMAIL,
    SEEDED_SECRET,
    SITE,
    Attachment,
    Comment,
    FakeConfluence,
    Page,
    Space,
    leaky_page_storage,
    storage_page,
)
from iceberg_connectors import ConfluenceConnector, registry

PACK = load_named_pack()
WEBHOOK_SECRET = "controlled-pilot-signing-key"
PRIVATE_TRIAGE_NOTE = "internal owner confirmed a controlled exception"


class AppTransport:
    """Carry EngineClient traffic through a cookie-free real TestClient."""

    def __init__(self, client: TestClient) -> None:
        self.client = client
        self.results_requests: list[bytes] = []
        self.lease_responses: list[bytes] = []

    def __call__(self, request: httpx2.Request) -> httpx2.Response:
        if request.url.path.endswith("/results"):
            self.results_requests.append(request.content)
        upstream = self.client.request(
            request.method,
            request.url.path,
            params=list(request.url.params.multi_items()),
            headers=dict(request.headers),
            content=request.content,
        )
        if request.url.path.endswith("/lease"):
            self.lease_responses.append(upstream.content)
        return httpx2.Response(
            upstream.status_code,
            headers=dict(upstream.headers),
            content=upstream.content,
            request=request,
        )


class WebhookSink:
    """A local HTTP receiver that records the actual webhook request bytes."""

    def __init__(self) -> None:
        self.requests: list[httpx2.Request] = []

    def __call__(self, request: httpx2.Request) -> httpx2.Response:
        self.requests.append(request)
        return httpx2.Response(204)


def _login_admin(client: TestClient, provider: FakeProvider) -> dict[str, str]:
    started = client.get("/api/v1/auth/login", follow_redirects=False)
    query = parse_qs(urlparse(started.headers["location"]).query)
    assert query["code_challenge_method"] == ["S256"]
    provider.id_token = provider.mint_id_token(
        subject=BOOTSTRAP_SUBJECT,
        nonce=query["nonce"][0],
        email=EMAIL,
    )
    completed = client.get(
        "/api/v1/auth/callback",
        params={"code": "controlled-pilot-code", "state": query["state"][0]},
        follow_redirects=False,
    )
    assert completed.status_code == 303
    assert provider.token_requests
    assert (
        pkce_challenge(provider.token_requests[-1]["code_verifier"]) == query["code_challenge"][0]
    )
    me = client.get("/api/v1/auth/me")
    assert me.status_code == 200
    assert me.json()["user"]["role"] == "admin"
    return {"X-CSRF-Token": str(me.json()["csrf_token"])}


def _create_source(
    client: TestClient,
    headers: dict[str, str],
    *,
    public_responses: list[bytes] | None = None,
) -> uuid.UUID:
    response = client.post(
        "/api/v1/sources",
        headers=headers,
        json={
            "name": "controlled-pilot",
            "type": "confluence",
            "connection": {
                "base_url": SITE,
                "email": EMAIL,
                "spaces": ["DOCS"],
                "include_comments": True,
                "include_attachments": True,
            },
            "credential": API_TOKEN,
        },
    )
    assert response.status_code == 201, response.text
    if public_responses is not None:
        public_responses.append(response.content)
    return uuid.UUID(response.json()["id"])


def _create_channel(
    client: TestClient,
    headers: dict[str, str],
    *,
    public_responses: list[bytes] | None = None,
) -> None:
    response = client.post(
        "/api/v1/notifications/channels",
        headers=headers,
        json={
            "name": "controlled-pilot-sink",
            "type": "webhook",
            "config": {"url": "https://sink.example.test/events"},
            "secret": WEBHOOK_SECRET,
            "event_filter": {"min_severity": "high"},
        },
    )
    assert response.status_code == 201, response.text
    if public_responses is not None:
        public_responses.append(response.content)


def _register_engine(
    client: TestClient,
    headers: dict[str, str],
) -> tuple[uuid.UUID, str, bytes]:
    response = client.post(
        "/api/v1/engines/register",
        headers=headers,
        json={"name": "controlled-pilot-engine", "version": "test"},
    )
    assert response.status_code == 201, response.text
    return (
        uuid.UUID(response.json()["engine_id"]),
        str(response.json()["token"]),
        response.content,
    )


def _run_scan(
    client: TestClient,
    headers: dict[str, str],
    source_id: uuid.UUID,
    dispatcher: RecordingDispatcher,
    engine: EngineClient,
    *,
    public_responses: list[bytes] | None = None,
) -> uuid.UUID:
    before = len(dispatcher.enqueued)
    triggered = client.post(f"/api/v1/sources/{source_id}/scan", headers=headers)
    assert triggered.status_code == 202, triggered.text
    if public_responses is not None:
        public_responses.append(triggered.content)
    scan_id = uuid.UUID(triggered.json()["id"])
    assert len(dispatcher.enqueued) == before + 1

    discovery = run_task(dispatcher.enqueued[before], client=engine, pack=PACK)
    assert discovery is not None
    fetch_ids = list(dispatcher.enqueued[before + 1 :])
    assert len(fetch_ids) == 1
    for task_id in fetch_ids:
        assert run_task(task_id, client=engine, pack=PACK) is not None
    return scan_id


def _database_dump(session: Session) -> str:
    wrapped = session.connection().connection
    driver = getattr(wrapped, "driver_connection", wrapped)
    return "\n".join(driver.iterdump())


def _assert_absent(needle: str, values: list[bytes | str]) -> None:
    assert all(
        needle not in (value.decode() if isinstance(value, bytes) else value) for value in values
    )


def test_controlled_pilot_from_oidc_login_to_triage_and_signed_notification(
    app: FastAPI,
    client: TestClient,
    provider: FakeProvider,
    session: Session,
    dispatcher: RecordingDispatcher,
    api_settings: ApiSettings,
    secret_store: EnvKeyBackend,
) -> None:
    """One production-shaped happy path, without a credential or auth bypass."""
    headers = _login_admin(client, provider)
    public_responses: list[bytes] = []
    with capture_logs() as setup_logs:
        source_id = _create_source(client, headers, public_responses=public_responses)
        _create_channel(client, headers, public_responses=public_responses)
        engine_id, engine_token, engine_registration = _register_engine(client, headers)
    footer = Comment(
        "f0",
        storage_page("footer discussion"),
        replies=[Comment("f1", storage_page(f"nested footer key {SEEDED_SECRET}"))],
    )
    inline = Comment(
        "i0",
        storage_page("inline discussion"),
        inline=True,
        replies=[
            Comment(
                "i1",
                storage_page("nested inline discussion"),
                inline=True,
                replies=[
                    Comment(
                        "i2",
                        storage_page(f"deep inline key {SEEDED_SECRET}"),
                        inline=True,
                    )
                ],
            )
        ],
    )
    site = FakeConfluence(
        spaces=[
            Space(
                "s1",
                "DOCS",
                "Documentation",
                pages=[
                    Page(
                        "p1",
                        "Runbook",
                        leaky_page_storage(),
                        comments=[footer, inline],
                        attachments=[
                            Attachment(
                                "deploy.env",
                                f"AWS_ACCESS_KEY_ID={SEEDED_SECRET}".encode(),
                            )
                        ],
                    )
                ],
            )
        ]
    )
    registry.clear()
    registry.register(
        ConfluenceConnector(transport=site.transport(), sleep=lambda _s: None, sandbox_factory=None)
    )

    with TestClient(app, base_url="http://testserver") as engine_http:
        bridge = AppTransport(engine_http)
        engine = EngineClient(
            base_url="http://api.test",
            token=engine_token,
            engine_id=engine_id,
            transport=httpx2.MockTransport(bridge),
            sleep=lambda _s: None,
        )
        try:
            with capture_logs() as first_scan_logs:
                first_scan_id = _run_scan(
                    client,
                    headers,
                    source_id,
                    dispatcher,
                    engine,
                    public_responses=public_responses,
                )
            # Human routes ignore engine bearer tokens; the two auth domains do
            # not become interchangeable just because they share an API origin.
            human_route = engine_http.get(
                "/api/v1/findings",
                headers={"Authorization": f"Bearer {engine_token}"},
            )
            assert human_route.status_code == 401
        finally:
            engine.close()
            registry.clear()

    findings = list(session.exec(select(Finding)))
    assert len(findings) == 4
    expected_locators = {
        ("p1", None, "body"),
        ("p1", "comment:f1", "comment"),
        ("p1", "comment:i2", "comment"),
        ("p1", "attachment:deploy.env", "attachment"),
    }
    assert {
        (
            item.resource_locator["resource_id"],
            item.resource_locator["sub_resource"],
            item.resource_locator["origin"],
        )
        for item in findings
    } == expected_locators
    original_identities = {
        (
            item.resource_locator["resource_id"],
            item.resource_locator["sub_resource"],
            item.resource_locator["origin"],
        ): (item.id, item.fingerprint, item.first_seen_scan_id)
        for item in findings
    }
    finding = next(item for item in findings if item.resource_locator["origin"] == "body")
    first_scan = session.get(Scan, first_scan_id)
    assert first_scan is not None and first_scan.status is ScanStatus.COMPLETED
    deliveries = list(session.exec(select(NotificationDelivery)))
    assert len(deliveries) == 4
    assert all(item.status is NotificationDeliveryStatus.PENDING for item in deliveries)

    # Human list/detail surfaces belong in the same no-plaintext proof as writes.
    for path in [
        f"/api/v1/sources/{source_id}",
        f"/api/v1/scans/{first_scan_id}",
        "/api/v1/findings",
        *(f"/api/v1/findings/{item.id}" for item in findings),
    ]:
        response = client.get(path)
        assert response.status_code == 200, response.text
        public_responses.append(response.content)

    admin = session.exec(select(User).where(col(User.oidc_subject) == BOOTSTRAP_SUBJECT)).one()
    sink = WebhookSink()
    webhook = WebhookTransport(
        api_settings,
        secret_store,
        transport=httpx2.MockTransport(sink),
    )
    with capture_logs() as triage_delivery_logs:
        triaged = client.patch(
            f"/api/v1/findings/{finding.id}",
            headers=headers,
            json={
                "state": "accepted_risk",
                "assignee_id": str(admin.id),
                "notes": PRIVATE_TRIAGE_NOTE,
                "comment": "owned by the platform team",
            },
        )
        assert triaged.status_code == 200, triaged.text
        public_responses.append(triaged.content)

        delivered = dispatch.deliver_pending(
            session,
            api_settings,
            secret_store,
            transports={NotificationChannelType.WEBHOOK: webhook},
        )
    assert delivered.delivered == 4
    assert len(sink.requests) == 4
    for webhook_request in sink.requests:
        timestamp = webhook_request.headers[TIMESTAMP_HEADER]
        signature = webhook_request.headers[SIGNATURE_HEADER]
        assert hmac.compare_digest(
            signature,
            sign(webhook_request.content, WEBHOOK_SECRET, timestamp),
        )
        payload = webhook_request.content.decode()
        assert SEEDED_SECRET not in payload
        assert API_TOKEN not in payload
        assert WEBHOOK_SECRET not in payload
        assert PRIVATE_TRIAGE_NOTE not in payload
        assert str(admin.id) not in payload
        assert "assignee_id" not in payload
        assert '"notes"' not in payload

    events = list(
        session.exec(select(FindingEvent).where(col(FindingEvent.finding_id) == finding.id))
    )
    assert {event.kind.value for event in events} == {
        "assign",
        "comment",
        "state_change",
    }
    assert all(event.actor_id == admin.id for event in events)
    assert finding.state is FindingState.ACCEPTED_RISK
    assert finding.assignee_id == admin.id
    assert finding.notes == PRIVATE_TRIAGE_NOTE

    audit_events = list(
        session.exec(select(AuditEvent).where(col(AuditEvent.actor_id) == admin.id))
    )
    assert {
        "channel.created",
        "channel.secret_set",
        "engine.registered",
        "source.created",
        "source.credential_set",
    } <= {event.action for event in audit_events}

    registry.register(
        ConfluenceConnector(transport=site.transport(), sleep=lambda _s: None, sandbox_factory=None)
    )
    with TestClient(app, base_url="http://testserver") as engine_http:
        bridge_again = AppTransport(engine_http)
        engine = EngineClient(
            base_url="http://api.test",
            token=engine_token,
            engine_id=engine_id,
            transport=httpx2.MockTransport(bridge_again),
            sleep=lambda _s: None,
        )
        try:
            with capture_logs() as second_scan_logs:
                second_scan_id = _run_scan(
                    client,
                    headers,
                    source_id,
                    dispatcher,
                    engine,
                    public_responses=public_responses,
                )
        finally:
            engine.close()
            registry.clear()

    rescanned_findings = list(session.exec(select(Finding)))
    rescanned_identities = {
        (
            item.resource_locator["resource_id"],
            item.resource_locator["sub_resource"],
            item.resource_locator["origin"],
        ): (item.id, item.fingerprint, item.first_seen_scan_id)
        for item in rescanned_findings
    }
    assert rescanned_identities == original_identities
    session.refresh(finding)
    assert finding.state is FindingState.ACCEPTED_RISK
    assert finding.assignee_id == admin.id
    assert finding.notes == PRIVATE_TRIAGE_NOTE
    assert (
        len(
            list(
                session.exec(select(FindingEvent).where(col(FindingEvent.finding_id) == finding.id))
            )
        )
        == 3
    )
    second_scan = session.get(Scan, second_scan_id)
    assert second_scan is not None and second_scan.status is ScanStatus.COMPLETED
    assert len(list(session.exec(select(NotificationDelivery)))) == 4
    receiver_count = len(sink.requests)
    with capture_logs() as second_delivery_logs:
        delivered_again = dispatch.deliver_pending(
            session,
            api_settings,
            secret_store,
            transports={NotificationChannelType.WEBHOOK: webhook},
        )
    assert delivered_again.delivered == 0
    assert len(sink.requests) == receiver_count

    result_bytes = bridge.results_requests + bridge_again.results_requests
    lease_bytes = bridge.lease_responses + bridge_again.lease_responses
    assert lease_bytes and all(API_TOKEN in body.decode() for body in lease_bytes)
    assert all(SEEDED_SECRET not in body.decode() for body in lease_bytes)
    log_text = json.dumps(
        setup_logs
        + first_scan_logs
        + triage_delivery_logs
        + second_scan_logs
        + second_delivery_logs,
        default=str,
    )
    dump = _database_dump(session)
    webhook_bodies = [request.content for request in sink.requests]
    for secret in (SEEDED_SECRET, API_TOKEN, WEBHOOK_SECRET):
        _assert_absent(
            secret,
            [
                *public_responses,
                engine_registration,
                *result_bytes,
                *webhook_bodies,
                log_text,
                dump,
            ],
        )
    assert engine_registration.decode().count(engine_token) == 1
    _assert_absent(
        engine_token,
        public_responses + result_bytes + lease_bytes + webhook_bodies + [log_text, dump],
    )


def test_incomplete_pilot_scan_keeps_partial_findings_and_queues_no_notification(
    app: FastAPI,
    client: TestClient,
    provider: FakeProvider,
    session: Session,
    dispatcher: RecordingDispatcher,
) -> None:
    """Readable findings survive a failed unit, but reconciliation/outbox do not run."""
    headers = _login_admin(client, provider)
    source_id = _create_source(client, headers)
    engine_id, engine_token, _engine_registration = _register_engine(client, headers)
    site = FakeConfluence(
        spaces=[
            Space(
                "s1",
                "DOCS",
                "Documentation",
                pages=[
                    Page("p1", "First", leaky_page_storage()),
                    Page("p2", "Second", leaky_page_storage()),
                ],
            )
        ]
    )
    registry.clear()
    registry.register(
        ConfluenceConnector(transport=site.transport(), sleep=lambda _s: None, sandbox_factory=None)
    )

    with TestClient(app, base_url="http://testserver") as engine_http:
        bridge = AppTransport(engine_http)
        engine = EngineClient(
            base_url="http://api.test",
            token=engine_token,
            engine_id=engine_id,
            transport=httpx2.MockTransport(bridge),
            sleep=lambda _s: None,
        )
        try:
            baseline_scan_id = _run_scan(client, headers, source_id, dispatcher, engine)
            assert len(list(session.exec(select(Finding)))) == 2
            _create_channel(client, headers)

            site.spaces[0].pages[1].body_in_list = False
            site.spaces[0].pages.append(Page("p3", "Third", leaky_page_storage()))
            site.failing_paths = ("/pages/p2",)
            with capture_logs() as logs:
                partial_scan_id = _run_scan(client, headers, source_id, dispatcher, engine)
        finally:
            engine.close()
            registry.clear()

    baseline = session.get(Scan, baseline_scan_id)
    partial = session.get(Scan, partial_scan_id)
    assert baseline is not None and baseline.status is ScanStatus.COMPLETED
    assert partial is not None and partial.status is ScanStatus.PARTIAL
    findings = list(session.exec(select(Finding)))
    assert {finding.resource_locator["resource_id"] for finding in findings} == {"p1", "p2", "p3"}
    unseen = next(
        finding for finding in findings if finding.resource_locator["resource_id"] == "p2"
    )
    partial_finding = next(
        finding for finding in findings if finding.resource_locator["resource_id"] == "p3"
    )
    assert unseen.state is FindingState.OPEN
    assert unseen.last_seen_scan_id == baseline_scan_id
    assert partial_finding.last_seen_scan_id == partial_scan_id
    assert session.exec(select(NotificationDelivery)).all() == []

    log_text = json.dumps(logs, default=str)
    for secret in (SEEDED_SECRET, API_TOKEN):
        _assert_absent(secret, [*bridge.results_requests, log_text])
