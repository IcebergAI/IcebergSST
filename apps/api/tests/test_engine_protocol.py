"""Engine registration, heartbeat, lease, and reclaim (#35 — ADR 0002, 0009)."""

import base64
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import pytest
from conftest import RecordingDispatcher
from fastapi.testclient import TestClient
from iceberg_api.engines.auth import hash_token
from iceberg_api.scans import service
from iceberg_core.enums import (
    ScanStatus,
    ScanTaskKind,
    ScanTaskStatus,
    ScanTrigger,
    SourceType,
    SuppressionScope,
    UserRole,
)
from iceberg_core.models import Engine, Scan, ScanTask, Source, Suppression, User
from iceberg_core.secrets import EnvKeyBackend, SecretStoreError
from sqlmodel import Session, select

REGISTER = "/api/v1/engines/register"
ENGINES = "/api/v1/engines"
CREDENTIAL = "admin@example.test:confluence-token"


def _source(session: Session, store: EnvKeyBackend, *, with_credential: bool = True) -> Source:
    source = Source(
        name="confluence-prod",
        type=SourceType.CONFLUENCE,
        connection={"base_url": "https://example.atlassian.net/wiki", "spaces": ["ENG"]},
        credential_ref=store.seal(CREDENTIAL) if with_credential else None,
    )
    session.add(source)
    session.commit()
    return source


def _scan_with_task(
    session: Session, source: Source, dispatcher: RecordingDispatcher
) -> tuple[Scan, ScanTask]:
    scan = service.launch_scan(session, source, trigger=ScanTrigger.MANUAL, dispatcher=dispatcher)
    task = session.exec(select(ScanTask).where(ScanTask.scan_id == scan.id)).one()
    return scan, task


def test_an_admin_registers_an_engine_and_sees_the_token_once(
    client: TestClient,
    session: Session,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """Only a hash is stored, so the plaintext exists in this one response."""
    headers = login_as(make_user(UserRole.ADMIN))

    response = client.post(REGISTER, json={"name": "engine-1", "version": "0.1.0"}, headers=headers)

    assert response.status_code == 201
    token = response.json()["token"]
    engine = session.exec(select(Engine)).one()
    assert engine.token_hash == hash_token(token)
    assert token not in engine.token_hash
    # And no route ever hands it back again.
    listed = client.get(ENGINES, headers=headers)
    assert token not in listed.text
    assert "token" not in listed.json()[0]


def test_registering_an_existing_name_rotates_its_token(
    client: TestClient,
    session: Session,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """How an operator replaces a credential they think has leaked."""
    headers = login_as(make_user(UserRole.ADMIN))
    first = client.post(REGISTER, json={"name": "engine-1"}, headers=headers).json()["token"]

    second = client.post(REGISTER, json={"name": "engine-1"}, headers=headers).json()["token"]

    assert first != second
    assert len(session.exec(select(Engine)).all()) == 1
    # The old token is dead the moment the new one is issued.
    assert session.exec(select(Engine)).one().token_hash == hash_token(second)


@pytest.mark.parametrize("role", [UserRole.ANALYST, UserRole.VIEWER])
def test_only_an_admin_can_mint_an_engine_credential(
    client: TestClient,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
    role: UserRole,
) -> None:
    """An engine cannot enrol itself, or anyone reaching the API could join the fleet."""
    headers = login_as(make_user(role))

    assert client.post(REGISTER, json={"name": "rogue"}, headers=headers).status_code == 403


def test_engine_routes_reject_missing_and_wrong_tokens(
    client: TestClient,
    session: Session,
    secret_store: EnvKeyBackend,
    dispatcher: RecordingDispatcher,
) -> None:
    source = _source(session, secret_store)
    _, task = _scan_with_task(session, source, dispatcher)
    lease = f"/api/v1/scan-tasks/{task.id}/lease"

    assert client.post(lease).status_code == 401
    assert client.post(lease, headers={"Authorization": "Bearer not-a-token"}).status_code == 401
    assert client.post(lease, headers={"Authorization": "Basic abc"}).status_code == 401


def test_a_human_session_cannot_lease_or_report(
    client: TestClient,
    session: Session,
    secret_store: EnvKeyBackend,
    dispatcher: RecordingDispatcher,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """Session cookies work everywhere except here (docs/api.md)."""
    headers = login_as(make_user(UserRole.ADMIN))
    source = _source(session, secret_store)
    _, task = _scan_with_task(session, source, dispatcher)

    assert client.post(f"/api/v1/scan-tasks/{task.id}/lease", headers=headers).status_code == 401
    results = client.post(
        f"/api/v1/scan-tasks/{task.id}/results",
        json={"idempotency_key": "x:1", "status": "completed"},
        headers=headers,
    )
    assert results.status_code == 401


def test_an_engine_token_cannot_read_findings_or_scans(
    client: TestClient,
    engine_credential: tuple[Engine, dict[str, str]],
) -> None:
    """The other half of the boundary: an engine token is not a session."""
    _, headers = engine_credential

    assert client.get("/api/v1/scans", headers=headers).status_code == 401
    assert client.get("/api/v1/sources", headers=headers).status_code == 401


def test_a_lease_carries_the_spec_credential_pepper_and_suppressions(
    client: TestClient,
    session: Session,
    secret_store: EnvKeyBackend,
    dispatcher: RecordingDispatcher,
    engine_credential: tuple[Engine, dict[str, str]],
) -> None:
    """Everything sensitive arrives here, once, for one task (ADR 0009 §2)."""
    engine, headers = engine_credential
    source = _source(session, secret_store)
    session.add(
        Suppression(
            scope=SuppressionScope.RULE,
            pattern="generic-high-entropy",
            source_id=source.id,
            reason="noisy",
        )
    )
    session.commit()
    scan, task = _scan_with_task(session, source, dispatcher)

    body = client.post(f"/api/v1/scan-tasks/{task.id}/lease", headers=headers).json()

    assert body["task_id"] == str(task.id)
    assert body["kind"] == ScanTaskKind.DISCOVERY.value
    assert body["attempt"] == 1
    assert body["credential"] == CREDENTIAL
    assert base64.b64decode(body["fingerprint_pepper"]) == secret_store.get_pepper()
    assert body["connection"]["spaces"] == ["ENG"]
    assert [rule["pattern"] for rule in body["suppressions"]] == ["generic-high-entropy"]

    session.refresh(task)
    session.refresh(scan)
    assert task.status is ScanTaskStatus.LEASED
    assert task.engine_id == engine.id
    # A leased discovery task is what "discovering" means.
    assert scan.status is ScanStatus.DISCOVERING


def test_only_one_engine_can_hold_a_lease(
    client: TestClient,
    session: Session,
    secret_store: EnvKeyBackend,
    dispatcher: RecordingDispatcher,
    engine_credential: tuple[Engine, dict[str, str]],
) -> None:
    """The claim is a conditional UPDATE, so the second attempt gets nothing."""
    _, headers = engine_credential
    source = _source(session, secret_store)
    _, task = _scan_with_task(session, source, dispatcher)
    lease = f"/api/v1/scan-tasks/{task.id}/lease"

    assert client.post(lease, headers=headers).status_code == 200
    second = client.post(lease, headers=headers)

    assert second.status_code == 409
    assert "not available" in second.text


def test_leasing_an_unknown_or_cancelled_task_is_a_conflict(
    client: TestClient,
    session: Session,
    secret_store: EnvKeyBackend,
    dispatcher: RecordingDispatcher,
    engine_credential: tuple[Engine, dict[str, str]],
) -> None:
    """The engine's response to every refusal is the same: drop the message."""
    _, headers = engine_credential
    source = _source(session, secret_store)
    _, task = _scan_with_task(session, source, dispatcher)
    task.status = ScanTaskStatus.CANCELLED
    session.commit()

    unknown = "00000000-0000-4000-8000-000000000000"
    assert client.post(f"/api/v1/scan-tasks/{unknown}/lease", headers=headers).status_code == 409
    assert client.post(f"/api/v1/scan-tasks/{task.id}/lease", headers=headers).status_code == 409


def test_a_source_whose_credential_will_not_decrypt_fails_the_task(
    client: TestClient,
    session: Session,
    secret_store: EnvKeyBackend,
    dispatcher: RecordingDispatcher,
    engine_credential: tuple[Engine, dict[str, str]],
) -> None:
    """Better a failed task than an engine scanning unauthenticated and finding nothing."""
    _, headers = engine_credential
    source = _source(session, secret_store)
    source.credential_ref = "envkey:1:credential:will-not-open"
    session.commit()
    _, task = _scan_with_task(session, source, dispatcher)

    response = client.post(f"/api/v1/scan-tasks/{task.id}/lease", headers=headers)

    assert response.status_code == 500
    session.refresh(task)
    assert task.status is ScanTaskStatus.FAILED


def test_a_missing_pepper_fails_the_task_rather_than_leasing_without_one(
    client: TestClient,
    session: Session,
    secret_store: EnvKeyBackend,
    dispatcher: RecordingDispatcher,
    engine_credential: tuple[Engine, dict[str, str]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unpeppered fingerprints match nothing stored: every finding would ingest as
    new and reconciliation would resolve the real ones. Fail closed (ADR 0006)."""
    _, headers = engine_credential
    source = _source(session, secret_store)
    _, task = _scan_with_task(session, source, dispatcher)

    def broken_pepper() -> bytes:
        raise SecretStoreError("pepper ref will not open")

    monkeypatch.setattr(secret_store, "get_pepper", broken_pepper)
    response = client.post(f"/api/v1/scan-tasks/{task.id}/lease", headers=headers)

    assert response.status_code == 500
    session.refresh(task)
    assert task.status is ScanTaskStatus.FAILED


def test_a_source_without_a_credential_still_leases(
    client: TestClient,
    session: Session,
    secret_store: EnvKeyBackend,
    dispatcher: RecordingDispatcher,
    engine_credential: tuple[Engine, dict[str, str]],
) -> None:
    """Anonymous sources are legitimate — a public wiki needs no token."""
    _, headers = engine_credential
    source = _source(session, secret_store, with_credential=False)
    _, task = _scan_with_task(session, source, dispatcher)

    body = client.post(f"/api/v1/scan-tasks/{task.id}/lease", headers=headers).json()

    assert body["credential"] is None


def test_a_heartbeat_extends_the_lease(
    client: TestClient,
    session: Session,
    secret_store: EnvKeyBackend,
    dispatcher: RecordingDispatcher,
    engine_credential: tuple[Engine, dict[str, str]],
) -> None:
    engine, headers = engine_credential
    source = _source(session, secret_store)
    _, task = _scan_with_task(session, source, dispatcher)
    client.post(f"/api/v1/scan-tasks/{task.id}/lease", headers=headers)
    session.refresh(task)
    first_expiry = task.lease_expires_at

    response = client.post(
        f"/api/v1/engines/{engine.id}/heartbeat",
        json={"task_ids": [str(task.id)], "version": "0.2.0"},
        headers=headers,
    )

    assert response.status_code == 200
    assert response.json()["cancelled_task_ids"] == []
    session.refresh(task)
    session.refresh(engine)
    assert task.lease_expires_at is not None
    assert first_expiry is not None
    assert task.lease_expires_at >= first_expiry
    assert task.status is ScanTaskStatus.RUNNING
    assert engine.last_heartbeat_at is not None
    assert engine.version == "0.2.0"


def test_an_engine_cannot_heartbeat_as_another_engine(
    client: TestClient,
    session: Session,
    engine_credential: tuple[Engine, dict[str, str]],
) -> None:
    """Otherwise one engine could keep another's leases alive."""
    _, headers = engine_credential
    other = Engine(name="engine-other", token_hash="unused")
    session.add(other)
    session.commit()

    response = client.post(f"/api/v1/engines/{other.id}/heartbeat", json={}, headers=headers)

    assert response.status_code == 403


def test_a_heartbeat_reports_cancellation(
    client: TestClient,
    session: Session,
    secret_store: EnvKeyBackend,
    dispatcher: RecordingDispatcher,
    engine_credential: tuple[Engine, dict[str, str]],
) -> None:
    """The only way to tell a working engine to stop (ADR 0009)."""
    engine, headers = engine_credential
    source = _source(session, secret_store)
    scan, task = _scan_with_task(session, source, dispatcher)
    client.post(f"/api/v1/scan-tasks/{task.id}/lease", headers=headers)
    service.cancel_scan(session, scan)

    body = client.post(
        f"/api/v1/engines/{engine.id}/heartbeat",
        json={"task_ids": [str(task.id)]},
        headers=headers,
    ).json()

    assert body["cancelled_task_ids"] == [str(task.id)]


def test_an_expired_lease_is_reclaimed_and_redispatched_exactly_once(
    session: Session,
    secret_store: EnvKeyBackend,
    dispatcher: RecordingDispatcher,
) -> None:
    """The single re-delivery mechanism: broker retries are off (ADR 0009 §2)."""
    source = _source(session, secret_store)
    _, task = _scan_with_task(session, source, dispatcher)
    engine = Engine(name="dead-engine", token_hash="unused")
    session.add(engine)
    session.commit()
    service.claim_task(session, task.id, engine.id, lease_seconds=1)
    dispatcher.enqueued.clear()

    later = datetime.now(UTC) + timedelta(minutes=5)
    reclaimed = service.reclaim_expired_leases(session, dispatcher=dispatcher, now=later)

    assert reclaimed == [task.id]
    assert dispatcher.enqueued == [task.id]
    session.refresh(task)
    assert task.status is ScanTaskStatus.QUEUED
    assert task.engine_id is None
    # Second sweep finds nothing: the task is queued, not leased.
    assert service.reclaim_expired_leases(session, dispatcher=dispatcher, now=later) == []


def test_a_live_lease_is_not_reclaimed(
    session: Session,
    secret_store: EnvKeyBackend,
    dispatcher: RecordingDispatcher,
) -> None:
    source = _source(session, secret_store)
    _, task = _scan_with_task(session, source, dispatcher)
    engine = Engine(name="live-engine", token_hash="unused")
    session.add(engine)
    session.commit()
    service.claim_task(session, task.id, engine.id, lease_seconds=600)

    assert service.reclaim_expired_leases(session, dispatcher=dispatcher) == []


def test_reclaim_does_not_resurrect_a_completed_task(
    session: Session,
    secret_store: EnvKeyBackend,
    dispatcher: RecordingDispatcher,
) -> None:
    """An engine that finished just before the sweep keeps its completion: the
    reclaim write is conditional, not read-then-write."""
    source = _source(session, secret_store)
    _, task = _scan_with_task(session, source, dispatcher)
    engine = Engine(name="slow-engine", token_hash="unused")
    session.add(engine)
    session.commit()
    service.claim_task(session, task.id, engine.id, lease_seconds=1)
    service.complete_task(session, task, status=ScanTaskStatus.COMPLETED)
    session.commit()

    later = datetime.now(UTC) + timedelta(minutes=5)
    assert service.reclaim_expired_leases(session, dispatcher=dispatcher, now=later) == []
    session.refresh(task)
    assert task.status is ScanTaskStatus.COMPLETED


def test_a_stale_heartbeat_cannot_resurrect_a_reclaimed_task(
    session: Session,
    secret_store: EnvKeyBackend,
    dispatcher: RecordingDispatcher,
) -> None:
    """Renewal is conditional on still holding the lease."""
    source = _source(session, secret_store)
    _, task = _scan_with_task(session, source, dispatcher)
    engine = Engine(name="quiet-engine", token_hash="unused")
    session.add(engine)
    session.commit()
    grant = service.claim_task(session, task.id, engine.id, lease_seconds=1)
    assert grant is not None
    stale = grant.task

    service.reclaim_expired_leases(
        session, dispatcher=dispatcher, now=datetime.now(UTC) + timedelta(minutes=5)
    )

    assert service.renew_lease(session, stale) is None
    session.refresh(task)
    assert task.status is ScanTaskStatus.QUEUED
    assert task.engine_id is None


def test_a_reclaimed_task_records_its_second_attempt(
    session: Session,
    secret_store: EnvKeyBackend,
    dispatcher: RecordingDispatcher,
) -> None:
    """`attempts` is what an idempotency key is built from."""
    source = _source(session, secret_store)
    _, task = _scan_with_task(session, source, dispatcher)
    engine = Engine(name="engine-1", token_hash="unused")
    session.add(engine)
    session.commit()

    service.claim_task(session, task.id, engine.id, lease_seconds=1)
    service.reclaim_expired_leases(
        session, dispatcher=dispatcher, now=datetime.now(UTC) + timedelta(minutes=5)
    )
    grant = service.claim_task(session, task.id, engine.id)

    assert grant is not None
    assert grant.task.attempts == 2


def test_an_engine_reports_its_rulepack_at_registration(
    client: TestClient,
    session: Session,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """Rule packs ship in engine images (ADR 0008), so the fleet is the only place
    that knows which rules are in force (#70)."""
    headers = login_as(make_user(UserRole.ADMIN))

    response = client.post(
        REGISTER,
        json={
            "name": "engine-reporting",
            "version": "0.2.0",
            "rulepack": {
                "version": "2026.07.1",
                "rules": [
                    {"id": "aws-access-key-id", "description": "AWS key", "severity": "high"}
                ],
            },
        },
        headers=headers,
    )

    assert response.status_code == 201
    engine = session.exec(select(Engine).where(Engine.name == "engine-reporting")).one()
    assert engine.rulepack["version"] == "2026.07.1"
    assert [rule["id"] for rule in engine.rulepack["rules"]] == ["aws-access-key-id"]


def test_a_heartbeat_replaces_the_reported_rulepack(
    client: TestClient,
    session: Session,
    engine_credential: tuple[Engine, dict[str, str]],
) -> None:
    """An engine restarted onto a smaller pack must not appear to still be running
    the rules it dropped — replaced, not merged."""
    engine, headers = engine_credential
    engine.rulepack = {
        "version": "2026.07.1",
        "rules": [
            {"id": "aws-access-key-id", "description": "AWS key", "severity": "high"},
            {"id": "retired-rule", "description": "Gone", "severity": "low"},
        ],
    }
    session.add(engine)
    session.commit()

    client.post(
        f"{ENGINES}/{engine.id}/heartbeat",
        json={
            "rulepack": {
                "version": "2026.08.1",
                "rules": [
                    {"id": "aws-access-key-id", "description": "AWS key", "severity": "high"}
                ],
            }
        },
        headers=headers,
    )

    session.refresh(engine)
    assert engine.rulepack["version"] == "2026.08.1"
    assert [rule["id"] for rule in engine.rulepack["rules"]] == ["aws-access-key-id"]


def test_a_heartbeat_without_a_rulepack_leaves_the_stored_one_alone(
    client: TestClient,
    session: Session,
    engine_credential: tuple[Engine, dict[str, str]],
) -> None:
    """Omitting the field is not the same as reporting an empty pack."""
    engine, headers = engine_credential
    engine.rulepack = {"version": "2026.07.1", "rules": []}
    session.add(engine)
    session.commit()

    client.post(f"{ENGINES}/{engine.id}/heartbeat", json={}, headers=headers)

    session.refresh(engine)
    assert engine.rulepack["version"] == "2026.07.1"
