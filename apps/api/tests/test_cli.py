"""Operator commands (#35 — the engine-token bootstrap)."""

import secrets
import uuid
from collections.abc import Iterator

import pytest
from iceberg_api import cli
from iceberg_api.engines.auth import hash_token
from iceberg_core.correlation import correlation_id
from iceberg_core.db import set_db_engine
from iceberg_core.enums import ScanStatus, ScanTrigger, Severity, SourceType
from iceberg_core.models import (
    AUDIT_CORRELATION_REINDEXED,
    AUDIT_ENGINE_REGISTERED,
    AUDIT_ENGINE_TOKEN_ROTATED,
    AuditEvent,
    Engine,
    Finding,
    Scan,
    Source,
)
from sqlalchemy import Engine as SAEngine
from sqlmodel import Session, col, select


@pytest.fixture(name="process_engine", autouse=True)
def process_engine_fixture(db_engine: SAEngine) -> Iterator[None]:
    set_db_engine(db_engine)
    yield
    set_db_engine(None)


def test_minting_a_token_registers_the_engine_and_stores_only_a_hash(
    session: Session,
) -> None:
    """The deploy-time bootstrap: no admin session exists yet (docs/security.md)."""
    engine_id, token = cli.mint_engine_token("engine-1", "0.1.0")

    engine = session.exec(select(Engine)).one()
    assert engine.name == "engine-1"
    assert engine.version == "0.1.0"
    assert engine.token_hash == hash_token(token)
    assert token not in engine.token_hash
    # The id is part of the credential: an engine names itself in its heartbeat
    # path and the API checks the two agree, so a token alone cannot renew a
    # lease (#51).
    assert engine_id == engine.id


def test_minting_again_rotates_rather_than_duplicating(session: Session) -> None:
    first_id, first = cli.mint_engine_token("engine-1", None)

    second_id, second = cli.mint_engine_token("engine-1", None)

    assert first != second
    # Rotation keeps the identity: the id an operator configured stays valid, so
    # only the token has to be replaced.
    assert first_id == second_id
    engines = session.exec(select(Engine)).all()
    assert len(engines) == 1
    assert engines[0].token_hash == hash_token(second)


def test_cli_minting_lands_in_the_audit_trail_like_the_route_does(session: Session) -> None:
    """Minting an engine credential is the same consequential action whichever
    door it comes through; the CLI path must not be the one that leaves no row.
    The token itself is never recorded (audit.py contract)."""
    engine_id, token = cli.mint_engine_token("engine-1", None)
    cli.mint_engine_token("engine-1", None)

    events = session.exec(select(AuditEvent).order_by(AuditEvent.created_at)).all()  # type: ignore[arg-type]
    assert [event.action for event in events] == [
        AUDIT_ENGINE_REGISTERED,
        AUDIT_ENGINE_TOKEN_ROTATED,
    ]
    assert all(event.target_id == engine_id for event in events)
    assert all(event.actor_id is None for event in events)
    assert token not in str([event.detail for event in events])


def _seed_finding(session: Session, *, correlation: str | None) -> Finding:
    source = Source(
        name=f"confluence-{uuid.uuid4().hex[:6]}",
        type=SourceType.CONFLUENCE,
        connection={"base_url": "https://example.atlassian.net/wiki"},
    )
    session.add(source)
    session.commit()
    scan = Scan(source_id=source.id, trigger=ScanTrigger.MANUAL, status=ScanStatus.COMPLETED)
    session.add(scan)
    session.commit()
    finding = Finding(
        source_id=source.id,
        fingerprint=uuid.uuid4().hex,
        rule_id="aws-access-key",
        rulepack_version="2026.07.1",
        resource_locator={"path": "/space/DOCS/page-1"},
        redacted_snippet="AKIA****************",
        secret_hash=uuid.uuid4().hex,
        correlation_id=correlation,
        severity=Severity.HIGH,
        first_seen_scan_id=scan.id,
        last_seen_scan_id=scan.id,
    )
    session.add(finding)
    session.commit()
    return finding


def test_reindex_correlation_rederives_and_audits(session: Session) -> None:
    """The key-rotation move (ADR 0011): every id re-derived under the new key
    from stored data alone, and the recompute itself lands in the trail."""
    stale = _seed_finding(session, correlation="0" * 64)
    missing = _seed_finding(session, correlation=None)
    key = secrets.token_bytes(32)

    outcome = cli.reindex_correlation(key, batch=1)

    assert (outcome.scanned, outcome.updated) == (2, 2)
    for finding in (stale, missing):
        session.refresh(finding)
        assert finding.correlation_id == correlation_id(finding.secret_hash, key=key)

    again = cli.reindex_correlation(key, batch=1)
    assert (again.scanned, again.updated) == (2, 0)

    events = session.exec(
        select(AuditEvent).where(col(AuditEvent.action) == AUDIT_CORRELATION_REINDEXED)
    ).all()
    assert len(events) == 2
    assert events[0].detail["updated"] == "2"
    assert events[1].detail["updated"] == "0"
