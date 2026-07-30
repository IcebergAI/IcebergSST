"""Operator commands (#35 — the engine-token bootstrap)."""

from collections.abc import Iterator

import pytest
from iceberg_api import cli
from iceberg_api.engines.auth import hash_token
from iceberg_core.db import set_db_engine
from iceberg_core.models import (
    AUDIT_ENGINE_REGISTERED,
    AUDIT_ENGINE_TOKEN_ROTATED,
    AuditEvent,
    Engine,
)
from sqlalchemy import Engine as SAEngine
from sqlmodel import Session, select


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
