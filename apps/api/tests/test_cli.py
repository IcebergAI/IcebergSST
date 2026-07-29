"""Operator commands (#35 — the engine-token bootstrap)."""

from collections.abc import Iterator

import pytest
from iceberg_api import cli
from iceberg_api.engines.auth import hash_token
from iceberg_core.db import set_db_engine
from iceberg_core.models import Engine
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
    token = cli.mint_engine_token("engine-1", "0.1.0")

    engine = session.exec(select(Engine)).one()
    assert engine.name == "engine-1"
    assert engine.version == "0.1.0"
    assert engine.token_hash == hash_token(token)
    assert token not in engine.token_hash


def test_minting_again_rotates_rather_than_duplicating(session: Session) -> None:
    first = cli.mint_engine_token("engine-1", None)

    second = cli.mint_engine_token("engine-1", None)

    assert first != second
    engines = session.exec(select(Engine)).all()
    assert len(engines) == 1
    assert engines[0].token_hash == hash_token(second)
