"""Shared pytest fixtures, published as a pytest plugin.

``iceberg-core`` declares this module under the ``pytest11`` entry point, so
every workspace member gets the fixtures below without copying conftest
boilerplate. Importing it outside a test run is not intended.

The database fixtures are SQLite-backed: fast, hermetic, and enough to exercise
the models and queries. Postgres-specific behaviour (partial indexes, JSONB
operators) is covered by the migration tests and by the compose stack.
"""

import secrets
from collections.abc import Iterator

import pytest
from sqlalchemy import Engine, StaticPool
from sqlmodel import Session, SQLModel, create_engine

from iceberg_core.db import enforce_sqlite_foreign_keys
from iceberg_core.secrets import EnvKeyBackend


@pytest.fixture(name="db_engine")
def db_engine_fixture() -> Iterator[Engine]:
    """An in-memory SQLite engine with the full schema created.

    ``StaticPool`` keeps every checkout on the same connection — without it each
    session would get a fresh, empty in-memory database.
    """
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    # Without this, ON DELETE CASCADE does nothing here and a cascade bug only
    # shows up against Postgres.
    enforce_sqlite_foreign_keys(engine)
    SQLModel.metadata.create_all(engine)
    try:
        yield engine
    finally:
        engine.dispose()


@pytest.fixture(name="session")
def session_fixture(db_engine: Engine) -> Iterator[Session]:
    """A session bound to the per-test schema. Rolled back on teardown."""
    with Session(db_engine) as session:
        yield session
        session.rollback()


@pytest.fixture(name="secret_store")
def secret_store_fixture() -> EnvKeyBackend:
    """An env-key store with an ephemeral master key and a sealed pepper.

    Tests that need a pepper (fingerprinting) or a credential ref get a real
    backend rather than a stub, so the code under test exercises the same
    seal/open path as production.
    """
    master_key = secrets.token_bytes(32)
    bootstrap = EnvKeyBackend(master_key)
    return EnvKeyBackend(master_key, pepper_ref=bootstrap.generate_pepper_ref())
