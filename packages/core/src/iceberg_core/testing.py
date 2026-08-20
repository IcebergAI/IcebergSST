"""Shared pytest fixtures, published as a pytest plugin.

``iceberg-core`` declares this module under the ``pytest11`` entry point, so
every workspace member gets the fixtures below without copying conftest
boilerplate. Importing it outside a test run is not intended.

The database fixtures are SQLite-backed: fast, hermetic, and enough to exercise
the models and queries. Postgres-specific behaviour (partial indexes, JSONB
operators) is covered by the migration tests and by the compose stack.

**The ORM imports are guarded, and that is not defensiveness** (#197). A
``pytest11`` plugin is auto-loaded by *every* pytest run in an environment where
this package is installed — including one carrying the engine's dependency shape,
which is plain ``iceberg-core`` with no ``db`` extra and therefore no SQLAlchemy
at all (ADR 0002). An unguarded import there fails at collection, before any test
has run, in a package that deliberately does not depend on the thing it needs.
So the module always imports, and the database fixtures skip with a sentence
saying what to install. Nothing silently passes: a test that asked for a session
and did not get one is reported as skipped, not green.
"""

import secrets
from collections.abc import Iterator
from typing import Any

import pytest

from iceberg_core.secrets import EnvKeyBackend

#: What to do about it, said once and reported by every fixture that cannot run.
MISSING_DB_EXTRA = (
    "the shared database fixtures need iceberg-core's `db` extra "
    "(install `iceberg-core[testing]`); this environment has the engine's "
    "dependency shape, where the ORM is deliberately absent (ADR 0002)"
)

try:
    from sqlalchemy import Engine, StaticPool
    from sqlmodel import Session, SQLModel, create_engine

    from iceberg_core.db import enforce_sqlite_foreign_keys
    from iceberg_core.models import DEFAULT_RESPONSE_TARGET_HOURS, ResponseTarget

    DB_FIXTURES_AVAILABLE = True
except ImportError:  # pragma: no cover — exercised by a subprocess test
    DB_FIXTURES_AVAILABLE = False
    # Bound so the annotations below still resolve for anything that evaluates
    # them; the fixtures themselves never get far enough to use these.
    Engine = Any  # type: ignore[assignment, misc]
    Session = Any  # type: ignore[assignment, misc]


@pytest.fixture(name="db_engine")
def db_engine_fixture() -> Iterator[Engine]:
    """An in-memory SQLite engine with the full schema created.

    ``StaticPool`` keeps every checkout on the same connection — without it each
    session would get a fresh, empty in-memory database.
    """
    if not DB_FIXTURES_AVAILABLE:
        pytest.skip(MISSING_DB_EXTRA)
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    # Without this, ON DELETE CASCADE does nothing here and a cascade bug only
    # shows up against Postgres.
    enforce_sqlite_foreign_keys(engine)
    SQLModel.metadata.create_all(engine)
    _seed_response_targets(engine)
    try:
        yield engine
    finally:
        engine.dispose()


def _seed_response_targets(engine: Engine) -> None:
    """The rows migration 0014 seeds, because ``create_all`` does not run it.

    The schema here comes from the metadata rather than from Alembic, so every
    table arrives empty — including the one whose *contents* are part of the
    shipped configuration. Without this, findings in tests get no due date while
    findings in any migrated deployment get one, and the difference would hide
    exactly the bugs due dates can have (#146). Same reasoning as the correlation
    key below being configured by default.
    """
    with Session(engine) as session:
        session.add_all(
            ResponseTarget(severity=severity, hours=hours)
            for severity, hours in DEFAULT_RESPONSE_TARGET_HOURS.items()
        )
        session.commit()


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
    return EnvKeyBackend(
        master_key,
        pepper_ref=bootstrap.generate_pepper_ref(),
        # Configured by default so ingest exercises correlation derivation the
        # way a fully configured deployment does; a test for the key-off path
        # builds its own store without one.
        correlation_key_ref=bootstrap.generate_correlation_key_ref(),
    )
