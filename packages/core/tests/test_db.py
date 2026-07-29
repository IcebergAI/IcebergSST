"""Engine construction and session semantics."""

from collections.abc import Iterator

import pytest
from iceberg_core.config import ApiSettings
from iceberg_core.db import (
    create_db_engine,
    get_db_engine,
    session_dependency,
    session_scope,
    set_db_engine,
)
from sqlalchemy import Column, Engine, MetaData, String, Table, insert, select
from sqlmodel import Session

# A scratch table in its own MetaData: the shared SQLModel metadata belongs to
# the real schema, and a test fixture has no business appearing in a migration.
_metadata = MetaData()
NOTES = Table("scratch_note", _metadata, Column("body", String, primary_key=True))


@pytest.fixture(name="scratch_engine")
def scratch_engine_fixture() -> Iterator[Engine]:
    engine = create_db_engine("sqlite://")
    _metadata.create_all(engine)
    try:
        yield engine
    finally:
        engine.dispose()


@pytest.fixture(autouse=True)
def _clear_process_engine() -> Iterator[None]:
    set_db_engine(None)
    yield
    set_db_engine(None)


def _bodies(engine: Engine) -> list[str]:
    with engine.connect() as connection:
        return list(connection.scalars(select(NOTES.c.body)))


def test_sqlite_urls_get_thread_safe_connect_args() -> None:
    engine = create_db_engine("sqlite://")
    try:
        with engine.connect() as connection:
            assert connection.exec_driver_sql("select 1").scalar() == 1
        assert engine.dialect.name == "sqlite"
    finally:
        engine.dispose()


def test_session_scope_commits_on_success(scratch_engine: Engine) -> None:
    with session_scope(scratch_engine) as session:
        session.execute(insert(NOTES).values(body="kept"))

    assert _bodies(scratch_engine) == ["kept"]


def test_session_scope_rolls_back_on_error(scratch_engine: Engine) -> None:
    class Boom(RuntimeError):
        pass

    with pytest.raises(Boom), session_scope(scratch_engine) as session:
        session.execute(insert(NOTES).values(body="discarded"))
        raise Boom

    assert _bodies(scratch_engine) == []


def test_get_db_engine_is_process_wide() -> None:
    settings = ApiSettings(database_url="sqlite://")

    first = get_db_engine(settings)
    second = get_db_engine(settings)

    assert first is second
    first.dispose()


def test_session_dependency_yields_a_live_session() -> None:
    engine = create_db_engine("sqlite://")
    set_db_engine(engine)
    try:
        sessions = session_dependency()
        session = next(sessions)
        assert session.execute(select(1)).scalar_one() == 1
        with pytest.raises(StopIteration):
            next(sessions)  # exhausting the dependency closes the session
    finally:
        engine.dispose()


def test_provided_session_fixture_is_usable(session: Session) -> None:
    """The shared ``session`` fixture from ``iceberg_core.testing``."""
    assert session.execute(select(1)).scalar_one() == 1
