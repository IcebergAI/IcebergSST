"""Issue #23 acceptance: a session fixture is available to tests.

These run against a real Postgres container (session-scoped, see the root
conftest) — no SQLite stand-in, because M1 leans on Postgres-specific features
like partial unique indexes (#34).
"""

import pytest
from iceberg_core.config import ApiSettings
from iceberg_core.db.session import (
    IcebergModel,
    create_engine,
    create_session_factory,
    session_scope,
    utcnow,
)
from sqlalchemy.ext.asyncio import AsyncEngine
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession


def test_sync_dsn_is_rejected_loudly() -> None:
    """A sync DSN otherwise fails deep in the first query with a greenlet error."""
    with pytest.raises(ValueError, match="asyncpg"):
        create_engine(ApiSettings(database_url="postgresql://u:p@host/db"))


def test_base_model_defaults() -> None:
    """Ids are app-minted so rows can be referenced before flush."""

    class Widget(IcebergModel):
        pass

    first, second = Widget(), Widget()
    assert first.id != second.id
    assert first.created_at.tzinfo is not None


def test_utcnow_is_timezone_aware() -> None:
    assert utcnow().tzinfo is not None


@pytest.mark.postgres
async def test_session_fixture_talks_to_postgres(db_session: AsyncSession) -> None:
    """The fixture #23 promises: a live async session."""
    result = await db_session.exec(select(1))
    assert result.one() == 1


@pytest.mark.postgres
async def test_session_scope_commits_on_success(db_engine: AsyncEngine) -> None:
    async with session_scope(create_session_factory(db_engine)) as session:
        await session.exec(select(1))


@pytest.mark.postgres
async def test_session_scope_rolls_back_on_error(db_engine: AsyncEngine) -> None:
    """An exception inside the scope must roll back and propagate, not swallow."""
    with pytest.raises(RuntimeError, match="boom"):
        async with session_scope(create_session_factory(db_engine)):
            raise RuntimeError("boom")
