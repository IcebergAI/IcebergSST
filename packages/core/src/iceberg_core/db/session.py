"""Async engine and session management (issue #23).

Full-async SQLModel over asyncpg. The api role owns the schema and is the sole
writer of record (ADR 0002); engines never import this module.

Base model conventions
----------------------
* Tables subclass :class:`IcebergModel` with ``table=True``.
* Primary keys are ``uuid.UUID`` defaulted with ``uuid4`` — ids are minted by the
  application, not the database, so a row can be referenced before it is flushed.
* Timestamps are timezone-aware UTC; ``created_at`` is set on construction.
* Table names are explicit snake_case plurals via ``__tablename__``.
* Single-org: no ``tenant_id`` on anything (ARCHITECTURE.md §1).
"""

import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime

from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine
from sqlmodel import Field, SQLModel

# SQLModel's AsyncSession, not SQLAlchemy's: it adds the typed ``.exec()`` that
# returns SQLModel rows rather than raw Result tuples.
from sqlmodel.ext.asyncio.session import AsyncSession

from iceberg_core.config import ApiSettings


def utcnow() -> datetime:
    """Timezone-aware UTC now — never use naive ``datetime.utcnow()``."""
    return datetime.now(UTC)


class IcebergModel(SQLModel):
    """Base for every persisted entity.

    Subclasses add ``table=True`` and their own ``__tablename__``.
    """

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    created_at: datetime = Field(default_factory=utcnow, nullable=False)


def create_engine(settings: ApiSettings) -> AsyncEngine:
    """Build the async engine from API settings.

    The DSN must name the asyncpg driver; a sync DSN silently produces a
    greenlet error deep in the first query, so fail loudly here instead.
    """
    url = settings.database_url
    if "+asyncpg" not in url:
        raise ValueError(
            f"database_url must use the asyncpg driver "
            f"(postgresql+asyncpg://…), got: {url.split('://')[0]}://…"
        )
    return create_async_engine(
        url,
        echo=settings.db_echo,
        pool_size=settings.db_pool_size,
        max_overflow=settings.db_max_overflow,
        pool_pre_ping=True,
    )


def create_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    """Session factory bound to an engine.

    ``expire_on_commit=False`` so committed objects stay usable in the response
    serialisation that follows a request handler's commit.
    """
    return async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


@asynccontextmanager
async def session_scope(
    factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[AsyncSession]:
    """Transactional scope: commit on success, roll back on any exception."""
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
