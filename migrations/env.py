"""Alembic environment (issue #27).

Async throughout, matching the runtime stack: the api talks to Postgres over
asyncpg, so migrations do too rather than keeping a second sync driver around.

The DSN comes from :class:`~iceberg_core.config.ApiSettings`, never from
alembic.ini — one source of truth for connection details, and no credential in
the repo.

Autogenerate targets ``SQLModel.metadata``. Models are imported below purely for
their registration side effect; M0 has none yet (they arrive with #31/#34), so
the first revision is an empty baseline.
"""

import asyncio
from logging.config import fileConfig

from alembic import context
from iceberg_core.config import ApiSettings
from iceberg_core.db.session import create_engine
from sqlalchemy import Connection
from sqlmodel import SQLModel

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Import model modules here so SQLModel.metadata is populated before
# autogenerate compares it against the database. Empty in M0.
target_metadata = SQLModel.metadata


def _settings() -> ApiSettings:
    return ApiSettings()


def run_migrations_offline() -> None:
    """Emit SQL to stdout without a live connection (`alembic upgrade --sql`)."""
    context.configure(
        url=_settings().database_url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def _run(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
        compare_server_default=True,
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    engine = create_engine(_settings())
    try:
        async with engine.connect() as connection:
            await connection.run_sync(_run)
    finally:
        await engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
