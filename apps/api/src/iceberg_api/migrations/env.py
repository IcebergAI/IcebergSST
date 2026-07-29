"""Alembic environment for the api role.

Two things make autogenerate trustworthy here:

* ``target_metadata`` is the **shared SQLModel metadata**, and importing
  :mod:`iceberg_core.models` registers every table on it. A new entity that is
  not re-exported from that package is invisible to autogenerate, which is why
  the package's ``__all__`` is part of the contract.
* the database URL comes from :class:`~iceberg_core.config.ApiSettings`, not from
  ``alembic.ini``, so migrations cannot be pointed at a different database than
  the API itself — and a URL with a password stays out of version control.

Tests override the URL through ``config.attributes["sqlalchemy.url"]``.
"""

from logging.config import fileConfig

import iceberg_core.models  # noqa: F401  # registers every table on the metadata
from alembic import context
from iceberg_core.config import get_api_settings
from sqlalchemy import Connection, create_engine, pool
from sqlmodel import SQLModel

config = context.config

if config.config_file_name is not None and not config.attributes.get("skip_logging_config"):
    fileConfig(config.config_file_name)

target_metadata = SQLModel.metadata


def _database_url() -> str:
    override = config.attributes.get("sqlalchemy.url") or config.get_main_option("sqlalchemy.url")
    if override:
        return str(override)
    return get_api_settings().database_url


def _configure(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
        compare_server_default=True,
        # SQLite cannot ALTER in place; batch mode keeps the test path working for
        # future column changes without affecting Postgres.
        render_as_batch=connection.dialect.name == "sqlite",
    )


def run_migrations_offline() -> None:
    """Emit SQL to stdout instead of applying it (``alembic upgrade --sql``)."""
    context.configure(
        url=_database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Apply migrations against a live connection."""
    connectable = config.attributes.get("connection")
    if isinstance(connectable, Connection):
        _configure(connectable)
        with context.begin_transaction():
            context.run_migrations()
        return

    engine = create_engine(_database_url(), poolclass=pool.NullPool)
    try:
        with engine.connect() as connection:
            _configure(connection)
            with context.begin_transaction():
                context.run_migrations()
    finally:
        engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
