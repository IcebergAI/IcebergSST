"""Database engine and session management.

**API role only.** Importing this module from ``apps/engine`` violates ADR 0002
and is caught by ``apps/engine/tests/test_no_db_access.py``, which imports the
engine and asserts this module never appears in ``sys.modules``.

Engines reach the database through the API or not at all.
"""

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from sqlalchemy import Engine
from sqlmodel import Session, create_engine

from iceberg_core.config import ApiSettings, get_api_settings

_engine: Engine | None = None


def create_db_engine(database_url: str, *, echo: bool = False) -> Engine:
    """Build a SQLAlchemy engine for ``database_url``.

    ``pool_pre_ping`` is on because the API sits behind long-lived pools that
    otherwise hand out connections a restarted Postgres has already dropped.
    SQLite gets the in-memory-friendly connect args so tests can share one
    connection across sessions.
    """
    connect_args: dict[str, Any] = {}
    if database_url.startswith("sqlite"):
        connect_args["check_same_thread"] = False
    return create_engine(
        database_url,
        echo=echo,
        pool_pre_ping=True,
        connect_args=connect_args,
    )


def get_db_engine(settings: ApiSettings | None = None) -> Engine:
    """Return the process-wide engine, creating it on first use."""
    global _engine
    if _engine is None:
        resolved = settings or get_api_settings()
        _engine = create_db_engine(resolved.database_url, echo=resolved.db_echo)
    return _engine


def set_db_engine(engine: Engine | None) -> None:
    """Install (or clear) the process-wide engine. For tests and migrations."""
    global _engine
    _engine = engine


@contextmanager
def session_scope(engine: Engine | None = None) -> Iterator[Session]:
    """Transactional session: commit on success, roll back on exception.

    Use this for background work (scheduler ticks, reconciliation). Request
    handlers use :func:`session_dependency`, which leaves commit timing to the
    handler.
    """
    with Session(engine or get_db_engine()) as session:
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise


def session_dependency() -> Iterator[Session]:
    """FastAPI dependency yielding a request-scoped session.

    Deliberately does *not* auto-commit: a route that mutates state commits
    explicitly, so a read-only route can never write by accident.
    """
    with Session(get_db_engine()) as session:
        yield session
