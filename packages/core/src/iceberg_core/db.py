"""Database engine and session management.

**API role only.** Importing this module from ``apps/engine`` violates ADR 0002
and is caught by ``apps/engine/tests/test_no_db_access.py``, which imports the
engine and asserts this module never appears in ``sys.modules``.

Engines reach the database through the API or not at all.
"""

import threading
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from sqlalchemy import Engine, event
from sqlmodel import Session, create_engine

from iceberg_core.config import ApiSettings, get_api_settings

_engine: Engine | None = None
_engine_lock = threading.Lock()


def create_db_engine(database_url: str, *, echo: bool = False) -> Engine:
    """Build a SQLAlchemy engine for ``database_url``.

    ``pool_pre_ping`` is on because the API sits behind long-lived pools that
    otherwise hand out connections a restarted Postgres has already dropped.
    SQLite gets the in-memory-friendly connect args so tests can share one
    connection across sessions, plus foreign-key enforcement (see
    :func:`enforce_sqlite_foreign_keys`).
    """
    connect_args: dict[str, Any] = {}
    if database_url.startswith("sqlite"):
        connect_args["check_same_thread"] = False
    engine = create_engine(
        database_url,
        echo=echo,
        pool_pre_ping=True,
        connect_args=connect_args,
    )
    if engine.dialect.name == "sqlite":
        enforce_sqlite_foreign_keys(engine)
    return engine


def enforce_sqlite_foreign_keys(engine: Engine) -> None:
    """Turn on ``PRAGMA foreign_keys`` for every SQLite connection.

    SQLite ignores foreign keys unless asked per connection. Left off, an
    ``ON DELETE CASCADE`` quietly does nothing and a test suite happily accepts
    orphan rows that Postgres would have refused — the schema would only be wrong
    in production. Turning it on makes the test database behave like the real one.
    """

    @event.listens_for(engine, "connect")
    def _set_pragma(dbapi_connection: Any, _record: Any) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


def get_db_engine(settings: ApiSettings | None = None) -> Engine:
    """Return the process-wide engine, creating it on first use.

    Locked, because first use is concurrent: the background-maintenance thread
    and the first request (FastAPI runs sync dependencies in a threadpool) can
    both arrive here at process start, and without the lock each would build an
    engine — the loser's connection pool never disposed for the process lifetime.
    """
    global _engine
    if _engine is None:
        with _engine_lock:
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
