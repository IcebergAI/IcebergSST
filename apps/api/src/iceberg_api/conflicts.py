"""Losing a uniqueness race is a 409, not a 500 (#197).

Every "a X with that name already exists" check in this API is a SELECT followed
by an INSERT. That guards the *sequential* case — an operator who types a name
already in use — and nothing else: two concurrent requests can both find nothing,
both insert, and the database, where the constraint actually lives, fails the
second one. Without this the loser gets an unhandled ``IntegrityError`` and a
500, for a condition the route already has a status code and a message for.

The pattern is `register_engine`'s, factored out rather than copied a sixth time.
"""

from typing import Any

import structlog
from fastapi import HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session

logger = structlog.get_logger()

#: SQLSTATE for a unique-violation, which is the only integrity failure this
#: turns into a 409. Anything else — a foreign key, a check constraint — is a bug
#: or a race this has no answer for, and dressing it as "that name is taken"
#: would send an operator looking in the wrong place.
_UNIQUE_VIOLATION = "23505"


def commit_or_conflict(db: Session, detail: str) -> None:
    """Commit; answer ``409`` with ``detail`` if a unique constraint refused it.

    The rollback matters as much as the status: the session holds a failed
    transaction afterwards, and every later statement on it — including the ones
    a dependency runs on the way out — would fail too.
    """
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        if not _is_unique_violation(exc):
            raise
        logger.info("write_lost_a_uniqueness_race", detail=detail)
        raise HTTPException(status.HTTP_409_CONFLICT, detail) from exc


def _is_unique_violation(exc: IntegrityError) -> bool:
    """Whether the database refused this for uniqueness, in either dialect.

    SQLAlchemy has no dialect-independent class for it. Postgres reports
    SQLSTATE ``23505`` on the driver exception; SQLite has no SQLSTATE at all and
    says so in the message. Read the code where there is one and fall back to the
    text only where there is not, so a Postgres deployment never depends on
    matching English.
    """
    original: Any = exc.orig
    sqlstate = getattr(original, "sqlstate", None) or getattr(original, "pgcode", None)
    if sqlstate is not None:
        return bool(sqlstate == _UNIQUE_VIOLATION)
    return "unique constraint failed" in str(original).lower()
