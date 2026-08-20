"""Enum columns are VARCHAR with no CHECK, and that is safe because reads fail
loudly (#197).

The decision is in ``iceberg_core.models.base.enum_type``: no ``create_constraint``,
because the constraint would make adding a value a locking migration again while
defending only against a writer who — holding the database credentials directly —
could drop it just as easily.

What makes that trade sound is the *read* behaviour, not the write behaviour: a
value the enum does not know cannot be quietly believed. These pin it, so the
trade is re-examined rather than silently invalidated if SQLAlchemy ever starts
coercing instead of raising.
"""

import uuid

import pytest
from iceberg_core.models import Source
from sqlalchemy import Engine, inspect, text
from sqlalchemy.exc import StatementError
from sqlmodel import Session, select


def _insert_unknown_type(engine: Engine) -> None:
    """Write a source type no release of this code has ever defined.

    Straight through the connection, which is the only way to produce it: the
    ORM's own bind-time validation refuses it, which is the half that already
    worked.
    """
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO source (id, name, type, connection, enabled, created_at, updated_at)"
                " VALUES (:id, 'smuggled', 'gopher', '{}', 1, :now, :now)"
            ),
            {"id": str(uuid.uuid4()), "now": "2026-01-01 00:00:00"},
        )


def test_an_unknown_enum_value_is_refused_at_read_rather_than_believed(
    db_engine: Engine,
) -> None:
    _insert_unknown_type(db_engine)

    with Session(db_engine) as session, pytest.raises(LookupError) as raised:
        session.exec(select(Source)).one()

    # Names the column's vocabulary, so the error says what to look at.
    assert "gopher" in str(raised.value)
    assert "confluence" in str(raised.value)


def test_the_orm_still_refuses_to_write_one(db_engine: Engine) -> None:
    """The half that does not depend on the decision above: bind-time validation
    (`validate_strings=True`) is what stops this code path storing nonsense."""
    with Session(db_engine) as session:
        session.add(Source(name="typo", type="gopher", connection={}))
        # Wrapped by SQLAlchemy on the way out of the statement; the LookupError
        # underneath is the same refusal the read side raises.
        with pytest.raises(StatementError) as raised:
            session.commit()

    assert isinstance(raised.value.orig, LookupError)


def test_enum_columns_are_plain_varchar(db_engine: Engine) -> None:
    """Not a native Postgres enum and not a constrained VARCHAR — adding a value
    stays a code change rather than a locking migration."""
    columns = {column["name"]: column for column in inspect(db_engine).get_columns("source")}

    assert "VARCHAR" in str(columns["type"]["type"]).upper()
