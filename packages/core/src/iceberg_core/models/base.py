"""Base model conventions for every IcebergSST table.

Conventions (see ``docs/data-model.md``):

* **UUID primary keys**, generated client-side, so a row can be referenced
  before it is flushed and ids leak no ordering information.
* **Timezone-aware timestamps**, always UTC. ``created_at`` is set on insert,
  ``updated_at`` maintained by SQLAlchemy's ``onupdate``.
* **Explicit ``__tablename__``** on every table (singular, snake_case) rather
  than SQLModel's implicit lowercased class name.
* **Deterministic constraint names** via a metadata naming convention, so
  Alembic autogenerate produces stable, reviewable migrations instead of
  database-assigned names nobody can predict.
* **Portable column types.** JSON columns are ``JSONB`` on Postgres and plain
  ``JSON`` elsewhere, so the SQLite-backed test suite exercises the same models.
"""

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import JSON, DateTime, MetaData, Text
from sqlalchemy import Enum as SAEnum
from sqlalchemy.dialects import postgresql
from sqlmodel import Field, SQLModel

#: Applied to the shared SQLModel metadata below. ``%(column_0_N_name)s`` names
#: multi-column constraints after all their columns, which keeps composite index
#: names self-describing.
NAMING_CONVENTION: dict[str, str] = {
    "ix": "ix_%(table_name)s_%(column_0_N_name)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

# SQLModel owns a single global MetaData; installing the convention on it before
# any table is defined is what makes every table below inherit it. Alembic's
# env.py targets this same object.
SQLModel.metadata.naming_convention = NAMING_CONVENTION
metadata: MetaData = SQLModel.metadata


def utc_now() -> datetime:
    """Current time as a timezone-aware UTC datetime.

    Naive datetimes are banned in this codebase: a scan that straddles a DST
    boundary or a lease that expires "an hour ago" is not a bug worth having.
    """
    return datetime.now(UTC)


def utc_timestamp_type() -> Any:
    """Column type for every timestamp: ``TIMESTAMP WITH TIME ZONE``.

    Returns ``Any`` because SQLModel annotates ``Field(sa_type=...)`` as
    ``type[Any]`` while parameterized SQLAlchemy types must be passed as
    instances; the alternative is a cast at every model field.
    """
    return DateTime(timezone=True)


def json_type() -> Any:
    """JSON column type — ``JSONB`` on Postgres, ``JSON`` elsewhere.

    The variant keeps Postgres's indexable binary JSON in production while the
    test suite (SQLite) stores the same values as text.
    """
    return JSON().with_variant(postgresql.JSONB(astext_type=Text()), "postgresql")


def enum_type[EnumT: StrEnum](enum_class: type[EnumT], *, name: str) -> Any:
    """Column type for a :class:`~enum.StrEnum`, stored as a plain VARCHAR.

    ``native_enum=False`` is deliberate. Native Postgres enum types make adding
    a value a schema migration with table locks; a bare VARCHAR makes it a code
    change, and behaves identically on SQLite.

    **No CHECK constraint, decided rather than defaulted** (#197). SQLAlchemy
    would emit one under ``create_constraint=True``; ``validate_strings=True``
    gives bind-time validation only, so an out-of-band write can put a value in
    the column that the enum does not know. Three things settle it:

    * A CHECK reintroduces exactly the cost ``native_enum=False`` was chosen to
      avoid. Adding a value becomes DROP CONSTRAINT / ADD CONSTRAINT — a table
      scan under an ACCESS EXCLUSIVE lock on Postgres — which is the native enum's
      pain spelled differently.
    * It defends against a writer this architecture says does not exist. Only the
      API writes (ADR 0002), so "out of band" means someone holding the database
      credentials directly — and they can drop the constraint as easily as they
      can violate it. It stops a typo in a manual UPDATE, not an adversary.
    * The value could never be *believed* anyway. Reading an unknown one raises
      ``LookupError`` naming the column's enum and its legal values, so the
      failure is loud and immediate rather than a wrong answer. That property is
      what the trade rests on, so ``packages/core/tests/test_enum_columns.py``
      pins it.

    Vocabulary lives in code; the database stores what the code wrote.
    """
    return SAEnum(
        enum_class,
        name=name,
        native_enum=False,
        length=32,
        values_callable=lambda enum: [member.value for member in enum],
        validate_strings=True,
    )


class IcebergModel(SQLModel):
    """Base for all tables: UUID primary key plus a creation timestamp.

    Timestamp columns are declared with ``sa_type`` rather than ``sa_column``
    deliberately: a ``Column`` instance on a shared base class would be handed
    to every subclass, and SQLAlchemy refuses to attach one column to two
    tables.
    """

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    created_at: datetime = Field(
        default_factory=utc_now,
        sa_type=utc_timestamp_type(),
        nullable=False,
    )


class TimestampedModel(IcebergModel):
    """Base for mutable tables: adds a self-maintaining ``updated_at``."""

    updated_at: datetime = Field(
        default_factory=utc_now,
        sa_type=utc_timestamp_type(),
        sa_column_kwargs={"onupdate": utc_now},
        nullable=False,
    )
