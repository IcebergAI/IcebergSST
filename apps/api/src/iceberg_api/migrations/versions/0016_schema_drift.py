"""Reconcile three columns the models and the migrations disagreed about (#147)

Found by the release rehearsal on its first run, which is the point of it: it
compares the *Postgres* schema to the models, and all three of these are
differences SQLite cannot express. `apps/api/tests/test_migrations.py` compares
the same way on SQLite and has been green throughout — a batch-mode ALTER there
rebuilds the table, `VARCHAR(n)` is not length-checked at all, and a unique index
and a unique constraint are the same object.

None of the three is a behaviour bug today. They matter because autogenerate
compares against the models: with the schema drifting, the next `--autogenerate`
would emit these fixes mixed into an unrelated migration, and the reviewer of
*that* pull request would have to work out which half was intended.

* `finding.validation_reason` — declared `length=64` in 0009 while
  `enum_type()` produces 32 for every enum in the codebase. Narrowed to 32; the
  longest value is `policy_budget_exhausted` at 23 characters, so nothing is
  truncated and the CHECK-free VARCHAR keeps behaving identically.
* `validation_policy.rationale` — created as `TEXT` in 0009 while the model says
  `max_length=2000`. Narrowed to match, which is also the limit the API already
  validates on write, so no row can exceed it.
* `owner_group.name`, `routing_rule.name`, `response_target.severity` — 0014
  created these as unique *indexes* while `Field(unique=True)` produces a unique
  *constraint*, which is how every other unique column in this schema (0001's
  `uq_source_name`, `uq_engine_name`) was created. Functionally identical on
  Postgres; different objects in the catalog, and the models are the reference.

Reversible, and the downgrade genuinely restores the previous shape rather than
approximating it — widening a VARCHAR and swapping a constraint back for an index
both lose nothing.

Revision ID: 0016
Revises: 0015
Create Date: 2026-08-16 05:00:00.000000+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0016"
down_revision: str | None = "0015"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_VALIDATION_REASON = (
    "credential_accepted",
    "credential_rejected",
    "provider_rate_limited",
    "provider_unavailable",
    "inconclusive_response",
    "timeout",
    "protocol_error",
    "policy_budget_exhausted",
)

#: (table, column, index name, constraint name) for the three unique columns 0014
#: created the wrong way round.
_UNIQUE = (
    ("owner_group", "name", "ix_owner_group_name", "uq_owner_group_name"),
    ("routing_rule", "name", "ix_routing_rule_name", "uq_routing_rule_name"),
    ("response_target", "severity", "ix_response_target_severity", "uq_response_target_severity"),
)


def _reason(length: int) -> sa.Enum:
    return sa.Enum(*_VALIDATION_REASON, name="validation_reason", native_enum=False, length=length)


def upgrade() -> None:
    with op.batch_alter_table("finding", schema=None) as batch_op:
        batch_op.alter_column(
            "validation_reason",
            existing_type=_reason(64),
            type_=_reason(32),
            existing_nullable=True,
        )

    with op.batch_alter_table("validation_policy", schema=None) as batch_op:
        batch_op.alter_column(
            "rationale",
            existing_type=sa.Text(),
            type_=sa.String(length=2000),
            existing_nullable=False,
        )

    for table, column, index_name, constraint_name in _UNIQUE:
        with op.batch_alter_table(table, schema=None) as batch_op:
            batch_op.drop_index(index_name)
            batch_op.create_unique_constraint(constraint_name, [column])


def downgrade() -> None:
    for table, column, index_name, constraint_name in reversed(_UNIQUE):
        with op.batch_alter_table(table, schema=None) as batch_op:
            batch_op.drop_constraint(constraint_name, type_="unique")
            batch_op.create_index(index_name, [column], unique=True)

    with op.batch_alter_table("validation_policy", schema=None) as batch_op:
        batch_op.alter_column(
            "rationale",
            existing_type=sa.String(length=2000),
            type_=sa.Text(),
            existing_nullable=False,
        )

    with op.batch_alter_table("finding", schema=None) as batch_op:
        batch_op.alter_column(
            "validation_reason",
            existing_type=_reason(32),
            type_=_reason(64),
            existing_nullable=True,
        )
