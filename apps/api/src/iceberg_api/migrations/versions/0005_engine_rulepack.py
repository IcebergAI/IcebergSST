"""Engines report the rule pack they are running

Rule packs ship inside engine images (ADR 0008), so the fleet is the only place
that knows which rules are actually in force. Recording each engine's report is
what lets ``GET /rules`` answer the question — and represent a rolling deploy
honestly, where two rule-pack versions are both correct at once (#70).

Revision ID: 0005
Revises: 0004
Create Date: 2026-07-30 01:45:00.000000+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

#: JSONB on Postgres, plain JSON elsewhere — the variant every JSON column in this
#: schema uses (``iceberg_core.models.base.json_type``).
_JSON = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")


def upgrade() -> None:
    with op.batch_alter_table("engine", schema=None) as batch_op:
        # Not nullable, with an empty default: an engine that has never reported a
        # pack reads as "reported nothing", which is the truth, rather than as a
        # null every caller has to remember to handle.
        batch_op.add_column(
            sa.Column("rulepack", _JSON, nullable=False, server_default=sa.text("'{}'"))
        )


def downgrade() -> None:
    with op.batch_alter_table("engine", schema=None) as batch_op:
        batch_op.drop_column("rulepack")
