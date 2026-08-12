"""Persist scan configuration identity and terminal coverage evidence

Revision ID: 0008
Revises: 0007
Create Date: 2026-08-12 12:00:00.000000+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_JSON = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")


def upgrade() -> None:
    with op.batch_alter_table("scan", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("source_configuration_version", sa.DateTime(timezone=True), nullable=True)
        )
        batch_op.add_column(
            sa.Column(
                "coverage_manifest",
                _JSON,
                nullable=False,
                server_default=sa.text("'{}'"),
            )
        )
    with op.batch_alter_table("scan_task", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("coverage", _JSON, nullable=False, server_default=sa.text("'{}'"))
        )


def downgrade() -> None:
    with op.batch_alter_table("scan_task", schema=None) as batch_op:
        batch_op.drop_column("coverage")
    with op.batch_alter_table("scan", schema=None) as batch_op:
        batch_op.drop_column("coverage_manifest")
        batch_op.drop_column("source_configuration_version")
