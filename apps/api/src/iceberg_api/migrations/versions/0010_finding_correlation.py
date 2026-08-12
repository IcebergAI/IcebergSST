"""Exposure-cluster correlation id on finding

``correlation_id`` is derived API-side from the stored ``secret_hash`` under a
dedicated key (ADR 0011), so the column is nullable and there is deliberately
no backfill here: deriving it needs the master key, which a migration must not
require. The maintenance loop fills NULLs once ``ICEBERG_CORRELATION_KEY_REF``
is set, and `reindex-correlation` recomputes after a key rotation. The index is
what makes "GROUP BY correlation_id" a cluster view instead of a table scan.

Revision ID: 0010
Revises: 0009
Create Date: 2026-08-12 12:00:00.000000+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0010"
down_revision: str | None = "0009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("finding", schema=None) as batch_op:
        batch_op.add_column(sa.Column("correlation_id", sa.String(length=64), nullable=True))
    op.create_index("ix_finding_correlation_id", "finding", ["correlation_id"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_finding_correlation_id", table_name="finding")
    with op.batch_alter_table("finding", schema=None) as batch_op:
        batch_op.drop_column("correlation_id")
