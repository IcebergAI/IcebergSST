"""Finding scan references become RESTRICT, not CASCADE

A finding's lifecycle belongs to its source; ``first_seen_scan_id`` and
``last_seen_scan_id`` are history. With CASCADE, deleting a scan row (retention,
cleanup) silently deleted every finding first- or last-seen in it — open ones
included — and their audit trail through ``finding_event``. RESTRICT makes the
database refuse instead.

Revision ID: 0004
Revises: 0003
Create Date: 2026-07-30 00:45:00.000000+00:00
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_SCAN_FKS = ("first_seen_scan_id", "last_seen_scan_id")


def upgrade() -> None:
    with op.batch_alter_table("finding", schema=None) as batch_op:
        for column in _SCAN_FKS:
            batch_op.drop_constraint(batch_op.f(f"fk_finding_{column}_scan"), type_="foreignkey")
            batch_op.create_foreign_key(
                batch_op.f(f"fk_finding_{column}_scan"),
                "scan",
                [column],
                ["id"],
                ondelete="RESTRICT",
            )


def downgrade() -> None:
    with op.batch_alter_table("finding", schema=None) as batch_op:
        for column in _SCAN_FKS:
            batch_op.drop_constraint(batch_op.f(f"fk_finding_{column}_scan"), type_="foreignkey")
            batch_op.create_foreign_key(
                batch_op.f(f"fk_finding_{column}_scan"),
                "scan",
                [column],
                ["id"],
                ondelete="CASCADE",
            )
