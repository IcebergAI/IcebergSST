"""Keyset-pagination and cascade-lookup indexes

Two gaps, both of which only bite once a deployment has data.

Every list endpoint orders by ``(created_at, id)`` and resumes with
``created_at > … OR (= AND id > …)``, but nothing indexed that pair — so the
findings queue, the table that grows with every scan, sorted the whole table per
page request.

And ``notification_delivery``'s foreign keys are ``ON DELETE CASCADE`` while its
only multi-column index leads on ``channel_id``, which cannot serve a lookup by
``finding_id`` or ``scan_id``. Retention deletes findings in batches of up to a
thousand and Postgres enforces each cascade with a per-row lookup, so a purge
round degenerated into a thousand sequential scans of the outbox.

Revision ID: 0007
Revises: 0006
Create Date: 2026-07-31 12:40:00.000000+00:00
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_index("ix_finding_created_at_id", "finding", ["created_at", "id"], unique=False)
    op.create_index("ix_scan_created_at_id", "scan", ["created_at", "id"], unique=False)
    op.create_index(
        "ix_notification_delivery_finding_id",
        "notification_delivery",
        ["finding_id"],
        unique=False,
    )
    op.create_index(
        "ix_notification_delivery_scan_id",
        "notification_delivery",
        ["scan_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_notification_delivery_scan_id", table_name="notification_delivery")
    op.drop_index("ix_notification_delivery_finding_id", table_name="notification_delivery")
    op.drop_index("ix_scan_created_at_id", table_name="scan")
    op.drop_index("ix_finding_created_at_id", table_name="finding")
