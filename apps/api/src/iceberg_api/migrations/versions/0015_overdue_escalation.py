"""Escalate findings that miss their response target (#146)

``notification_delivery`` becomes a two-kind outbox. A finding *opened* is caused
by a scan and deduplicated on it; a finding *overdue* is caused by the clock
passing and has no scan at all, so it is deduplicated on the deadline it is about.

Three changes, and the third is the one that matters:

* ``kind`` — defaulted to ``finding_opened``, so every row written before
  escalations existed reads as what it was.
* ``scan_id`` becomes nullable, and ``due_at`` arrives to carry the deadline. The
  deadline is copied onto the row rather than read back off the finding because
  the finding's own ``due_at`` moves when a resolved secret comes back: a team
  that missed the *new* target should hear about it again, and one that already
  heard about the old one should not hear twice.
* A **partial unique index** over ``(channel_id, finding_id, due_at)`` for
  escalation rows. The existing unique constraint cannot do this job: it includes
  ``scan_id``, which is now NULL on these rows, and NULLs do not collide in a
  unique constraint — so an escalation would re-insert on every maintenance beat
  and mail the owning team once a minute until somebody noticed.

Enum columns are ``native_enum=False`` (VARCHAR + CHECK) per
``iceberg_core.models.base.enum_type``, so a third event kind later is a value
rather than another migration.

Revision ID: 0015
Revises: 0014
Create Date: 2026-08-16 03:00:00.000000+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0015"
down_revision: str | None = "0014"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_EVENT_KIND = ("finding_opened", "finding_overdue")

#: Mirrors `iceberg_core.models.notifications._ESCALATION_WHERE`.
_ESCALATION_WHERE = sa.text("kind = 'finding_overdue'")


def upgrade() -> None:
    with op.batch_alter_table("notification_delivery", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column(
                "kind",
                sa.Enum(
                    *_EVENT_KIND,
                    name="notification_event_kind",
                    native_enum=False,
                    length=32,
                ),
                nullable=False,
                server_default="finding_opened",
            )
        )
        batch_op.add_column(sa.Column("due_at", sa.DateTime(timezone=True), nullable=True))
        batch_op.alter_column("scan_id", existing_type=sa.Uuid(), nullable=True)
        batch_op.create_index(
            "uq_notification_delivery_escalation",
            ["channel_id", "finding_id", "due_at"],
            unique=True,
            postgresql_where=_ESCALATION_WHERE,
            sqlite_where=_ESCALATION_WHERE,
        )


def downgrade() -> None:
    # Escalation rows have no scan, and the column is about to require one. They
    # are delivery records rather than history, so dropping them is the honest
    # reversal — the alternative is inventing a scan id that never sent anything.
    op.execute(sa.text("DELETE FROM notification_delivery WHERE kind = 'finding_overdue'"))
    with op.batch_alter_table("notification_delivery", schema=None) as batch_op:
        batch_op.drop_index("uq_notification_delivery_escalation")
        batch_op.alter_column("scan_id", existing_type=sa.Uuid(), nullable=False)
        batch_op.drop_column("due_at")
        batch_op.drop_column("kind")
