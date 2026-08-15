"""Make system finding events idempotent per scan (#143)

Results ingest has always been idempotent for *findings* — the
``(source_id, fingerprint)`` unique constraint plus the refresh path absorb a
repeated sighting. Nothing enforced the same for ``finding_event``, which has no
constraints at all: a re-ingested batch appending a second identical reopen or
auto-resolve row was prevented only by the state machine happening to be a no-op
the second time round.

Batched result submission (#143) makes that too thin to rely on. A partial unique
index over ``(finding_id, kind, scan_id)`` for system rows makes it structural.
Analyst rows are exempt: two people may legitimately record the same transition,
and their rows carry an actor and no scan.

``scan_id`` is RESTRICT for the same reason ``finding.first_seen_scan_id`` is
(0004) — an audit row naming a scan must not be orphaned by deleting it.

Backfilled as NULL: existing rows predate the column, so they are exempt from the
index and keep the behaviour they have always had.

Revision ID: 0013
Revises: 0012
Create Date: 2026-08-14 12:00:00.000000+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0013"
down_revision: str | None = "0012"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

#: Mirrors `iceberg_core.models.findings._SYSTEM_EVENT_WHERE`. Validation events
#: are deliberately outside it: a scan whose tasks observe a credential changing
#: status mid-run may truthfully record two, and constraining that would turn a
#: correct second observation into a failed results submission.
_SYSTEM_EVENT_WHERE = sa.text(
    "actor_id IS NULL AND scan_id IS NOT NULL AND kind IN ('reopened', 'state_change')"
)


def upgrade() -> None:
    with op.batch_alter_table("finding_event", schema=None) as batch_op:
        batch_op.add_column(sa.Column("scan_id", sa.Uuid(), nullable=True))
        batch_op.create_foreign_key(
            batch_op.f("fk_finding_event_scan_id_scan"),
            "scan",
            ["scan_id"],
            ["id"],
            ondelete="RESTRICT",
        )
        batch_op.create_index(
            "uq_finding_event_system_per_scan",
            ["finding_id", "kind", "scan_id"],
            unique=True,
            postgresql_where=_SYSTEM_EVENT_WHERE,
            sqlite_where=_SYSTEM_EVENT_WHERE,
        )


def downgrade() -> None:
    with op.batch_alter_table("finding_event", schema=None) as batch_op:
        batch_op.drop_index("uq_finding_event_system_per_scan")
        batch_op.drop_constraint(batch_op.f("fk_finding_event_scan_id_scan"), type_="foreignkey")
        batch_op.drop_column("scan_id")
