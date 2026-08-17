"""Record what the receiving system says back (#141)

The inbound half of the hand-over, and the shape follows from one decision:
**what a receiver says is recorded here, never written onto the finding.**

A finding's state is a decision made by a named analyst, through a state machine
that enforces the legal moves and the deployment's evidence policy
(``iceberg_api.findings.triage``). A receiver is not a person and has no standing
to make that decision, so its report is evidence about the work item and nothing
more. Keeping the two vocabularies apart — ``handoff_external_state`` beside
``finding.state`` — is what makes a disagreement between them expressible instead
of a value that silently overwrote the other.

Which is why there is **no conflict column**. A conflict is a disagreement
between ``external_state`` and the finding's current state, so it is derived at
read time and cannot go stale: it clears by itself when the two agree, whether
that is the receiver moving on or an analyst triaging the finding. What *is*
stored is the human judgement "I have looked, and this divergence is fine" —
pinned to the state it was made about, so a receiver moving on re-raises it
rather than staying silenced by a decision about a different situation.

``last_callback_at`` is ours rather than theirs, and is the sync-health signal: a
hand-over delivered weeks ago whose receiver has never called back is a different
problem from one that reported yesterday, and only a clock we control can tell
them apart.

Revision ID: 0018
Revises: 0017
Create Date: 2026-08-17 22:59:26.881061+00:00
"""

from collections.abc import Sequence
from datetime import datetime

import sqlalchemy as sa
from alembic import op

revision: str = "0018"
down_revision: str | None = "0017"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_EXTERNAL_STATE = ("open", "in_progress", "resolved", "rejected", "cancelled")


def _state_column(name: str) -> sa.Column[str]:
    return sa.Column(
        name,
        sa.Enum(*_EXTERNAL_STATE, name="handoff_external_state", native_enum=False, length=32),
        nullable=True,
    )


def _timestamp_column(name: str) -> sa.Column[datetime]:
    return sa.Column(name, sa.DateTime(timezone=True), nullable=True)


def upgrade() -> None:
    with op.batch_alter_table("finding_handoff", schema=None) as batch_op:
        # Every column is nullable: an existing hand-over has simply never been
        # reported on, and null says exactly that. A default would claim the
        # receiver had said something.
        batch_op.add_column(_state_column("external_state"))
        batch_op.add_column(_timestamp_column("external_state_at"))
        batch_op.add_column(_timestamp_column("last_callback_at"))
        batch_op.add_column(_state_column("conflict_dismissed_state"))
        batch_op.add_column(_timestamp_column("conflict_dismissed_at"))
        batch_op.add_column(sa.Column("conflict_dismissed_by_id", sa.Uuid(), nullable=True))
        batch_op.create_foreign_key(
            batch_op.f("fk_finding_handoff_conflict_dismissed_by_id_app_user"),
            "app_user",
            ["conflict_dismissed_by_id"],
            ["id"],
            # The judgement outlives the account that made it, for the reason
            # `requested_by_id` does: "who decided that divergence was fine" has
            # to stay answerable after somebody leaves.
            ondelete="SET NULL",
        )


def downgrade() -> None:
    with op.batch_alter_table("finding_handoff", schema=None) as batch_op:
        batch_op.drop_constraint(
            batch_op.f("fk_finding_handoff_conflict_dismissed_by_id_app_user"), type_="foreignkey"
        )
        batch_op.drop_column("conflict_dismissed_by_id")
        batch_op.drop_column("conflict_dismissed_at")
        batch_op.drop_column("conflict_dismissed_state")
        batch_op.drop_column("last_callback_at")
        batch_op.drop_column("external_state_at")
        batch_op.drop_column("external_state")
