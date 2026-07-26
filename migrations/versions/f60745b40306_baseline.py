"""baseline

The initial revision. Deliberately empty: M0 defines no tables — the first
models arrive with #31 (Source) and #34 (Scan/ScanTask). Its job is to prove the
Alembic wiring end to end and give those migrations a parent to hang from.

Revision ID: f60745b40306
Revises:
Create Date: 2026-07-26 08:40:10.809420
"""

from collections.abc import Sequence

revision: str = "f60745b40306"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
