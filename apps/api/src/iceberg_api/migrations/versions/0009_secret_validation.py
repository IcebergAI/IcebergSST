"""Add opt-in validation policies and structured finding liveness metadata.

Revision ID: 0009
Revises: 0008
Create Date: 2026-08-12 20:00:00.000000+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
import sqlmodel.sql.sqltypes
from alembic import op

revision: str = "0009"
down_revision: str | None = "0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "validation_policy",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("rule_id", sqlmodel.sql.sqltypes.AutoString(length=128), nullable=False),
        sa.Column("provider", sqlmodel.sql.sqltypes.AutoString(length=64), nullable=False),
        sa.Column("validator_id", sqlmodel.sql.sqltypes.AutoString(length=128), nullable=False),
        sa.Column("contract_version", sqlmodel.sql.sqltypes.AutoString(length=64), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("timeout_seconds", sa.Float(), nullable=False),
        sa.Column("requests_per_minute", sa.Integer(), nullable=False),
        sa.Column("max_attempts_per_task", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_validation_policy")),
        sa.UniqueConstraint(
            "rule_id",
            "provider",
            name="uq_validation_policy_rule_id_provider",
        ),
    )
    op.create_index(
        op.f("ix_validation_policy_enabled"),
        "validation_policy",
        ["enabled"],
        unique=False,
    )
    op.create_index(
        op.f("ix_validation_policy_provider"),
        "validation_policy",
        ["provider"],
        unique=False,
    )
    op.create_index(
        op.f("ix_validation_policy_rule_id"),
        "validation_policy",
        ["rule_id"],
        unique=False,
    )

    with op.batch_alter_table("finding", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column(
                "validation_provider",
                sqlmodel.sql.sqltypes.AutoString(length=64),
                nullable=True,
            )
        )
        batch_op.add_column(
            sa.Column(
                "validation_validator_id",
                sqlmodel.sql.sqltypes.AutoString(length=128),
                nullable=True,
            )
        )
        batch_op.add_column(
            sa.Column(
                "validation_contract_version",
                sqlmodel.sql.sqltypes.AutoString(length=64),
                nullable=True,
            )
        )
        batch_op.add_column(
            sa.Column(
                "validation_status",
                sa.Enum(
                    "live",
                    "revoked",
                    "unknown",
                    "blocked",
                    "error",
                    name="validation_status",
                    native_enum=False,
                    length=32,
                ),
                nullable=True,
            )
        )
        batch_op.add_column(
            sa.Column(
                "validation_reason",
                sa.Enum(
                    "credential_accepted",
                    "credential_rejected",
                    "provider_rate_limited",
                    "provider_unavailable",
                    "inconclusive_response",
                    "timeout",
                    "protocol_error",
                    "policy_budget_exhausted",
                    name="validation_reason",
                    native_enum=False,
                    length=64,
                ),
                nullable=True,
            )
        )
        batch_op.add_column(sa.Column("validated_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("finding", schema=None) as batch_op:
        batch_op.drop_column("validated_at")
        batch_op.drop_column("validation_reason")
        batch_op.drop_column("validation_status")
        batch_op.drop_column("validation_contract_version")
        batch_op.drop_column("validation_validator_id")
        batch_op.drop_column("validation_provider")

    op.drop_index(op.f("ix_validation_policy_rule_id"), table_name="validation_policy")
    op.drop_index(op.f("ix_validation_policy_provider"), table_name="validation_policy")
    op.drop_index(op.f("ix_validation_policy_enabled"), table_name="validation_policy")
    op.drop_table("validation_policy")
