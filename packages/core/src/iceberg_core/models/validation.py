"""Opt-in, administrator-controlled credential validation policies (#151)."""

from sqlalchemy import UniqueConstraint
from sqlmodel import Field

from iceberg_core.models.base import TimestampedModel


class ValidationPolicy(TimestampedModel, table=True):
    """Authorization and resource limits for one detector/provider pair.

    A policy is disabled by default. ``validator_id`` names reviewed engine code;
    ``contract_version`` pins the safe, side-effect-free protocol that code must
    report back. No credential or provider response is stored here.
    """

    __tablename__ = "validation_policy"
    __table_args__ = (
        UniqueConstraint("rule_id", "provider", name="uq_validation_policy_rule_id_provider"),
    )

    rule_id: str = Field(max_length=128, index=True)
    provider: str = Field(max_length=64, index=True)
    validator_id: str = Field(max_length=128)
    contract_version: str = Field(max_length=64)
    enabled: bool = Field(default=False, index=True)
    rationale: str = Field(max_length=2000)
    timeout_seconds: float = Field(default=5.0, ge=0.1, le=30.0)
    requests_per_minute: int = Field(default=30, ge=1, le=10_000)
    max_attempts_per_task: int = Field(default=1, ge=1, le=10)
