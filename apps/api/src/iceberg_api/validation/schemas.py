"""Human API shapes for opt-in secret validation policies (#151)."""

import uuid
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from iceberg_api.schemas import UtcDatetime


class ValidationPolicyCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_id: str = Field(min_length=1, max_length=128)
    provider: str = Field(min_length=1, max_length=64)
    validator_id: str = Field(min_length=1, max_length=128)
    contract_version: str = Field(min_length=1, max_length=64)
    enabled: bool = False
    rationale: str = Field(min_length=1, max_length=2000)
    timeout_seconds: float = Field(default=5.0, ge=0.1, le=30.0)
    requests_per_minute: int = Field(default=30, ge=1, le=10_000)
    max_attempts_per_task: int = Field(default=1, ge=1, le=10)

    @field_validator("rule_id", "provider", "validator_id", "contract_version")
    @classmethod
    def _trimmed_identifier(cls, value: str) -> str:
        trimmed = value.strip()
        if not trimmed:
            raise ValueError("must not be blank")
        return trimmed


class ValidationPolicyUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    validator_id: str | None = Field(default=None, min_length=1, max_length=128)
    contract_version: str | None = Field(default=None, min_length=1, max_length=64)
    enabled: bool | None = None
    timeout_seconds: float | None = Field(default=None, ge=0.1, le=30.0)
    requests_per_minute: int | None = Field(default=None, ge=1, le=10_000)
    max_attempts_per_task: int | None = Field(default=None, ge=1, le=10)
    rationale: str | None = Field(default=None, min_length=1, max_length=2000)

    @field_validator("validator_id", "contract_version", "rationale")
    @classmethod
    def _trimmed_identifier(cls, value: str | None) -> str | None:
        if value is None:
            return None
        trimmed = value.strip()
        if not trimmed:
            raise ValueError("must not be blank")
        return trimmed

    @model_validator(mode="after")
    def _not_empty(self) -> Self:
        if not self.model_fields_set:
            raise ValueError("at least one policy field is required")
        return self


class ValidationPolicyRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    rule_id: str
    provider: str
    validator_id: str
    contract_version: str
    enabled: bool
    rationale: str
    timeout_seconds: float
    requests_per_minute: int
    max_attempts_per_task: int
    created_at: UtcDatetime
    updated_at: UtcDatetime
