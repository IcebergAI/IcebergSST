"""Request and response shapes for sources and schedules.

Two rules shape these:

* **A credential never appears in a response.** Not the plaintext, and not the
  sealed ref either — a ref plus a leaked master key is a credential, and no client
  has any use for one. Responses carry ``has_credential`` instead.
* **The `connection` blob is validated per source type**, not stored as whatever
  JSON arrived. A typo in ``base_url`` should fail when an admin saves the source,
  not hours later inside a scan task.
"""

import uuid
from datetime import datetime
from typing import Any

from croniter import croniter
from iceberg_core.enums import SourceType
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    field_validator,
    model_validator,
)

#: MVP scope (ARCHITECTURE.md §1). Jira and file shares are post-MVP connectors,
#: and a source nothing can scan is worse than a clear refusal.
SUPPORTED_SOURCE_TYPES = frozenset({SourceType.CONFLUENCE})


class ConfluenceConnection(BaseModel):
    """Where a Confluence instance lives and how much of it is in scope."""

    model_config = ConfigDict(extra="forbid")

    #: Instance base URL, e.g. ``https://example.atlassian.net/wiki``.
    base_url: str
    #: Space keys to scan. Empty means every space the credential can read.
    spaces: list[str] = Field(default_factory=list)
    include_attachments: bool = True

    @field_validator("base_url")
    @classmethod
    def _sane_base_url(cls, value: str) -> str:
        trimmed = value.strip().rstrip("/")
        if not trimmed.startswith(("http://", "https://")):
            raise ValueError("base_url must start with http:// or https://")
        if " " in trimmed:
            raise ValueError("base_url must not contain spaces")
        return trimmed

    @field_validator("spaces")
    @classmethod
    def _clean_spaces(cls, value: list[str]) -> list[str]:
        cleaned = [space.strip() for space in value if space.strip()]
        if len(set(cleaned)) != len(cleaned):
            raise ValueError("spaces must not repeat")
        return cleaned


CONNECTION_MODELS: dict[SourceType, type[BaseModel]] = {
    SourceType.CONFLUENCE: ConfluenceConnection,
}


def validate_connection(source_type: SourceType, connection: dict[str, Any]) -> dict[str, Any]:
    """Validate a connection blob for its type and return it normalised.

    Raises ``ValueError`` for an unsupported type, and pydantic's
    ``ValidationError`` for a malformed one — the route turns either into a 422.
    """
    model = CONNECTION_MODELS.get(source_type)
    if model is None:
        raise ValueError(
            f"the {source_type.value} connector is not available yet; "
            f"supported types: {', '.join(sorted(t.value for t in SUPPORTED_SOURCE_TYPES))}"
        )
    return model.model_validate(connection).model_dump(mode="json")


class SourceCreate(BaseModel):
    """``POST /sources``."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=255)
    type: SourceType
    connection: dict[str, Any]
    #: Stored sealed, through the secret store (ADR 0007). Write-only.
    credential: SecretStr | None = None
    enabled: bool = True


class SourceUpdate(BaseModel):
    """``PATCH /sources/{id}``. Omitted fields are left alone.

    Supplying ``credential`` rotates it. There is no way to *remove* a credential:
    a source that cannot authenticate cannot be scanned, so deleting the source is
    the honest operation.
    """

    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=255)
    connection: dict[str, Any] | None = None
    credential: SecretStr | None = None
    enabled: bool | None = None


class SourceRead(BaseModel):
    """A source as the API exposes it — never including its credential."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    type: SourceType
    connection: dict[str, Any]
    enabled: bool
    #: Whether a credential is stored. The ref itself is deliberately not exposed.
    has_credential: bool
    created_at: datetime
    updated_at: datetime


class ConnectivityResult(BaseModel):
    """``POST /sources/{id}/test``: can we reach it with the stored credential?"""

    reachable: bool
    #: HTTP status the source answered with, when it answered at all.
    status_code: int | None = None
    #: A short, bounded explanation. Never echoes the credential or a response body.
    detail: str


class ScheduleCreate(BaseModel):
    """``POST /schedules``."""

    model_config = ConfigDict(extra="forbid")

    source_id: uuid.UUID
    cron: str = Field(min_length=1, max_length=128)
    enabled: bool = True

    @field_validator("cron")
    @classmethod
    def _valid_cron(cls, value: str) -> str:
        expression = value.strip()
        if not croniter.is_valid(expression):
            raise ValueError("cron must be a valid 5-field expression, e.g. '0 3 * * *'")
        return expression


class ScheduleUpdate(BaseModel):
    """``PATCH /schedules/{id}``."""

    model_config = ConfigDict(extra="forbid")

    cron: str | None = Field(default=None, min_length=1, max_length=128)
    enabled: bool | None = None

    @model_validator(mode="after")
    def _valid_cron(self) -> "ScheduleUpdate":
        if self.cron is not None and not croniter.is_valid(self.cron.strip()):
            raise ValueError("cron must be a valid 5-field expression, e.g. '0 3 * * *'")
        return self


class ScheduleRead(BaseModel):
    """A schedule as the API exposes it."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    source_id: uuid.UUID
    cron: str
    enabled: bool
    next_run_at: datetime | None
    last_run_at: datetime | None
    created_at: datetime
    updated_at: datetime
