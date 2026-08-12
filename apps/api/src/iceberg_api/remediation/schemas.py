"""Request and response shapes for remediation actions (#142, ADR 0011).

Two rules shape these:

* **Evidence is links, never bytes.** The platform records *where proof lives*
  (a ticket, a provider console page), not the proof itself — there is no
  upload path anywhere in the system, deliberately. Links are http(s)-only and
  refuse embedded userinfo, because `https://token@host/` is exactly the kind
  of string this product exists to find.
* **Redaction is role-shaped.** Viewers see that an action happened — kind,
  actor, times, verification — but not the note or the link URLs, which are
  written by responders about internal systems. One route serves both shapes;
  the role picks which.
"""

import uuid
from datetime import UTC, datetime
from urllib.parse import urlsplit

from iceberg_core.enums import RemediationActionKind, RemediationVerification
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from iceberg_api.schemas import UtcDatetime

MAX_EVIDENCE_LINKS = 10


class EvidenceLink(BaseModel):
    """One pointer at proof: a ticket, a console page, a change record."""

    model_config = ConfigDict(extra="forbid")

    url: str = Field(min_length=1, max_length=2048)
    label: str = Field(min_length=1, max_length=200)

    @field_validator("label")
    @classmethod
    def _trimmed(cls, value: str) -> str:
        trimmed = value.strip()
        if not trimmed:
            raise ValueError("label must not be blank")
        return trimmed

    @field_validator("url")
    @classmethod
    def _http_only_no_userinfo(cls, value: str) -> str:
        parts = urlsplit(value.strip())
        if parts.scheme not in {"http", "https"}:
            raise ValueError("evidence links must be http or https URLs")
        if not parts.netloc:
            raise ValueError("evidence links must carry a host")
        if "@" in parts.netloc:
            # A credential-bearing URL submitted as evidence of credential
            # cleanup would be this product's own finding.
            raise ValueError("evidence links must not embed credentials")
        return value.strip()


class RemediationCreate(BaseModel):
    """``POST /findings/{id}/remediations``: record what was done."""

    model_config = ConfigDict(extra="forbid")

    kind: RemediationActionKind
    #: When it was performed; omitted means "when recorded". Never the future.
    occurred_at: datetime | None = None
    note: str | None = Field(default=None, max_length=2000)
    evidence_links: list[EvidenceLink] = Field(default_factory=list, max_length=MAX_EVIDENCE_LINKS)

    @model_validator(mode="after")
    def _occurred_in_the_past(self) -> RemediationCreate:
        if self.occurred_at is None:
            return self
        # A naive timestamp is read as UTC, like every timestamp in the API.
        at = self.occurred_at if self.occurred_at.tzinfo else self.occurred_at.replace(tzinfo=UTC)
        if at > datetime.now(UTC):
            raise ValueError("occurred_at must not be in the future")
        self.occurred_at = at
        return self


class RemediationVerify(BaseModel):
    """``POST .../verify``: a second look confirming the action took effect."""

    model_config = ConfigDict(extra="forbid")

    comment: str | None = Field(default=None, max_length=2000)


class RemediationRetract(BaseModel):
    """``POST .../retract``: the record was wrong. The reason is not optional —
    a retraction without one is indistinguishable from tampering."""

    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=1, max_length=2000)

    @field_validator("reason")
    @classmethod
    def _trimmed(cls, value: str) -> str:
        trimmed = value.strip()
        if not trimmed:
            raise ValueError("reason must not be blank")
        return trimmed


class RemediationRead(BaseModel):
    """An action as analysts see it: everything, URLs included."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    finding_id: uuid.UUID
    actor_id: uuid.UUID | None
    kind: RemediationActionKind
    occurred_at: UtcDatetime | None
    note: str | None
    evidence_links: list[dict[str, object]]
    guidance_version: str | None
    verification: RemediationVerification
    verified_by_id: uuid.UUID | None
    verified_at: UtcDatetime | None
    retracted_at: UtcDatetime | None
    retracted_by_id: uuid.UUID | None
    retracted_reason: str | None
    created_at: UtcDatetime


class RemediationReadRedacted(BaseModel):
    """The same action as viewers see it: the fact, not the internals.

    Labels survive so the record still says *what kind* of proof exists;
    URLs and the free-text note do not — both are written about internal
    systems, and viewers are the widest audience the console has.
    """

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    finding_id: uuid.UUID
    actor_id: uuid.UUID | None
    kind: RemediationActionKind
    occurred_at: UtcDatetime | None
    guidance_version: str | None
    verification: RemediationVerification
    verified_by_id: uuid.UUID | None
    verified_at: UtcDatetime | None
    retracted_at: UtcDatetime | None
    retracted_by_id: uuid.UUID | None
    created_at: UtcDatetime

    #: Labels only, in link order. Populated by the serializer from the row's
    #: JSON — never the URLs.
    evidence_labels: list[str] = Field(default_factory=list)
