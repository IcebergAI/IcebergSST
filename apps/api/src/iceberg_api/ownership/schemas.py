"""Request and response shapes for ownership configuration (#146).

Three small resources with one thing in common: they are *policy*, not data about
a finding. Editing them changes who is answerable for work that already exists, so
every write is admin-only and audited, and every response is shaped so a console
can render the rule set without a second round trip per row.
"""

import uuid

from iceberg_core.enums import Severity
from pydantic import BaseModel, ConfigDict, Field, field_validator

from iceberg_api.schemas import UtcDatetime

#: A rule may narrow on at most this many tags. Not a storage limit — a rule that
#: needs eight tags to express itself is a rule nobody will be able to reason
#: about when it stops matching.
MAX_SOURCE_TAGS = 8


def _clean_tags(value: list[str]) -> list[str]:
    """Trimmed, de-duplicated, order preserved.

    Case is *not* folded: source tags are free-form operator labels and "PCI" and
    "pci" are the same label to a human, so the comparison folds instead — see
    ``iceberg_api.findings.ownership``. Folding here as well would silently
    rewrite what an operator typed.
    """
    seen: set[str] = set()
    cleaned: list[str] = []
    for raw in value:
        tag = raw.strip()
        if not tag or tag.casefold() in seen:
            continue
        seen.add(tag.casefold())
        cleaned.append(tag)
    return cleaned


class OwnerGroupCreate(BaseModel):
    """``POST /owner-groups``."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=1000)
    #: Where escalations for this group go. Optional: a group with no channel is
    #: a valid owner, it is just one that has to come looking.
    notification_channel_id: uuid.UUID | None = None

    @field_validator("name")
    @classmethod
    def _trimmed(cls, value: str) -> str:
        trimmed = value.strip()
        if not trimmed:
            raise ValueError("must not be blank")
        return trimmed


class OwnerGroupUpdate(BaseModel):
    """``PATCH /owner-groups/{id}``. Every field optional; omitted means unchanged."""

    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=1000)
    notification_channel_id: uuid.UUID | None = None
    #: Disbanding a team. The group is kept rather than deleted so its findings
    #: keep their history; routing simply stops choosing it.
    disabled: bool | None = None


class OwnerGroupRead(BaseModel):
    """A group, plus what it currently owes."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    description: str | None
    notification_channel_id: uuid.UUID | None
    disabled: bool
    created_at: UtcDatetime
    updated_at: UtcDatetime

    #: Open, unsuppressed findings owned by this group, and how many of those are
    #: past their target. Counted server-side because the alternative is a console
    #: issuing one findings query per group to render a list.
    open_findings: int = 0
    overdue_findings: int = 0


class RoutingRuleCreate(BaseModel):
    """``POST /routing-rules``.

    Every matcher is optional and they are ANDed, so a body with none of them set
    creates a catch-all — which is how a default owner is expressed. Give it a
    high ``priority`` number so it is consulted last.
    """

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=255)
    owner_group_id: uuid.UUID
    #: Lower runs first. Not unique: ties break on ``(created_at, id)``, so the
    #: order is total without making "put this above that" a constraint dance.
    priority: int = Field(default=100, ge=0, le=10_000)
    source_id: uuid.UUID | None = None
    rule_id: str | None = Field(default=None, max_length=128)
    min_severity: Severity | None = None
    source_tags: list[str] = Field(default_factory=list, max_length=MAX_SOURCE_TAGS)
    enabled: bool = True

    @field_validator("name")
    @classmethod
    def _trimmed(cls, value: str) -> str:
        trimmed = value.strip()
        if not trimmed:
            raise ValueError("must not be blank")
        return trimmed

    @field_validator("source_tags")
    @classmethod
    def _tags(cls, value: list[str]) -> list[str]:
        return _clean_tags(value)


class RoutingRuleUpdate(BaseModel):
    """``PATCH /routing-rules/{id}``.

    Matchers are nullable *and* optional, which are different things: sending
    ``null`` widens the rule by dropping that matcher, omitting the field leaves
    it alone. The route reads the difference off ``model_fields_set``, the same
    way finding triage does for ``assignee_id``.
    """

    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=255)
    owner_group_id: uuid.UUID | None = None
    priority: int | None = Field(default=None, ge=0, le=10_000)
    source_id: uuid.UUID | None = None
    rule_id: str | None = Field(default=None, max_length=128)
    min_severity: Severity | None = None
    source_tags: list[str] | None = Field(default=None, max_length=MAX_SOURCE_TAGS)
    enabled: bool | None = None

    @field_validator("source_tags")
    @classmethod
    def _tags(cls, value: list[str] | None) -> list[str] | None:
        return None if value is None else _clean_tags(value)


class RoutingRuleRead(BaseModel):
    """A rule as the API exposes it."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    priority: int
    owner_group_id: uuid.UUID
    source_id: uuid.UUID | None
    rule_id: str | None
    min_severity: Severity | None
    source_tags: list[str]
    enabled: bool
    created_at: UtcDatetime
    updated_at: UtcDatetime


class ResponseTargetRead(BaseModel):
    """How long one severity may sit before it is overdue."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    severity: Severity
    hours: int
    updated_at: UtcDatetime


class ResponseTargetUpdate(BaseModel):
    """``PUT /response-targets/{severity}``.

    Only the hours: there is exactly one row per severity, seeded by migration, so
    this resource is edited and never created or deleted. A severity with no
    target would mean findings of that severity silently stop getting due dates.
    """

    model_config = ConfigDict(extra="forbid")

    #: Bounded above at ten years — a target nobody will live to see is a
    #: configuration mistake, not a policy.
    hours: int = Field(ge=1, le=87_600)
