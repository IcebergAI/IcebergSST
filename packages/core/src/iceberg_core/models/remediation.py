"""Remediation actions: what was done about an exposure, with evidence (#142).

The mutability contract, stated once and relied on everywhere:

* **Content is written once.** Kind, when it happened, the note, the evidence
  links, and the guidance version stamped at recording time never change. A
  wrong record is *retracted* (set-once fields below) and a corrected one
  recorded — the trail shows both, which is the point.
* **Verification is one-way.** ``unverified`` → ``verified``, with who and
  when; there is no un-verify, only retraction of the whole action.
* **Every change writes trail rows.** Recording, verifying, and retracting
  each add a ``FindingEvent`` (the finding's history) and an ``AuditEvent``
  (the administrative record). The rows here are the *state*; the immutable
  audit evidence #142 requires lives in those append-only tables.

Evidence is **links plus structure, never file bytes** (ADR 0011): the platform
stores where proof lives (a ticket, a provider console), not the proof itself —
the same reasoning that keeps plaintext secrets out (ADR 0004) keeps arbitrary
uploaded documents out. Link URLs may later be scrubbed to labels-only by the
retention window; the row itself is never deleted while its finding exists.
"""

import uuid
from datetime import datetime
from typing import Any

from sqlmodel import Field

from iceberg_core.enums import RemediationActionKind, RemediationVerification
from iceberg_core.models.base import (
    IcebergModel,
    enum_type,
    json_type,
    utc_timestamp_type,
)


class RemediationAction(IcebergModel, table=True):
    """One containment action taken on one finding.

    Not a :class:`TimestampedModel`: content never updates, and the set-once
    fields below carry their own timestamps. ``created_at`` is when it was
    *recorded*; ``occurred_at`` is when the responder says it was *done*.
    """

    __tablename__ = "remediation_action"

    finding_id: uuid.UUID = Field(foreign_key="finding.id", ondelete="CASCADE", index=True)

    #: Null for actions recorded by a later system door; today always a person.
    actor_id: uuid.UUID | None = Field(
        default=None,
        foreign_key="app_user.id",
        ondelete="SET NULL",
    )
    kind: RemediationActionKind = Field(
        sa_type=enum_type(RemediationActionKind, name="remediation_action_kind")
    )
    #: When the action was performed, per the responder. Null means "when
    #: recorded" — the honest default for work done at the keyboard.
    occurred_at: datetime | None = Field(default=None, sa_type=utc_timestamp_type())
    note: str | None = Field(default=None)

    #: ``[{"url": …, "label": …}]``, validated at the API layer. After the
    #: retention scrub, ``[{"label": …, "scrubbed": true}]`` — the reference
    #: survives, the potentially internal URL does not.
    evidence_links: list[dict[str, Any]] = Field(default_factory=list, sa_type=json_type())

    #: The guidance-pack version shown when this was recorded, so "what were
    #: they told to do" is answerable after the guidance changes.
    guidance_version: str | None = Field(default=None, max_length=64)

    verification: RemediationVerification = Field(
        default=RemediationVerification.UNVERIFIED,
        sa_type=enum_type(RemediationVerification, name="remediation_verification"),
    )
    verified_by_id: uuid.UUID | None = Field(
        default=None,
        foreign_key="app_user.id",
        ondelete="SET NULL",
    )
    verified_at: datetime | None = Field(default=None, sa_type=utc_timestamp_type())

    retracted_at: datetime | None = Field(default=None, sa_type=utc_timestamp_type())
    retracted_by_id: uuid.UUID | None = Field(
        default=None,
        foreign_key="app_user.id",
        ondelete="SET NULL",
    )
    retracted_reason: str | None = Field(default=None)
