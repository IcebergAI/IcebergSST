"""Request and response shapes for external hand-over (#141).

A hand-over target is a stronger version of a notification channel: it carries
finding context off the deployment *and* creates an object in somebody else's
system. The same three rules apply, enforced the same way (docs/handoff.md):

* **The ``config`` blob is validated per target type**, never stored as whatever
  JSON arrived — and validated by *one* function that both create and update
  call. A URL that is not a URL should fail when an admin saves the target, not
  at delivery time when the finding has already been requested.
* **A target secret never appears in a response.** It arrives once, is sealed
  through the secret store (ADR 0007), and the row keeps only the opaque ref.
  Responses carry ``has_secret``.
* **The reply from the receiver is somebody else's data.** ``external_id`` and
  ``external_url`` are echoed back as strings and nothing more.
"""

import uuid
from typing import Any

from iceberg_core.enums import (
    FindingState,
    HandoffExternalState,
    HandoffStatus,
    HandoffTargetType,
)
from pydantic import BaseModel, ConfigDict, Field, SecretStr

from iceberg_api.notifications.schemas import SECRET_REF_KEY, EventFilter
from iceberg_api.schemas import UtcDatetime, WebhookUrl


class WebhookTargetConfig(BaseModel):
    """``type=webhook``: where to POST the hand-over.

    Deliberately narrower than a notification channel's config — no custom
    headers. A notification's headers exist to satisfy a gateway's routing; a
    hand-over already carries its routing in the payload, and every header this
    sender needs (signature, timestamp, idempotency key) is one it sets itself.
    Adding an operator-controlled header set here would be a second way to smuggle
    a credential into plain JSON, for no case anyone has.

    ``extra="forbid"`` keeps this model and the sender in step: a key this model
    omits is one no admin can store and no sender will ever read.
    """

    model_config = ConfigDict(extra="forbid")

    url: WebhookUrl
    #: Read back out of the sealed ref at delivery time and sent as the payload
    #: signature. Never supplied by a caller — see ``_validated_config``.
    secret_ref: str | None = None


CONFIG_MODELS: dict[HandoffTargetType, type[BaseModel]] = {
    HandoffTargetType.WEBHOOK: WebhookTargetConfig,
}


def validate_config(target_type: HandoffTargetType, config: dict[str, Any]) -> dict[str, Any]:
    """Validate a config blob for its type and return it normalised.

    The single definition both ``POST`` and ``PATCH`` go through. Raises
    pydantic's ``ValidationError``; the route turns that into a 422.
    """
    model = CONFIG_MODELS[target_type]
    return model.model_validate(config).model_dump(mode="json", exclude_none=True)


def public_config(config: dict[str, Any]) -> dict[str, Any]:
    """The config as a client may see it: everything except the sealed ref."""
    return {key: value for key, value in config.items() if key != SECRET_REF_KEY}


class HandoffTargetCreate(BaseModel):
    """``POST /handoff/targets``."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=255)
    type: HandoffTargetType = HandoffTargetType.WEBHOOK
    config: dict[str, Any] = Field(default_factory=dict)
    #: Which findings may be handed to this target. The same filter vocabulary a
    #: notification channel uses, so an operator learns it once.
    event_filter: EventFilter = Field(default_factory=EventFilter)
    #: Sealed through the secret store on the way in. Write-only.
    secret: SecretStr | None = None
    enabled: bool = True


class HandoffTargetUpdate(BaseModel):
    """``PATCH /handoff/targets/{id}``. Omitted fields are left alone.

    ``config`` is replaced wholesale and re-validated by the same function
    ``POST`` uses, rather than being patched key by key against an unvalidated
    field. That is the fix for #180 and the reason it cannot recur: there is no
    ``url`` field here to declare without a validator.

    ``type`` is not editable, for the reason a channel's is not: a config
    validated as one shape is not another shape.
    """

    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=255)
    config: dict[str, Any] | None = None
    event_filter: EventFilter | None = None
    secret: SecretStr | None = None
    enabled: bool | None = None


class HandoffTargetRead(BaseModel):
    """A target as the API exposes it — never including its secret."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    type: HandoffTargetType
    #: The stored config with the sealed ref removed. See ``has_secret``.
    config: dict[str, Any]
    event_filter: EventFilter
    has_secret: bool
    enabled: bool
    created_at: UtcDatetime
    updated_at: UtcDatetime


class HandoffTargetChoice(BaseModel):
    """A target as an **analyst** sees it: enough to choose one, and no more.

    An analyst has to be able to pick a destination — they are the role that
    hands findings over — but "which systems has this deployment approved" and
    "what URL does that one post to, and does it hold a signing key" are
    different questions. The first is needed to do the job; the second is the
    administrative detail that made the target list admin-only to begin with.

    So the config, the sealed-secret flag, and the timestamps are all absent
    here rather than blanked: a field that is not in the model cannot be
    forgotten into a response.
    """

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    type: HandoffTargetType


class HandoffRequest(BaseModel):
    """``POST /findings/{id}/handoffs``: which target to hand it to."""

    model_config = ConfigDict(extra="forbid")

    target_id: uuid.UUID


class HandoffCallback(BaseModel):
    """``POST /handoff/callback``: what the receiving system says about a work item.

    Keyed by the idempotency key we sent, because that is the value the receiver
    was told to treat as the work item's identity — asking it to hold a second
    identifier of ours would be asking for no reason.

    ``extra="forbid"`` so a receiver sending a field this does not model is told
    so, rather than having it silently dropped and wondering why nothing changed.
    """

    model_config = ConfigDict(extra="forbid")

    idempotency_key: str = Field(min_length=1, max_length=128)
    #: A closed vocabulary. The mapping from a vendor's own statuses onto these
    #: belongs on the receiving side, next to the automation that knows them.
    state: HandoffExternalState
    #: When it reached that state on their side. Optional, and only as good as
    #: what they send; the API stamps its own arrival time regardless.
    state_at: UtcDatetime | None = None
    #: Sent when the receiver is naming the work item for the first time — which
    #: is the ordinary way a lost reply to the original POST gets repaired.
    external_id: str | None = Field(default=None, max_length=255)
    external_url: str | None = Field(default=None, max_length=2048)


class HandoffConflictRead(BaseModel):
    """A hand-over whose two systems currently disagree.

    Derived at read time from the receiver's last word and the finding's state,
    so it cannot describe a disagreement that has already been settled.
    """

    model_config = ConfigDict(from_attributes=True)

    handoff_id: uuid.UUID
    finding_id: uuid.UUID
    target_id: uuid.UUID
    target_name: str
    #: Stable enough to switch on; ``reason`` is the sentence for a human.
    kind: str
    reason: str
    finding_state: FindingState
    external_state: HandoffExternalState
    external_url: str | None
    external_state_at: UtcDatetime | None


class SilentHandoffRead(BaseModel):
    """A hand-over delivered long ago that no receiver has ever reported on."""

    model_config = ConfigDict(from_attributes=True)

    handoff_id: uuid.UUID
    finding_id: uuid.UUID
    target_id: uuid.UUID
    target_name: str
    external_id: str | None
    delivered_at: UtcDatetime | None


class HandoffHealthRead(BaseModel):
    """Whether the hand-over integrations are actually working.

    Two questions an operator cannot answer from anywhere else. **Conflicts** are
    the two systems disagreeing, which is a decision waiting for somebody.
    **Silence** is the absence of evidence: a receiver with nothing to report
    looks exactly like one that has stopped calling back, so only elapsed time
    tells them apart, and only against a clock this deployment controls.
    """

    model_config = ConfigDict(from_attributes=True)

    #: How many hand-overs currently disagree with their receiver.
    conflicts: int
    #: How long a delivered hand-over may stay quiet before it is listed below.
    silent_after_hours: int
    silent: list[SilentHandoffRead]


class FindingHandoffRead(BaseModel):
    """One finding's hand-over to one target, as the API exposes it.

    Carries the delivery state an operator needs to answer "did this actually
    reach anybody?" — the status, how many attempts it took, and the error that
    ended it if it failed. ``last_error`` is ours, never a response body: what is
    on the other end is somebody else's system and could echo anything back.
    """

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    target_id: uuid.UUID
    target_name: str
    finding_id: uuid.UUID
    status: HandoffStatus
    attempts: int
    #: The value the receiver is expected to deduplicate on. Exposed because an
    #: operator chasing a missing ticket needs to be able to search for it in the
    #: receiving system.
    idempotency_key: str
    #: What the receiver called the work item, if it said so. Both may be null on
    #: a delivered hand-over: the 2xx is what said the item was created.
    external_id: str | None
    external_url: str | None
    last_error: str | None
    requested_by_id: uuid.UUID | None
    next_attempt_at: UtcDatetime
    delivered_at: UtcDatetime | None
    created_at: UtcDatetime
    updated_at: UtcDatetime

    #: What the receiver last said, and when we last heard it. Null means no
    #: callback has ever arrived — which for a hand-over delivered long ago is
    #: itself the answer to "is that integration still working?"
    external_state: HandoffExternalState | None = None
    external_state_at: UtcDatetime | None = None
    last_callback_at: UtcDatetime | None = None
    #: The disagreement between the receiver and this deployment, if there is one
    #: right now. Derived, so it disappears when the two agree.
    conflict: str | None = None
