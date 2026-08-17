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

from iceberg_core.enums import HandoffStatus, HandoffTargetType
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
