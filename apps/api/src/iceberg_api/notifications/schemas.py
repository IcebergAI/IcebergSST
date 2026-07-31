"""Request and response shapes for notification channels (#72).

A webhook channel is a deliberate egress path: it sends redacted snippets and
resource locations to an operator-supplied URL (docs/security.md § Notification
egress). Three rules follow from that, and they are what these models enforce:

* **The `config` blob is validated per channel type**, never stored as whatever
  JSON arrived. A webhook URL that is not a URL should fail when an admin saves
  the channel, not at 3am when a critical finding cannot be announced.
* **A channel secret never appears in a response.** It arrives once, is sealed
  through the secret store (ADR 0007), and the row keeps only the opaque ref.
  Responses carry ``has_secret`` — the same contract source credentials have.
* **Custom headers may not carry credentials.** They are stored in the clear, so
  the header names browsers and proxies use for authentication are refused with
  a pointer at ``secret``, which is the field that gets sealed.
"""

import uuid
from typing import Any

from iceberg_core.enums import NotificationChannelType, Severity
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator

from iceberg_api.schemas import UtcDatetime

#: Where the sealed secret's opaque ref lives inside ``config``. Stripped from
#: every response — a ref plus a leaked master key is a credential.
SECRET_REF_KEY = "secret_ref"  # noqa: S105  # a dict key, not a credential

#: Header names that carry credentials. Config is stored as plain JSON, so one of
#: these would be a plaintext secret at rest — the thing this system exists to
#: find in other people's systems.
_CREDENTIAL_HEADERS = frozenset({"authorization", "proxy-authorization", "cookie"})

#: Bounded so a channel cannot become a general-purpose request builder.
_MAX_HEADERS = 10
_MAX_RECIPIENTS = 50


class WebhookConfig(BaseModel):
    """``type=webhook``: where to POST, and what to send with it.

    ``extra="forbid"`` is what keeps this model and the dispatcher in step — a key
    this model omits is one no admin can store and no dispatcher will ever read.
    """

    model_config = ConfigDict(extra="forbid")

    #: Absolute http(s) URL. May be internal — a chat relay usually is — so there
    #: is no address blocklist; the control is that only an admin can set it.
    url: str = Field(min_length=1, max_length=2048)
    #: Non-secret headers, e.g. a routing key a gateway expects.
    headers: dict[str, str] = Field(default_factory=dict)
    #: Read back out of the sealed ref at dispatch time and sent as the payload
    #: signature. Never part of ``headers`` — see the module docstring.
    secret_ref: str | None = None

    @field_validator("url")
    @classmethod
    def _absolute_http_url(cls, value: str) -> str:
        trimmed = value.strip()
        if not trimmed.startswith(("http://", "https://")):
            raise ValueError("url must start with http:// or https://")
        if " " in trimmed or any(char < " " or char == "\x7f" for char in trimmed):
            # A newline here would let a caller inject a second request line into
            # anything downstream that builds a request from this string.
            raise ValueError("url must not contain spaces or control characters")
        return trimmed

    @field_validator("headers")
    @classmethod
    def _no_credential_headers(cls, value: dict[str, str]) -> dict[str, str]:
        if len(value) > _MAX_HEADERS:
            raise ValueError(f"at most {_MAX_HEADERS} headers")
        for name, header_value in value.items():
            if not name.strip():
                raise ValueError("header names must not be blank")
            if name.strip().lower() in _CREDENTIAL_HEADERS:
                raise ValueError(
                    f"{name} is stored in the clear; put the credential in `secret` instead, "
                    "which is sealed through the secret store"
                )
            if any(char in header_value for char in "\r\n"):
                raise ValueError("header values must not contain line breaks")
        return value


class EmailConfig(BaseModel):
    """``type=email``: who gets told."""

    model_config = ConfigDict(extra="forbid")

    recipients: list[str] = Field(min_length=1)

    @field_validator("recipients")
    @classmethod
    def _plausible_addresses(cls, value: list[str]) -> list[str]:
        cleaned = [address.strip() for address in value if address.strip()]
        if not cleaned:
            raise ValueError("at least one recipient is required")
        if len(cleaned) > _MAX_RECIPIENTS:
            raise ValueError(f"at most {_MAX_RECIPIENTS} recipients")
        for address in cleaned:
            # Deliberately shallow: RFC 5322 is not worth re-implementing, and the
            # SMTP server is the authority on deliverability. This catches the typo
            # that would otherwise look like a silent delivery failure.
            local, _, domain = address.partition("@")
            if not local or "." not in domain or any(char.isspace() for char in address):
                raise ValueError(f"{address!r} is not an email address")
        if len(set(cleaned)) != len(cleaned):
            raise ValueError("recipients must not repeat")
        return cleaned


CONFIG_MODELS: dict[NotificationChannelType, type[BaseModel]] = {
    NotificationChannelType.WEBHOOK: WebhookConfig,
    NotificationChannelType.EMAIL: EmailConfig,
}


def validate_config(
    channel_type: NotificationChannelType, config: dict[str, Any]
) -> dict[str, Any]:
    """Validate a config blob for its type and return it normalised.

    Raises pydantic's ``ValidationError`` for a malformed blob; the route turns
    that into a 422.
    """
    model = CONFIG_MODELS[channel_type]
    return model.model_validate(config).model_dump(mode="json", exclude_none=True)


class EventFilter(BaseModel):
    """Which findings a channel is interested in.

    Empty means everything newly opened, which is the useful default for the
    first channel an operator adds.
    """

    model_config = ConfigDict(extra="forbid")

    #: Announce this severity and above. Null means every severity.
    min_severity: Severity | None = None
    #: Restrict to these sources. Empty means all of them.
    source_ids: list[uuid.UUID] = Field(default_factory=list)


class NotificationChannelCreate(BaseModel):
    """``POST /notifications/channels``."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=255)
    type: NotificationChannelType
    config: dict[str, Any] = Field(default_factory=dict)
    event_filter: EventFilter = Field(default_factory=EventFilter)
    #: Sealed through the secret store on the way in. Write-only.
    secret: SecretStr | None = None
    enabled: bool = True


class NotificationChannelUpdate(BaseModel):
    """``PATCH /notifications/channels/{id}``. Omitted fields are left alone.

    Supplying ``secret`` rotates it. There is no way to *remove* one: a channel
    whose receiver requires a signature and no longer has a key cannot deliver, so
    deleting the channel is the honest operation.
    """

    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=255)
    config: dict[str, Any] | None = None
    event_filter: EventFilter | None = None
    secret: SecretStr | None = None
    enabled: bool | None = None


class NotificationChannelRead(BaseModel):
    """A channel as the API exposes it — never including its secret."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    type: NotificationChannelType
    #: The stored config with the sealed ref removed. See ``has_secret``.
    config: dict[str, Any]
    event_filter: EventFilter
    #: Whether a secret is stored. The ref itself is deliberately not exposed.
    has_secret: bool
    enabled: bool
    created_at: UtcDatetime
    updated_at: UtcDatetime


def public_config(config: dict[str, Any]) -> dict[str, Any]:
    """The config as a client may see it: everything except the sealed ref."""
    return {key: value for key, value in config.items() if key != SECRET_REF_KEY}
