"""Response and request shapes for the human-facing API.

Separate from the SQLModel tables on purpose: the OpenAPI schema is the contract
(docs/api.md), and a table is free to grow a column that no client should see.
"""

import uuid
from datetime import UTC, datetime
from typing import Annotated

from iceberg_core.enums import UserRole
from pydantic import AfterValidator, BaseModel, ConfigDict, Field


def _assume_utc(value: datetime) -> datetime:
    """Attach UTC to a naive timestamp.

    Every timestamp in this system is stored as UTC (`TIMESTAMP WITH TIME ZONE`),
    but SQLite hands values back without the offset. Normalising here means the API
    contract is "always offset-aware" regardless of which database is underneath,
    rather than something clients have to infer from the deployment.
    """
    return value if value.tzinfo else value.replace(tzinfo=UTC)


#: Use for every timestamp in a response model.
UtcDatetime = Annotated[datetime, AfterValidator(_assume_utc)]


def _absolute_http_url(value: str) -> str:
    """An operator-supplied destination we are willing to POST findings to."""
    trimmed = value.strip()
    if not trimmed.startswith(("http://", "https://")):
        raise ValueError("url must start with http:// or https://")
    if " " in trimmed or any(char < " " or char == "\x7f" for char in trimmed):
        # A newline here would let a caller inject a second request line into
        # anything downstream that builds a request from this string.
        raise ValueError("url must not contain spaces or control characters")
    return trimmed


#: Use for **every** field holding an egress destination a caller can supply.
#:
#: One definition rather than a validator per schema, because the second copy is
#: what goes missing: a handoff target's update schema declared a bare ``url``
#: while only its create schema checked the scheme, so an admin could `PATCH` a
#: working target into ``file:///…`` and find out at delivery time (#180). A
#: field that cannot be declared without its validator cannot be declared without
#: its validator on one of two paths.
#:
#: Deliberately no address blocklist: a receiver is usually internal, and the
#: control is that only an admin can set one (docs/security.md § Notification
#: egress). What is refused is what is not a destination at all.
WebhookUrl = Annotated[
    str, Field(min_length=1, max_length=2048), AfterValidator(_absolute_http_url)
]


class UserRead(BaseModel):
    """A user as the API exposes them."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    oidc_subject: str
    email: str
    display_name: str
    role: UserRole
    disabled: bool
    created_at: UtcDatetime
    last_login_at: UtcDatetime | None


class MeRead(BaseModel):
    """``GET /auth/me``: who you are, plus the token the UI needs to mutate."""

    user: UserRead
    #: This session's CSRF token, for the ``X-CSRF-Token`` header on mutations.
    csrf_token: str


class UserUpdate(BaseModel):
    """``PATCH /users/{id}``: the only two things an admin may change."""

    model_config = ConfigDict(extra="forbid")

    role: UserRole | None = None
    disabled: bool | None = None


class Page[ItemT](BaseModel):
    """One page of a list endpoint.

    Cursor-based rather than offset-based: offsets skip or repeat rows when the
    underlying set changes between requests, and these lists change while an
    analyst is reading them.
    """

    items: list[ItemT]
    #: Pass back as ``?cursor=`` to continue. ``None`` means this is the last page.
    next_cursor: str | None = None
