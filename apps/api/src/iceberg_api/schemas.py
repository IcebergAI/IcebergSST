"""Response and request shapes for the human-facing API.

Separate from the SQLModel tables on purpose: the OpenAPI schema is the contract
(docs/api.md), and a table is free to grow a column that no client should see.
"""

import uuid
from datetime import datetime

from iceberg_core.enums import UserRole
from pydantic import BaseModel, ConfigDict, Field


class UserRead(BaseModel):
    """A user as the API exposes them."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    oidc_subject: str
    email: str
    display_name: str
    role: UserRole
    disabled: bool
    created_at: datetime
    last_login_at: datetime | None


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


class PageParams(BaseModel):
    """Shared list-endpoint query parameters."""

    limit: int = Field(default=50, ge=1, le=200)
    cursor: str | None = None
