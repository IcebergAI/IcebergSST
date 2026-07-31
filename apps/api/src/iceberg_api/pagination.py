"""Keyset pagination for list endpoints.

Cursor-based rather than offset-based (docs/api.md § Conventions). Offsets skip or
repeat rows when the underlying set shifts between requests, and these lists shift
while an analyst is reading them — a new scan finishes, a finding is triaged.

The cursor is the last row's ``(created_at, id)``, which is a total order because
``id`` breaks ties. It is opaque to clients on purpose: base64 discourages anyone
from constructing one by hand, and nothing about it is secret or trusted — a
malformed cursor is a 400, never a wrong page.
"""

import base64
import binascii
import json
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

from fastapi import HTTPException, status
from sqlalchemy import ColumnElement, and_, or_
from sqlmodel.sql.expression import SelectOfScalar

from iceberg_api.schemas import Page

DEFAULT_LIMIT = 50
MAX_LIMIT = 200


class CursorError(ValueError):
    """A cursor was not one we issued."""


@dataclass(frozen=True, slots=True)
class Cursor:
    """The position of the last row on the previous page."""

    created_at: datetime
    row_id: uuid.UUID

    def encode(self) -> str:
        payload = json.dumps(
            {"created_at": self.created_at.isoformat(), "id": str(self.row_id)},
            separators=(",", ":"),
        )
        return base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")

    @classmethod
    def decode(cls, raw: str) -> Cursor:
        try:
            padded = raw + "=" * (-len(raw) % 4)
            payload: dict[str, Any] = json.loads(base64.urlsafe_b64decode(padded))
            created_at = datetime.fromisoformat(payload["created_at"])
            return cls(
                # SQLite hands back naive datetimes, so a cursor built from one
                # needs the offset restored before it can be compared.
                created_at=created_at if created_at.tzinfo else created_at.replace(tzinfo=UTC),
                row_id=uuid.UUID(payload["id"]),
            )
        except (KeyError, TypeError, ValueError, binascii.Error, json.JSONDecodeError) as exc:
            # TypeError included: valid base64 of `[]` or `null` decodes fine and
            # then fails subscripting — still a malformed cursor, still a 400.
            raise CursorError("cursor is not valid") from exc


def after[RowT](
    statement: SelectOfScalar[RowT],
    *,
    created_at: ColumnElement[datetime],
    row_id: ColumnElement[uuid.UUID],
    cursor: Cursor | None,
) -> SelectOfScalar[RowT]:
    """Order by ``(created_at, id)`` and, given a cursor, start after it.

    Written as ``a > x OR (a = x AND b > y)`` rather than a row-value comparison,
    which not every supported database version handles.
    """
    ordered = statement.order_by(created_at, row_id)
    if cursor is None:
        return ordered
    return ordered.where(
        or_(
            created_at > cursor.created_at,
            and_(created_at == cursor.created_at, row_id > cursor.row_id),
        )
    )


def resolve_cursor(raw: str | None) -> Cursor | None:
    return None if raw is None else Cursor.decode(raw)


class Keyed(Protocol):
    """A row the cursor can address: it has the two columns the order is built on."""

    created_at: datetime
    id: uuid.UUID


def position(raw: str | None) -> Cursor | None:
    """Resolve a client's cursor, or refuse the request.

    Every list endpoint answers a malformed cursor the same way, so it is answered
    once here — nothing about a cursor is trusted, and a bad one is a 400 rather
    than a silently wrong page.
    """
    try:
        return resolve_cursor(raw)
    except CursorError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "cursor is not valid") from exc


def build_page[RowT: Keyed, ItemT](
    rows: Sequence[RowT],
    *,
    limit: int,
    read: Callable[[RowT], ItemT],
) -> Page[ItemT]:
    """Turn a ``limit + 1`` probe query into a page and its continuation cursor.

    Endpoints fetch one row more than they asked for; that extra row answers "is
    there another page?" without a second count query, and it is dropped here so
    no caller has to remember to.
    """
    page, has_more = list(rows[:limit]), len(rows) > limit
    return Page(
        items=[read(row) for row in page],
        next_cursor=(
            Cursor(created_at=page[-1].created_at, row_id=page[-1].id).encode()
            if has_more and page
            else None
        ),
    )
