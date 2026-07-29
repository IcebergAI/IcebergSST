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
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import ColumnElement, and_, or_
from sqlmodel.sql.expression import SelectOfScalar

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
    def decode(cls, raw: str) -> "Cursor":
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
        except (KeyError, ValueError, binascii.Error, json.JSONDecodeError) as exc:
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
