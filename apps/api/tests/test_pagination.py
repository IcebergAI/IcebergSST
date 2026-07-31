"""The shared keyset-pagination helpers.

Every list endpoint resolves a cursor the same way and ends the same way — fetch
one row more than asked, drop it, encode the last row it kept. That was five
verbatim copies, and a copy is where a subtle difference between two endpoints
hides. These tests pin the single implementation they now share.
"""

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import pytest
from fastapi import HTTPException
from iceberg_api.pagination import Cursor, build_page, position

NOW = datetime(2026, 7, 31, 12, 0, tzinfo=UTC)


@dataclass
class Row:
    """The two columns the cursor addresses, and nothing else."""

    created_at: datetime
    id: uuid.UUID


def _rows(count: int) -> list[Row]:
    return [
        Row(created_at=NOW + timedelta(seconds=index), id=uuid.uuid4()) for index in range(count)
    ]


def test_the_probe_row_is_dropped_and_becomes_the_next_cursor() -> None:
    rows = _rows(3)

    page = build_page(rows, limit=2, read=lambda row: row.id)

    assert page.items == [rows[0].id, rows[1].id]
    assert page.next_cursor is not None
    # The cursor names the last row *kept*, so the next page resumes after it.
    assert Cursor.decode(page.next_cursor) == Cursor(
        created_at=rows[1].created_at, row_id=rows[1].id
    )


def test_a_page_that_did_not_fill_has_no_continuation() -> None:
    """Exactly `limit` rows means there was no probe row, so this is the last page."""
    rows = _rows(2)

    assert build_page(rows, limit=2, read=lambda row: row.id).next_cursor is None
    assert build_page([], limit=2, read=lambda row: row.id).next_cursor is None


def test_no_cursor_means_the_first_page() -> None:
    assert position(None) is None


def test_a_cursor_we_issued_round_trips() -> None:
    original = Cursor(created_at=NOW, row_id=uuid.uuid4())

    assert position(original.encode()) == original


def test_a_cursor_we_did_not_issue_is_a_400() -> None:
    """Never quietly answered with the first page: a client paging through a
    queue would silently re-read rows it had already triaged."""
    with pytest.raises(HTTPException) as refused:
        position("not-a-cursor")

    assert refused.value.status_code == 400
