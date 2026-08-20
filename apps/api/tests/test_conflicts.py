"""Losing a uniqueness race answers 409, not 500 (#197).

Every "a X with that name already exists" check in this API is a SELECT then an
INSERT, which only ever guarded the sequential case. These cover the concurrent
one by doing what a lost race does: inserting a row the pre-check could not have
seen, then committing.
"""

import uuid

import pytest
from fastapi import HTTPException
from iceberg_api.conflicts import commit_or_conflict
from iceberg_core.enums import SourceType
from iceberg_core.models import Finding, Source
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select


def _source(name: str) -> Source:
    return Source(name=name, type=SourceType.CONFLUENCE, connection={"base_url": "https://x.test"})


def test_a_duplicate_name_is_a_conflict_rather_than_an_unhandled_error(
    session: Session,
) -> None:
    """What two concurrent creates do: both pre-checks pass, both insert, and the
    database — where the constraint actually lives — refuses the second."""
    session.add(_source("confluence-eng"))
    session.commit()
    session.add(_source("confluence-eng"))

    with pytest.raises(HTTPException) as raised:
        commit_or_conflict(session, "a source with that name already exists")

    assert raised.value.status_code == 409
    assert raised.value.detail == "a source with that name already exists"


def test_the_session_is_usable_again_afterwards(session: Session) -> None:
    """The rollback matters as much as the status. A session holding a failed
    transaction fails every later statement on it, including the ones a
    dependency runs on the way out of the request."""
    session.add(_source("confluence-eng"))
    session.commit()
    session.add(_source("confluence-eng"))
    with pytest.raises(HTTPException):
        commit_or_conflict(session, "a source with that name already exists")

    session.add(_source("confluence-ops"))
    session.commit()

    assert len(list(session.exec(select(Source)))) == 2


def test_an_integrity_failure_that_is_not_uniqueness_is_not_dressed_as_one(
    session: Session,
) -> None:
    """A foreign key or a NOT NULL is a bug, not a name somebody else took.
    Answering "that name already exists" would send an operator looking in
    entirely the wrong place, so anything but a unique violation is re-raised."""
    session.add(
        Finding(
            source_id=uuid.uuid4(),  # no such source
            fingerprint="f" * 64,
            rule_id="aws-access-key-id",
            severity="high",
            secret_hash="a" * 64,
            redacted_snippet="AKIA****",
            resource_locator={"path": "/x"},
            first_seen_scan_id=uuid.uuid4(),
            last_seen_scan_id=uuid.uuid4(),
        )
    )

    with pytest.raises(IntegrityError):
        commit_or_conflict(session, "a source with that name already exists")
