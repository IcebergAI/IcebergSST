"""Ingest reads the findings it might update in one pass, not one each (#197).

The hottest path in the API. A 500-finding batch used to issue a point SELECT per
payload — two, during a pepper-rotation window — inside the transaction that holds
the scan row locked, so the cost was paid in lock time as well as round trips.

Counted rather than asserted about in prose: a query count is the only thing that
notices the next person putting a lookup back inside the loop.
"""

import uuid
from collections.abc import Iterator

import pytest
from iceberg_api.engines.ingest import ingest_findings
from iceberg_api.engines.schemas import FindingPayload
from iceberg_core.enums import ScanStatus, ScanTrigger, Severity, SourceType
from iceberg_core.models import Finding, Scan, Source
from sqlalchemy import event
from sqlmodel import Session, select


class _Counter:
    """Counts SELECTs against the finding table on one session's connection."""

    def __init__(self, session: Session) -> None:
        self._bind = session.get_bind()
        self.selects = 0

    def __enter__(self) -> _Counter:
        event.listen(self._bind, "before_cursor_execute", self._record)
        return self

    def __exit__(self, *_exc: object) -> None:
        event.remove(self._bind, "before_cursor_execute", self._record)

    def _record(
        self,
        _conn: object,
        _cursor: object,
        statement: str,
        *_rest: object,
    ) -> None:
        normalized = " ".join(statement.split()).lower()
        if normalized.startswith("select") and "from finding" in normalized:
            self.selects += 1


def _payload(marker: int, *, previous: str | None = None) -> FindingPayload:
    return FindingPayload(
        fingerprint=f"{marker:064d}",
        previous_fingerprint=previous,
        rule_id="generic-high-entropy",
        rulepack_version="2026.07.1",
        resource_locator={"path": f"/space/DOCS/page-{marker}"},
        redacted_snippet="[20 chars redacted]",
        secret_hash=uuid.uuid4().hex,
        confidence=0.9,
        severity=Severity.MEDIUM,
    )


@pytest.fixture(name="scan")
def scan_fixture(session: Session) -> Iterator[Scan]:
    source = Source(
        name=f"confluence-{uuid.uuid4().hex[:6]}",
        type=SourceType.CONFLUENCE,
        connection={"base_url": "https://example.atlassian.net/wiki"},
    )
    session.add(source)
    session.commit()
    scan = Scan(source_id=source.id, trigger=ScanTrigger.MANUAL, status=ScanStatus.RUNNING)
    session.add(scan)
    session.commit()
    yield scan


def test_the_finding_lookup_does_not_scale_with_the_batch(session: Session, scan: Scan) -> None:
    """Twenty payloads, one lookup — the property, not a magic number: the count
    must not move when the batch grows."""
    with _Counter(session) as small:
        ingest_findings(session, scan, [_payload(n) for n in range(2)])
    with _Counter(session) as large:
        ingest_findings(session, scan, [_payload(n) for n in range(100, 120)])

    assert small.selects == large.selects, "the lookup is per payload again"


def test_a_rotation_window_still_finds_the_outgoing_identity(session: Session, scan: Scan) -> None:
    """Both identities are loaded in the same pass, so a finding stored under the
    outgoing pepper is still re-keyed rather than duplicated (#64)."""
    ingest_findings(session, scan, [_payload(1)])
    session.commit()

    outcome = ingest_findings(session, scan, [_payload(2, previous=f"{1:064d}")])
    session.commit()

    assert outcome.rekeyed == 1
    stored = list(session.exec(select(Finding).where(Finding.source_id == scan.source_id)))
    assert [finding.fingerprint for finding in stored] == [f"{2:064d}"]


def test_the_same_fingerprint_twice_in_one_batch_is_one_finding(
    session: Session, scan: Scan
) -> None:
    """The per-payload select used to see the pending insert through autoflush.
    A preloaded map has to be kept in step, or the second payload inserts a
    duplicate the unique constraint refuses — turning a harmless repeat into a
    failed submission."""
    outcome = ingest_findings(session, scan, [_payload(7), _payload(7)])
    session.commit()

    assert outcome.ingested == 2
    stored = list(session.exec(select(Finding).where(Finding.source_id == scan.source_id)))
    assert len(stored) == 1
