"""Correlation ids at ingest, backfill, and reindex (ADR 0011, #140).

The claims that make clusters trustworthy: the same secret gets the same id
wherever it lands, a missing key degrades to NULL instead of failing the task,
NULLs are repairable from stored data, a pepper re-key moves the id with the
hash, and a key rotation converges to ``updated=0`` without any rescan.
"""

import secrets
import uuid
from collections.abc import Callable

import pytest
from iceberg_api.correlation.reindex import fill_missing, reindex_all
from iceberg_api.engines.ingest import ingest_findings
from iceberg_api.engines.schemas import FindingPayload
from iceberg_core.correlation import correlation_id
from iceberg_core.enums import ScanStatus, ScanTrigger, Severity, SourceType
from iceberg_core.fingerprint import CoarseLocator, fingerprint, secret_hash
from iceberg_core.models import Finding, Scan, Source
from sqlmodel import Session, col, select

PEPPER = b"the-active-pepper-32-bytes-long!"
OLD_PEPPER = b"the-outgoing-pepper-32-bytes-ok!"
KEY = secrets.token_bytes(32)

SECRET = "AKIAIOSFODNN7EXAMPLE"
OTHER_SECRET = "ghp_an_entirely_different_secret"
RULE = "aws-access-key-id"


def _payload(secret: str, resource_id: str, *, pepper: bytes = PEPPER) -> FindingPayload:
    hashed = secret_hash(secret, pepper=pepper)
    locator = CoarseLocator(connector_type="confluence", resource_id=resource_id)
    return FindingPayload(
        fingerprint=fingerprint(locator=locator, rule_id=RULE, secret_hash=hashed, pepper=pepper),
        rule_id=RULE,
        rulepack_version="2026.07.1",
        resource_locator={"page_id": resource_id},
        redacted_snippet="AKIA****************",
        secret_hash=hashed,
        severity=Severity.HIGH,
        confidence=0.9,
    )


@pytest.fixture(name="make_scan")
def make_scan_fixture(session: Session) -> Callable[[], Scan]:
    def factory() -> Scan:
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
        return scan

    return factory


def _findings(session: Session) -> list[Finding]:
    return list(session.exec(select(Finding).order_by(col(Finding.created_at))))


def _scan_of_same_source(session: Session, scan: Scan) -> Scan:
    """A follow-up scan of the same source — a re-sighting, not a new exposure."""
    # One active scan per source (ADR 0009): finish the earlier one first.
    scan.status = ScanStatus.COMPLETED
    session.add(scan)
    follow_up = Scan(
        source_id=scan.source_id, trigger=ScanTrigger.MANUAL, status=ScanStatus.RUNNING
    )
    session.add(follow_up)
    session.commit()
    return follow_up


def test_the_same_secret_in_two_sources_shares_one_correlation_id(
    session: Session, make_scan: Callable[[], Scan]
) -> None:
    ingest_findings(session, make_scan(), [_payload(SECRET, "page-1")], correlation_key=KEY)
    ingest_findings(session, make_scan(), [_payload(SECRET, "page-2")], correlation_key=KEY)

    first, second = _findings(session)
    assert first.fingerprint != second.fingerprint  # two locations, two findings
    assert first.correlation_id is not None
    assert first.correlation_id == second.correlation_id  # one exposure


def test_different_secrets_do_not_correlate(
    session: Session, make_scan: Callable[[], Scan]
) -> None:
    ingest_findings(
        session,
        make_scan(),
        [_payload(SECRET, "page-1"), _payload(OTHER_SECRET, "page-2")],
        correlation_key=KEY,
    )

    first, second = _findings(session)
    assert first.correlation_id != second.correlation_id


def test_the_stored_id_is_never_the_stored_hash(
    session: Session, make_scan: Callable[[], Scan]
) -> None:
    """The column must not re-expose ``secret_hash`` under another name."""
    ingest_findings(session, make_scan(), [_payload(SECRET, "page-1")], correlation_key=KEY)

    (finding,) = _findings(session)
    assert finding.correlation_id != finding.secret_hash


def test_without_a_key_ingest_stores_null_and_succeeds(
    session: Session, make_scan: Callable[[], Scan]
) -> None:
    outcome = ingest_findings(session, make_scan(), [_payload(SECRET, "page-1")])

    assert outcome.ingested == 1
    (finding,) = _findings(session)
    assert finding.correlation_id is None


def test_backfill_repairs_null_ids_from_the_stored_hash(
    session: Session, make_scan: Callable[[], Scan]
) -> None:
    ingest_findings(session, make_scan(), [_payload(SECRET, "page-1")])

    filled = fill_missing(session, KEY, batch=10)
    session.commit()

    assert filled == 1
    (finding,) = _findings(session)
    assert finding.correlation_id == correlation_id(finding.secret_hash, key=KEY)


def test_backfill_leaves_populated_rows_alone(
    session: Session, make_scan: Callable[[], Scan]
) -> None:
    ingest_findings(session, make_scan(), [_payload(SECRET, "page-1")], correlation_key=KEY)

    assert fill_missing(session, KEY, batch=10) == 0


def test_a_resighting_fills_a_null_id(session: Session, make_scan: Callable[[], Scan]) -> None:
    """A row from before the key existed gets its id the next time it is seen."""
    scan = make_scan()
    ingest_findings(session, scan, [_payload(SECRET, "page-1")])
    (finding,) = _findings(session)
    assert finding.correlation_id is None

    follow_up = _scan_of_same_source(session, scan)
    ingest_findings(session, follow_up, [_payload(SECRET, "page-1")], correlation_key=KEY)
    session.commit()  # ingest never commits; the route owns the transaction

    session.refresh(finding)
    assert finding.correlation_id == correlation_id(finding.secret_hash, key=KEY)


def test_a_pepper_rekey_moves_the_correlation_id_with_the_hash(
    session: Session, make_scan: Callable[[], Scan]
) -> None:
    """During a pepper rotation the hash changes, so the id must change with it —
    a row keyed under the old hash would sit outside its own cluster."""
    scan = make_scan()
    ingest_findings(
        session, scan, [_payload(SECRET, "page-1", pepper=OLD_PEPPER)], correlation_key=KEY
    )
    (finding,) = _findings(session)
    stale_id = finding.correlation_id

    rekeyed = _payload(SECRET, "page-1")
    old = _payload(SECRET, "page-1", pepper=OLD_PEPPER)
    rekeyed = FindingPayload(
        **rekeyed.model_dump(exclude={"previous_fingerprint", "previous_secret_hash"}),
        previous_fingerprint=old.fingerprint,
        previous_secret_hash=old.secret_hash,
    )
    follow_up = _scan_of_same_source(session, scan)
    outcome = ingest_findings(session, follow_up, [rekeyed], correlation_key=KEY)
    session.commit()  # ingest never commits; the route owns the transaction

    assert outcome.rekeyed == 1
    session.refresh(finding)
    assert finding.correlation_id == correlation_id(finding.secret_hash, key=KEY)
    assert finding.correlation_id != stale_id


def test_reindex_rotates_every_id_and_then_reports_zero(
    session: Session, make_scan: Callable[[], Scan]
) -> None:
    """The key-rotation path: swap the key, reindex, and the second run's
    ``updated=0`` is the operator's signal that the rotation is complete."""
    ingest_findings(session, make_scan(), [_payload(SECRET, "page-1")], correlation_key=KEY)
    ingest_findings(session, make_scan(), [_payload(OTHER_SECRET, "page-2")], correlation_key=KEY)
    new_key = secrets.token_bytes(32)

    first = reindex_all(session, new_key, batch=1)  # batch=1 exercises the pagination
    session.commit()

    assert (first.scanned, first.updated) == (2, 2)
    for finding in _findings(session):
        assert finding.correlation_id == correlation_id(finding.secret_hash, key=new_key)

    second = reindex_all(session, new_key, batch=1)
    assert (second.scanned, second.updated) == (2, 0)


def test_reindex_preserves_clusters_under_the_new_key(
    session: Session, make_scan: Callable[[], Scan]
) -> None:
    ingest_findings(session, make_scan(), [_payload(SECRET, "page-1")], correlation_key=KEY)
    ingest_findings(session, make_scan(), [_payload(SECRET, "page-2")], correlation_key=KEY)

    reindex_all(session, secrets.token_bytes(32), batch=100)
    session.commit()

    first, second = _findings(session)
    assert first.correlation_id == second.correlation_id
