"""The confidence threshold, applied in both places (#70).

One value, configured on the API, delivered to engines in their lease and applied
again at ingest. The point of applying it twice is the case where the two
disagree: an engine running a stale image must not be able to fill the queue with
matches this deployment has decided are noise.
"""

import uuid

import pytest
from fastapi.testclient import TestClient
from iceberg_api.engines.ingest import ingest_findings
from iceberg_api.engines.schemas import FindingPayload
from iceberg_core.config import ApiSettings
from iceberg_core.enums import ScanStatus, ScanTrigger, Severity, SourceType
from iceberg_core.models import Finding, Scan, Source
from sqlmodel import Session, select


def _payload(fingerprint: str, confidence: float | None) -> FindingPayload:
    return FindingPayload(
        fingerprint=fingerprint,
        rule_id="generic-high-entropy",
        rulepack_version="2026.07.1",
        resource_locator={"path": "/space/DOCS/page-1"},
        redacted_snippet="[20 chars redacted]",
        secret_hash=uuid.uuid4().hex,
        confidence=confidence,
        severity=Severity.MEDIUM,
    )


@pytest.fixture(name="scan")
def scan_fixture(session: Session) -> Scan:
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


def test_findings_below_the_threshold_are_dropped_and_counted(session: Session, scan: Scan) -> None:
    outcome = ingest_findings(
        session,
        scan,
        [_payload("a" * 64, 0.9), _payload("b" * 64, 0.2)],
        threshold=0.5,
    )
    session.commit()

    assert (outcome.ingested, outcome.below_threshold) == (1, 1)
    assert [finding.fingerprint for finding in session.exec(select(Finding))] == ["a" * 64]


def test_a_finding_exactly_at_the_threshold_is_kept(session: Session, scan: Scan) -> None:
    """The threshold is a minimum, not a strict one: 0.5 means 0.5 is good enough."""
    outcome = ingest_findings(session, scan, [_payload("a" * 64, 0.5)], threshold=0.5)

    assert (outcome.ingested, outcome.below_threshold) == (1, 0)


def test_an_unscored_finding_is_kept(session: Session, scan: Scan) -> None:
    """`None` means the engine did not judge it, not that it judged it noise —
    dropping it would lose a finding over a missing field."""
    outcome = ingest_findings(session, scan, [_payload("a" * 64, None)], threshold=0.9)

    assert (outcome.ingested, outcome.below_threshold) == (1, 0)


def test_the_drop_is_recorded_on_the_scan_counts(session: Session, scan: Scan) -> None:
    """A scan reporting nothing should be able to say whether it found nothing or
    dropped everything."""
    from iceberg_api.engines.ingest import merge_scan_counts

    outcome = ingest_findings(
        session, scan, [_payload("a" * 64, 0.1), _payload("b" * 64, 0.2)], threshold=0.5
    )
    merge_scan_counts(scan, outcome, {})

    assert scan.counts["below_threshold"] == 2
    assert scan.counts["findings"] == 0


def test_a_lease_carries_the_configured_threshold(
    client: TestClient,
    session: Session,
    api_settings: ApiSettings,
    engine_credential: tuple[object, dict[str, str]],
    dispatcher: object,
) -> None:
    """Delivered per task rather than set in engine config: one value, one place."""
    from iceberg_api.scans import service
    from iceberg_core.models import ScanTask

    _engine, headers = engine_credential
    source = Source(
        name=f"confluence-{uuid.uuid4().hex[:6]}",
        type=SourceType.CONFLUENCE,
        connection={"base_url": "https://example.atlassian.net/wiki"},
    )
    session.add(source)
    session.commit()
    scan = service.launch_scan(
        session,
        source,
        trigger=ScanTrigger.MANUAL,
        dispatcher=dispatcher,  # type: ignore[arg-type]  # RecordingDispatcher
    )
    task = session.exec(select(ScanTask).where(ScanTask.scan_id == scan.id)).one()

    body = client.post(f"/api/v1/scan-tasks/{task.id}/lease", headers=headers).json()

    assert body["confidence_threshold"] == api_settings.confidence_threshold


def test_the_threshold_is_configurable() -> None:
    settings = ApiSettings(database_url="sqlite://", confidence_threshold=0.75)

    assert settings.confidence_threshold == 0.75


@pytest.mark.parametrize("value", [-0.1, 1.1])
def test_a_threshold_outside_the_unit_interval_is_refused(value: float) -> None:
    """Confidence is a score in [0, 1]; a threshold outside it silently keeps
    everything or nothing."""
    with pytest.raises(ValueError, match="confidence_threshold"):
        ApiSettings(database_url="sqlite://", confidence_threshold=value)
