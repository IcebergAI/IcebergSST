"""The connector protocol, task specs, and the registry (#45)."""

import json
from collections.abc import Iterator

import pytest
from iceberg_connectors import (
    Connector,
    ConnectorError,
    ContentOrigin,
    CredentialError,
    FakeConnector,
    FakePage,
    FetchOutcome,
    TaskCoverage,
    TaskSpec,
    UnknownConnectorError,
    registry,
)
from iceberg_core.enums import (
    CoverageObjectKind,
    CoverageReason,
    ScanTaskKind,
)


@pytest.fixture(name="source")
def source_fixture() -> FakeConnector:
    return FakeConnector(
        spaces={
            "DOCS": [
                FakePage("page-1", "nothing interesting here"),
                FakePage("page-2", "a comment", origin=ContentOrigin.COMMENT),
                FakePage("page-3", "", skip=True),
                FakePage("page-4", "", unreadable=True),
            ],
            "SANDBOX": [FakePage("page-9", "throwaway")],
        }
    )


@pytest.fixture(name="clean_registry", autouse=True)
def clean_registry_fixture() -> Iterator[None]:
    registry.clear()
    yield
    registry.clear()


def test_the_fake_connector_satisfies_the_protocol(source: FakeConnector) -> None:
    """Structural typing means a connector needs no import from us to be one."""
    assert isinstance(source, Connector)


def test_discovery_yields_one_spec_per_space(source: FakeConnector) -> None:
    specs = list(source.discover({}, None))

    assert [spec.params["space"] for spec in specs] == ["DOCS", "SANDBOX"]


def test_discovery_honours_the_sources_scope_filter(source: FakeConnector) -> None:
    """ "Scan only these spaces" is configuration on the source, applied here."""
    specs = list(source.discover({"spaces": ["SANDBOX"]}, None))

    assert [spec.params["space"] for spec in specs] == ["SANDBOX"]


def test_an_empty_source_discovers_nothing_without_erroring() -> None:
    """A legitimate answer — and reconciliation refuses to auto-resolve on it
    (ADR 0009 §4), which is why it must not be an error here."""
    assert list(FakeConnector().discover({}, None)) == []


def test_fetch_yields_units_and_tallies_skips_and_failures(source: FakeConnector) -> None:
    """One bad page is counted without hiding readable neighboring units."""
    outcome = FetchOutcome()

    units = list(source.fetch({}, TaskSpec("space DOCS", {"space": "DOCS"}), None, outcome))

    assert [unit.locator.resource_id for unit in units] == ["page-1", "page-2"]
    assert outcome.as_counts() == {"units": 2, "units_skipped": 1, "units_failed": 1}


def test_coverage_reconciles_every_observed_object_to_one_disposition() -> None:
    coverage = TaskCoverage(
        phase=ScanTaskKind.FETCH,
        reference_key=b"coverage-reference-key",
    )

    coverage.scanned_for(CoverageObjectKind.PAGE, "page-readable")
    coverage.skipped_for(
        CoverageReason.EMPTY_CONTENT,
        CoverageObjectKind.COMMENT,
        "comment-empty",
    )
    coverage.failed_for(
        CoverageReason.SIZE_LIMIT,
        CoverageObjectKind.ATTACHMENT,
        "attachment-too-large",
    )

    payload = coverage.as_payload()
    counts = payload["counts"]
    assert counts == {
        "requested": 3,
        "discovered": 3,
        "scanned": 1,
        "skipped": 1,
        "failed": 1,
    }
    assert counts["requested"] == counts["scanned"] + counts["skipped"] + counts["failed"]
    assert payload["reasons"] == [
        {"outcome": "failed", "reason": "size_limit", "count": 1},
        {"outcome": "skipped", "reason": "empty_content", "count": 1},
    ]


def test_an_incomplete_scan_replaces_the_objects_scanned_disposition() -> None:
    coverage = TaskCoverage(phase=ScanTaskKind.FETCH)
    coverage.scanned_for(CoverageObjectKind.ATTACHMENT, "attachment-1")

    coverage.scanned_but_incomplete(
        CoverageReason.OUTPUT_LIMIT,
        CoverageObjectKind.ATTACHMENT,
        "attachment-1",
    )

    payload = coverage.as_payload()
    assert payload["counts"] == {
        "requested": 1,
        "discovered": 1,
        "scanned": 0,
        "skipped": 0,
        "failed": 1,
    }
    assert payload["reasons"] == [{"outcome": "failed", "reason": "output_limit", "count": 1}]


def test_an_unrecorded_object_cannot_be_reconciled_as_incomplete() -> None:
    coverage = TaskCoverage(phase=ScanTaskKind.FETCH)

    with pytest.raises(ValueError, match="unrecorded object"):
        coverage.scanned_but_incomplete(
            CoverageReason.OUTPUT_LIMIT,
            CoverageObjectKind.ATTACHMENT,
            "attachment-1",
        )


def test_reason_codes_cannot_change_meaning_between_dispositions() -> None:
    coverage = TaskCoverage(phase=ScanTaskKind.FETCH)

    with pytest.raises(ValueError, match="not a valid skipped coverage reason"):
        coverage.skipped_for(
            CoverageReason.PERMISSION_DENIED,
            CoverageObjectKind.PAGE,
            "page-1",
        )

    assert coverage.as_payload()["counts"] == {
        "requested": 0,
        "discovered": 0,
        "scanned": 0,
        "skipped": 0,
        "failed": 0,
    }


def test_gap_references_are_stable_hmacs_and_never_expose_raw_source_identity() -> None:
    raw_reference = {
        "page_id": "private-page-4815",
        "filename": "customer-payroll.txt",
    }

    def reference_for(key: bytes, kind: CoverageObjectKind) -> str:
        coverage = TaskCoverage(phase=ScanTaskKind.FETCH, reference_key=key)
        coverage.failed_for(CoverageReason.PERMISSION_DENIED, kind, raw_reference)
        payload = coverage.as_payload()
        assert "private-page-4815" not in json.dumps(payload)
        assert "customer-payroll.txt" not in json.dumps(payload)
        reference = payload["gaps"][0]["reference"]
        assert isinstance(reference, str)
        return reference

    first = reference_for(b"key-one", CoverageObjectKind.ATTACHMENT)
    repeated = reference_for(b"key-one", CoverageObjectKind.ATTACHMENT)
    other_key = reference_for(b"key-two", CoverageObjectKind.ATTACHMENT)
    other_kind = reference_for(b"key-one", CoverageObjectKind.PAGE)

    assert len(first) == 64
    assert int(first, 16) >= 0
    assert first == repeated
    assert first != other_key
    assert first != other_kind


def test_the_outcome_is_populated_even_if_the_caller_stops_early(source: FakeConnector) -> None:
    """Fetch is a generator, so tallies cannot be a return value: a cancelled task
    still needs to report what it managed."""
    outcome = FetchOutcome()
    stream = source.fetch({}, TaskSpec("space DOCS", {"space": "DOCS"}), None, outcome)

    next(stream)

    assert outcome.units == 1


def test_a_rejected_credential_raises_a_distinct_error() -> None:
    """Different operator response — rotate the credential — so a different type.
    Retrying will not help, and an empty result would look like "no secrets"."""
    source = FakeConnector(spaces={"DOCS": []}, expected_credential="the-real-token")

    with pytest.raises(CredentialError):
        list(source.discover({}, "the-wrong-token"))


def test_an_unreachable_source_raises_rather_than_reporting_nothing() -> None:
    source = FakeConnector(discovery_fails=True)

    with pytest.raises(ConnectionError):
        list(source.discover({}, None))


def test_a_task_spec_round_trips_through_a_lease() -> None:
    """It crosses the wire twice: engine → API after discovery, API → engine in
    the lease."""
    spec = TaskSpec(label="space DOCS", params={"space": "DOCS", "cursor": "abc"})

    assert TaskSpec.from_payload(spec.as_payload()) == spec


def test_a_spec_written_without_a_label_still_loads() -> None:
    """A label is cosmetic; failing a task over a display string would not be."""
    spec = TaskSpec.from_payload({"space": "DOCS"})

    assert spec.params == {"space": "DOCS"}
    assert spec.label


def test_a_connector_is_found_by_source_type(source: FakeConnector) -> None:
    registry.register(source)

    assert registry.get("fake") is source
    assert registry.registered_types() == ("fake",)


def test_registering_a_second_connector_for_one_type_is_refused(source: FakeConnector) -> None:
    """Silently replacing one would make which connector runs depend on import
    order."""
    registry.register(source)

    with pytest.raises(ConnectorError, match="already registered"):
        registry.register(FakeConnector())

    registry.register(FakeConnector(), replace=True)  # ...unless asked explicitly


def test_an_unsupported_source_type_says_what_this_engine_has(source: FakeConnector) -> None:
    """An engine leasing a task it cannot run must fail loudly: reporting an empty
    source would read as "no secrets here"."""
    registry.register(source)

    with pytest.raises(UnknownConnectorError, match="this engine has: fake"):
        registry.get("confluence")
