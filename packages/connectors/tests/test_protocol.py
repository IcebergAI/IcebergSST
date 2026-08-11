"""The connector protocol, task specs, and the registry (#45)."""

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
    TaskSpec,
    UnknownConnectorError,
    registry,
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
