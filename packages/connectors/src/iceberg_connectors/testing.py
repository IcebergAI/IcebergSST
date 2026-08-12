"""Dependency-free connector SDK conformance helpers.

Connector authors can call :func:`assert_connector_conformance` from their own
pytest/unittest suite. The helper deliberately accepts explicit fixtures instead
of importing a connector or discovering unsigned code.
"""

import json
from dataclasses import dataclass
from typing import Any

from iceberg_connectors.protocol import (
    CONNECTOR_SDK_VERSION,
    Connector,
    ConnectorCapability,
    ConnectorError,
    FetchOutcome,
)
from iceberg_connectors.units import ContentUnit


@dataclass(frozen=True, slots=True)
class ConformanceCase:
    connector: Connector
    connection: dict[str, Any]
    credential: str | None
    reference_key: bytes
    expected_minimum_specs: int = 1
    expected_minimum_units: int = 1
    expected_minimum_gaps: int = 0
    secret_sentinels: tuple[str, ...] = ()


def assert_connector_conformance(case: ConformanceCase) -> dict[str, object]:
    """Exercise the stable discovery/fetch/coverage and privacy boundary."""

    connector = case.connector
    metadata = connector.metadata
    if metadata.connector_type != connector.connector_type:
        raise AssertionError("connector type and metadata disagree")
    if metadata.sdk_version.split(".", 1)[0] != CONNECTOR_SDK_VERSION.split(".", 1)[0]:
        raise AssertionError("connector SDK major is incompatible")
    required = {ConnectorCapability.DISCOVERY, ConnectorCapability.GAP_REPORTING}
    if not required.issubset(metadata.capabilities):
        raise AssertionError("required connector capabilities are missing")

    specs = list(connector.discover(case.connection, case.credential))
    if len(specs) < case.expected_minimum_specs:
        raise AssertionError("connector discovered too few task specs")
    repeated_specs = list(connector.discover(case.connection, case.credential))
    spec_payloads = [spec.as_payload() for spec in specs]
    if spec_payloads != [spec.as_payload() for spec in repeated_specs]:
        raise AssertionError("connector discovery is not deterministic for an unchanged fixture")
    canonical_specs = [json.dumps(payload, sort_keys=True) for payload in spec_payloads]
    if len(canonical_specs) != len(set(canonical_specs)):
        raise AssertionError("connector discovered duplicate task identity")
    units: list[ContentUnit] = []
    coverage: list[dict[str, object]] = []
    for spec in specs:
        outcome = FetchOutcome(reference_key=case.reference_key)
        units.extend(connector.fetch(case.connection, spec, case.credential, outcome))
        payload = outcome.as_coverage()
        counts = payload["counts"]
        if not isinstance(counts, dict):
            raise AssertionError("coverage counts are not an object")
        observed = sum(int(counts[key]) for key in ("scanned", "skipped", "failed"))
        if int(counts["discovered"]) != observed:
            raise AssertionError("coverage dispositions do not reconcile")
        coverage.append(payload)
    if len(units) < case.expected_minimum_units:
        raise AssertionError("connector fetched too few content units")
    gap_count = 0
    for item in coverage:
        gaps = item.get("gaps", [])
        if not isinstance(gaps, list):
            raise AssertionError("coverage gaps are not an array")
        gap_count += len(gaps)
    if gap_count < case.expected_minimum_gaps:
        raise AssertionError("connector reported too few coverage gaps")

    public_payload: dict[str, object] = {
        "metadata": metadata.as_payload(),
        "specs": spec_payloads,
        "coverage": coverage,
    }
    serialized = json.dumps(public_payload, sort_keys=True)
    for sentinel in case.secret_sentinels:
        if sentinel and sentinel in serialized:
            raise AssertionError("credential/content sentinel crossed the public boundary")
    return public_payload


def assert_failure_contract(error: ConnectorError) -> None:
    """Ensure failure classification is stable and machine-readable."""
    if not error.code.value:
        raise AssertionError("connector failure code is empty")
    if not isinstance(error.retryable, bool):
        raise AssertionError("connector retryability is not boolean")
