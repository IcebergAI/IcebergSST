"""Dependency-free connector SDK conformance helpers.

Connector authors can call :func:`assert_connector_conformance` from their own
pytest/unittest suite. The helper deliberately accepts explicit fixtures instead
of importing a connector or discovering unsigned code.
"""

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, cast

from iceberg_connectors.protocol import (
    CONNECTOR_SDK_VERSION,
    Checkpoint,
    Connector,
    ConnectorCapability,
    ConnectorError,
    FetchOutcome,
    IncrementalConnector,
    TaskSpec,
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


def assert_checkpoint_resume(case: ConformanceCase) -> None:
    """Prove a resumable fetch loses nothing and repeats nothing (#143).

    Only meaningful for a connector declaring
    :attr:`~iceberg_connectors.protocol.ConnectorCapability.CHECKPOINTS`; it
    returns early otherwise, so a case can run it unconditionally.

    The method: fetch a spec to completion, recording alongside each unit the
    checkpoint that was published *at the moment that unit arrived*. Because fetch
    is a generator, that checkpoint covers everything strictly before the unit in
    hand — which is exactly the pairing an engine flushing mid-fetch relies on, so
    it is the pairing tested here. Resuming from it must then yield the rest of the
    run verbatim: same locators, same order, none dropped, none repeated.

    "Resume runs without raising" does not imply any of that, which is the point.
    """
    connector = case.connector
    if ConnectorCapability.CHECKPOINTS not in connector.metadata.capabilities:
        return

    for spec in connector.discover(case.connection, case.credential):
        full = FetchOutcome(reference_key=case.reference_key)
        trail: list[tuple[str, Checkpoint | None]] = []
        for unit in connector.fetch(case.connection, spec, case.credential, full):
            trail.append((_identity(unit), full.checkpoint))
        if len(trail) < 3:
            # Too short to resume from partway through and still prove anything.
            continue

        midpoint = len(trail) // 2
        resume_from = trail[midpoint][1]
        if resume_from is None:
            raise AssertionError(
                "connector declares checkpoints but published none partway through a fetch"
            )
        expected = [identity for identity, _ in trail[midpoint:]]

        resumed = FetchOutcome(reference_key=case.reference_key, resume_from=resume_from)
        observed = [
            _identity(unit)
            for unit in connector.fetch(case.connection, spec, case.credential, resumed)
        ]
        if observed != expected:
            missing = [item for item in expected if item not in observed]
            repeated = [item for item in observed if item not in expected]
            raise AssertionError(
                "resuming from a published checkpoint did not continue where it left off "
                f"({len(missing)} unit(s) skipped, {len(repeated)} re-yielded)"
            )

        # Coverage has to restart too. A resumed attempt that re-counted the units
        # an earlier attempt already reported would double them once the API merged
        # the two batches, and the manifest would claim more content than exists.
        counts = resumed.as_coverage()["counts"]
        if not isinstance(counts, dict):  # pragma: no cover - defensive
            raise AssertionError("coverage counts are not an object")
        if int(counts["scanned"]) != len(expected):
            raise AssertionError("a resumed fetch re-counted objects an earlier attempt reported")


def assert_incremental_contract(case: ConformanceCase, cursors: Mapping[str, Any]) -> None:
    """Prove cursor-narrowed discovery is deterministic, bounded, and content-free.

    Only meaningful for a connector declaring
    :attr:`~iceberg_connectors.protocol.ConnectorCapability.INCREMENTAL`; returns
    early otherwise.

    ``cursors`` is a scope → position mapping of the shape the API would hand back
    from a previous complete scan. What is asserted is that narrowing is a *subset*
    of the full enumeration rather than a different enumeration — an incremental
    scan that invented specs a full scan would not produce could not be reconciled
    against one.
    """
    connector = case.connector
    if ConnectorCapability.INCREMENTAL not in connector.metadata.capabilities:
        return
    # The declared capability is what licenses the keyword argument. `isinstance`
    # against a runtime-checkable Protocol would not: it checks that `discover`
    # exists, not that it accepts `cursors`, so an SDK 1.0 connector would pass the
    # check and fail on the call.
    incremental = cast(IncrementalConnector, connector)

    full = {_spec_scope(spec) for spec in connector.discover(case.connection, case.credential)}
    narrowed = list(incremental.discover(case.connection, case.credential, cursors=cursors))
    repeated = list(incremental.discover(case.connection, case.credential, cursors=cursors))
    if [spec.as_payload() for spec in narrowed] != [spec.as_payload() for spec in repeated]:
        raise AssertionError("incremental discovery is not deterministic for an unchanged fixture")

    stray = {_spec_scope(spec) for spec in narrowed} - full
    if stray:
        raise AssertionError("incremental discovery yielded scopes a full scan would not")

    serialized = json.dumps([spec.as_payload() for spec in narrowed], sort_keys=True, default=str)
    for sentinel in case.secret_sentinels:
        if sentinel and sentinel in serialized:
            raise AssertionError("credential/content sentinel crossed the incremental boundary")


def _identity(unit: ContentUnit) -> str:
    """A unit's stable identity, which is exactly its coarse locator (ADR 0006)."""
    return json.dumps(
        [
            unit.locator.connector_type,
            unit.locator.resource_id,
            unit.locator.sub_resource,
        ],
        sort_keys=True,
    )


def _spec_scope(spec: TaskSpec) -> str:
    """The scope a spec covers, without knowing the connector's parameter name.

    Discovery may emit several specs per scope (Jira windows a project), so the
    subset check compares scopes rather than specs — otherwise a connector that
    narrowed a project to one window would look like it invented work.
    """
    for key in ("space_key", "project_key", "space", "path", "scope"):
        value = spec.params.get(key)
        if isinstance(value, str) and value:
            return f"{key}={value}"
    return json.dumps(spec.params, sort_keys=True, default=str)


def assert_failure_contract(error: ConnectorError) -> None:
    """Ensure failure classification is stable and machine-readable."""
    if not error.code.value:
        raise AssertionError("connector failure code is empty")
    if not isinstance(error.retryable, bool):
        raise AssertionError("connector retryability is not boolean")
