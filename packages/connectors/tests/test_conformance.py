"""Public connector SDK identity and reusable conformance contract (#149)."""

import json
from dataclasses import replace

import pytest
from iceberg_connectors import (
    CONNECTOR_SDK_VERSION,
    ConfluenceConnector,
    ConformanceCase,
    ConnectorCapability,
    ConnectorError,
    ConnectorFailureCode,
    ConnectorMetadata,
    CredentialError,
    FakeConnector,
    FakePage,
    RateLimitError,
    assert_connector_conformance,
    assert_failure_contract,
    registry,
)


@pytest.fixture(autouse=True)
def clean_registry() -> None:
    registry.clear()


def test_shipped_example_passes_the_public_conformance_kit() -> None:
    credential = "test-credential-sentinel"
    source_content = "source-content-sentinel"
    connector = FakeConnector(
        spaces={
            "EXAMPLE": [
                FakePage("record-1", source_content),
                FakePage("record-2", "", skip=True),
                FakePage("record-3", "", unreadable=True),
            ]
        },
        expected_credential=credential,
    )

    payload = assert_connector_conformance(
        ConformanceCase(
            connector=connector,
            connection={"spaces": ["EXAMPLE"]},
            credential=credential,
            reference_key=b"connector-conformance-reference-key",
            expected_minimum_gaps=2,
            secret_sentinels=(credential, source_content),
        )
    )

    assert payload["metadata"] == {
        "connector_type": "fake",
        "sdk_version": CONNECTOR_SDK_VERSION,
        "capabilities": ["anonymous_auth", "discovery", "gap_reporting"],
    }


def test_conformance_rejects_a_connector_missing_required_capabilities() -> None:
    connector = FakeConnector(
        spaces={"EXAMPLE": [FakePage("record-1", "text")]},
        metadata=ConnectorMetadata("fake", capabilities=frozenset()),
    )

    with pytest.raises(AssertionError, match="required connector capabilities"):
        assert_connector_conformance(
            ConformanceCase(
                connector=connector,
                connection={},
                credential=None,
                reference_key=b"connector-conformance-reference-key",
            )
        )


def test_registry_rejects_missing_mismatched_and_incompatible_metadata() -> None:
    class LegacyConnector:
        connector_type = "legacy"

    with pytest.raises(ConnectorError, match="does not declare ConnectorMetadata"):
        registry.register(LegacyConnector())  # type: ignore[arg-type]

    mismatched = FakeConnector(metadata=ConnectorMetadata("not-fake"))
    with pytest.raises(ConnectorError, match="metadata type"):
        registry.register(mismatched)

    incompatible = FakeConnector(metadata=replace(FakeConnector().metadata, sdk_version="2.0"))
    with pytest.raises(ConnectorError, match="incompatible"):
        registry.register(incompatible)


def test_registry_exposes_a_sorted_content_free_capability_manifest() -> None:
    registry.register(FakeConnector())
    registry.register(ConfluenceConnector())

    payload = registry.capability_manifest()

    assert [entry["connector_type"] for entry in payload] == ["confluence", "fake"]
    capabilities = payload[0]["capabilities"]
    assert isinstance(capabilities, list)
    assert ConnectorCapability.ATTACHMENTS.value in capabilities
    serialized = json.dumps(payload)
    assert "credential" not in serialized
    assert "connection" not in serialized


@pytest.mark.parametrize(
    ("error", "code", "retryable"),
    [
        (ConnectorError("safe"), ConnectorFailureCode.CONNECTOR_ERROR, False),
        (CredentialError("safe"), ConnectorFailureCode.CREDENTIAL_REJECTED, False),
        (RateLimitError("safe"), ConnectorFailureCode.RATE_LIMITED, True),
    ],
)
def test_failure_contract_is_stable_and_machine_readable(
    error: ConnectorError,
    code: ConnectorFailureCode,
    retryable: bool,
) -> None:
    assert_failure_contract(error)
    assert error.code is code
    assert error.retryable is retryable


def test_both_shipped_connectors_declare_the_current_sdk_contract() -> None:
    connectors = (FakeConnector(), ConfluenceConnector())

    assert {connector.connector_type for connector in connectors} == {"fake", "confluence"}
    assert all(connector.metadata.sdk_version == CONNECTOR_SDK_VERSION for connector in connectors)
    assert ConnectorCapability.PAGINATION in connectors[1].metadata.capabilities
    assert ConnectorCapability.COMMENTS in connectors[1].metadata.capabilities
    assert ConnectorCapability.ATTACHMENTS in connectors[1].metadata.capabilities
