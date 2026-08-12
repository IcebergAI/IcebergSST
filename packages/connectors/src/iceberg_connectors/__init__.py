"""Connector interface and source connectors (Confluence MVP; Jira/SMB later).

A connector turns a source into :class:`ContentUnit`\\ s for detection. The
interface is two methods — :meth:`~iceberg_connectors.protocol.Connector.discover`
splits a source into parallelisable work, ``fetch`` runs one piece — and both run
inside an engine, with the credential arriving from the task lease (ADR 0002/0009).

Attachments go through :func:`extract_text` first, which turns supported formats
into text inside a child process — attacker-editable input meeting a parser is the
engine's largest attack surface (docs/security.md, boundary 4).

Nothing here touches a database or reads the environment, which is what keeps it
importable from an engine process.
"""

from iceberg_core.enums import CoverageReason

from iceberg_connectors.confluence import (
    CONFLUENCE_CONNECTOR_TYPE,
    ConfluenceConnector,
)
from iceberg_connectors.extraction import (
    Extracted,
    ExtractionLimits,
    ExtractionOutcome,
    classify,
    extract_text,
)
from iceberg_connectors.fake import FAKE_CONNECTOR_TYPE, FakeConnector, FakePage
from iceberg_connectors.protocol import (
    CONNECTOR_SDK_VERSION,
    Connector,
    ConnectorCapability,
    ConnectorError,
    ConnectorFailureCode,
    ConnectorMetadata,
    CredentialError,
    FetchOutcome,
    RateLimitError,
    TaskCoverage,
    TaskSpec,
)
from iceberg_connectors.registry import UnknownConnectorError
from iceberg_connectors.sandbox import ExtractionSandbox
from iceberg_connectors.testing import (
    ConformanceCase,
    assert_connector_conformance,
    assert_failure_contract,
)
from iceberg_connectors.units import GLOB_FRIENDLY_KEYS, ContentOrigin, ContentUnit

__version__ = "0.1.0"

__all__ = [
    "CONFLUENCE_CONNECTOR_TYPE",
    "CONNECTOR_SDK_VERSION",
    "FAKE_CONNECTOR_TYPE",
    "GLOB_FRIENDLY_KEYS",
    "ConfluenceConnector",
    "ConformanceCase",
    "Connector",
    "ConnectorCapability",
    "ConnectorError",
    "ConnectorFailureCode",
    "ConnectorMetadata",
    "ContentOrigin",
    "ContentUnit",
    "CoverageReason",
    "CredentialError",
    "Extracted",
    "ExtractionLimits",
    "ExtractionOutcome",
    "ExtractionSandbox",
    "FakeConnector",
    "FakePage",
    "FetchOutcome",
    "RateLimitError",
    "TaskCoverage",
    "TaskSpec",
    "UnknownConnectorError",
    "__version__",
    "assert_connector_conformance",
    "assert_failure_contract",
    "classify",
    "extract_text",
]
