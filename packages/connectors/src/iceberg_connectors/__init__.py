"""Connector interface and source connectors (Confluence MVP; Jira/SMB later).

A connector turns a source into :class:`ContentUnit`\\ s for detection. The
interface is two methods — :meth:`~iceberg_connectors.protocol.Connector.discover`
splits a source into parallelisable work, ``fetch`` runs one piece — and both run
inside an engine, with the credential arriving from the task lease (ADR 0002/0009).

Nothing here touches a database or reads the environment, which is what keeps it
importable from an engine process.
"""

from iceberg_connectors.fake import FAKE_CONNECTOR_TYPE, FakeConnector, FakePage
from iceberg_connectors.protocol import (
    Connector,
    ConnectorError,
    CredentialError,
    FetchOutcome,
    TaskSpec,
)
from iceberg_connectors.registry import UnknownConnectorError
from iceberg_connectors.units import GLOB_FRIENDLY_KEYS, ContentOrigin, ContentUnit

__version__ = "0.1.0"

__all__ = [
    "FAKE_CONNECTOR_TYPE",
    "GLOB_FRIENDLY_KEYS",
    "Connector",
    "ConnectorError",
    "ContentOrigin",
    "ContentUnit",
    "CredentialError",
    "FakeConnector",
    "FakePage",
    "FetchOutcome",
    "TaskSpec",
    "UnknownConnectorError",
    "__version__",
]
