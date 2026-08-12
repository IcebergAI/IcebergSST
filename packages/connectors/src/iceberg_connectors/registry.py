"""Finding the connector for a source type (#45).

A lease names a ``source_type`` and nothing else; the worker has to turn that
string into something with ``discover``/``fetch``. This is that lookup.

Registration is explicit rather than by import-time scanning of the package.
Auto-discovery would mean the set of connectors an engine supports depends on
which modules happened to be imported, which is a difficult thing to reason about
when the answer decides whether a scan runs or fails.
"""

import structlog

from iceberg_connectors.protocol import (
    CONNECTOR_SDK_VERSION,
    Connector,
    ConnectorError,
    ConnectorMetadata,
)

logger = structlog.get_logger()

_REGISTRY: dict[str, Connector] = {}


class UnknownConnectorError(ConnectorError):
    """No connector is registered for this source type.

    Means an engine leased a task for a source type its image does not support —
    a mixed-fleet deployment, or a source created for a connector that has not
    shipped yet. The task fails with this rather than silently reporting an empty
    source, which would look like "no secrets here".
    """


def register(connector: Connector, *, replace: bool = False) -> None:
    """Make a connector available by its ``connector_type``."""
    metadata = getattr(connector, "metadata", None)
    if not isinstance(metadata, ConnectorMetadata):
        raise ConnectorError("connector does not declare ConnectorMetadata")
    if metadata.connector_type != connector.connector_type:
        raise ConnectorError("connector metadata type does not match connector_type")
    if metadata.sdk_version.split(".", 1)[0] != CONNECTOR_SDK_VERSION.split(".", 1)[0]:
        raise ConnectorError(
            f"connector SDK {metadata.sdk_version!r} is incompatible with "
            f"engine SDK {CONNECTOR_SDK_VERSION!r}"
        )
    existing = _REGISTRY.get(connector.connector_type)
    if existing is not None and not replace:
        raise ConnectorError(
            f"a connector is already registered for {connector.connector_type!r}; "
            f"pass replace=True to override"
        )
    _REGISTRY[connector.connector_type] = connector
    logger.debug("connector_registered", connector_type=connector.connector_type)


def get(source_type: str) -> Connector:
    """The connector for a source type, or raise :class:`UnknownConnectorError`."""
    try:
        return _REGISTRY[source_type]
    except KeyError as exc:
        known = ", ".join(sorted(_REGISTRY)) or "none"
        raise UnknownConnectorError(
            f"no connector for source type {source_type!r}; this engine has: {known}"
        ) from exc


def registered_types() -> tuple[str, ...]:
    """Source types this engine can scan. Reported at registration (#70-adjacent)."""
    return tuple(sorted(_REGISTRY))


def capability_manifest() -> list[dict[str, object]]:
    """JSON-safe, content-free inventory of explicitly registered connectors."""
    return [_REGISTRY[key].metadata.as_payload() for key in sorted(_REGISTRY)]


def clear() -> None:
    """Empty the registry. For tests that register doubles."""
    _REGISTRY.clear()
