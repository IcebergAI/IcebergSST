# Connector SDK v1

The `iceberg-connectors` package is the supported interface for adding a source to an IcebergSST
engine. SDK v1 is intentionally small: implement discovery and fetch, declare capabilities, and run
the shared conformance kit. Connectors execute only inside an engine and are explicitly registered;
the API never imports or auto-discovers connector code.

## Minimal connector

`FakeConnector` is the shipped, network-free reference implementation. A connector must expose
immutable `ConnectorMetadata`, stream `TaskSpec` values from `discover()`, stream `ContentUnit`
values from `fetch()`, and classify every observed object through `FetchOutcome`.

```python
from collections.abc import Iterator

from iceberg_connectors import (
    ConnectorCapability,
    ConnectorMetadata,
    ContentUnit,
    FetchOutcome,
    TaskSpec,
)


class ExampleConnector:
    connector_type = "example"
    metadata = ConnectorMetadata(
        connector_type=connector_type,
        capabilities=frozenset(
            {ConnectorCapability.DISCOVERY, ConnectorCapability.GAP_REPORTING}
        ),
    )

    def discover(self, connection, credential) -> Iterator[TaskSpec]:
        ...

    def fetch(self, connection, spec, credential, outcome: FetchOutcome) -> Iterator[ContentUnit]:
        ...
```

Run the same contract IcebergSST uses for its shipped connectors:

```python
from iceberg_connectors import ConformanceCase, assert_connector_conformance


def test_example_connector_contract(example_connector):
    assert_connector_conformance(
        ConformanceCase(
            connector=example_connector,
            connection={"scope": "fixture"},
            credential="fixture-only-token",
            reference_key=b"fixture-reference-key",
            secret_sentinels=("fixture-only-token", "private fixture body"),
        )
    )
```

Use only synthetic fixtures. The helper checks SDK compatibility, required capabilities,
deterministic and unique task identity, discovery/fetch streaming, coverage reconciliation and gap
evidence, JSON serialization, and that supplied secret/content sentinels do not cross the
connector's public metadata, task-spec, or coverage boundary. Connector-specific shared fixtures
remain required for redirects, multi-page cursors, bounded retry exhaustion, authorization
failures, malformed responses, size/output limits, partial reads, and (when the capability ships)
checkpoint restoration. The Confluence suite demonstrates these network fixtures; the fake
connector demonstrates the complete base contract without a network.

## Compatibility policy

- `CONNECTOR_SDK_VERSION` versions the connector interface independently from the package version.
- Engines accept connectors with the same SDK major version. Registration fails closed on missing,
  mismatched, or incompatible metadata.
- A minor SDK release may add optional capabilities or helpers without changing existing behavior.
- A major SDK release may change method signatures, required capabilities, or serialized contracts.
  An engine image must not mix incompatible connector majors.
- Capabilities describe implemented behavior; they are not permissions. `CHECKPOINTS` is reserved
  for the resumable-scan work and must not be declared until the connector implements that contract.

The registry's `capability_manifest()` is a content-free inventory suitable for engine diagnostics.
It contains connector type, SDK version, and capability names only.

## Security boundary

- Credentials are lease-scoped inputs. Never retain them on the connector, include them in task
  specs or metadata, log them, or copy them into exception text.
- Source bodies may exist only ephemerally in engine memory. Only normalized units enter detection;
  plaintext must not cross the engine results boundary.
- Task specs may contain stable source identifiers needed to fetch work, but never credentials,
  source bodies, signed URLs, or authorization headers.
- Convert provider errors into stable `ConnectorFailureCode` classifications. Public error text must
  be content-free; retryability is machine-readable.
- Every enumerated object receives exactly one scanned, skipped, or failed disposition. Unknown
  remainder becomes a scope gap rather than an invented clean count.
- Register connectors explicitly. Do not import unsigned plugins, scan entry points, or execute
  source-supplied code.

See [connectors.md](./connectors.md) for the full runtime contract and Confluence behavior.
