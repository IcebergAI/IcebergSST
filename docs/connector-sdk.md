# Connector SDK v1

The `iceberg-connectors` package is the supported interface for adding a source to an IcebergSST
engine. SDK v1 is intentionally small: implement discovery and fetch, declare capabilities, and run
the shared conformance kit. Connectors execute only inside an engine and are explicitly registered;
the API never imports or auto-discovers connector code.

## Minimal connector

`FakeConnector` is the shipped, network-free reference implementation, and the Jira connector (#144) is the worked example of a real one built against this contract from the outside. A connector must expose
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
failures, malformed responses, size/output limits, partial reads, and checkpoint restoration.
`assert_checkpoint_resume` and `assert_incremental_contract` cover the last two: both are gated on
the declared capability, so a case may call them unconditionally. The Confluence suite demonstrates these network fixtures; the fake
connector demonstrates the complete base contract without a network.

## Compatibility policy

- `CONNECTOR_SDK_VERSION` versions the connector interface independently from the package version.
- Engines accept connectors with the same SDK major version. Registration fails closed on missing,
  mismatched, or incompatible metadata.
- A minor SDK release may add optional capabilities or helpers without changing existing behavior.
- A major SDK release may change method signatures, required capabilities, or serialized contracts.
  An engine image must not mix incompatible connector majors.
- Capabilities describe implemented behavior; they are not permissions. Declaring one is a promise
  the conformance kit then holds you to — `CHECKPOINTS` means `assert_checkpoint_resume` passes,
  `INCREMENTAL` means `assert_incremental_contract` does.

## Resumable and incremental connectors (SDK 1.1)

Both are optional, both ride on `FetchOutcome`, and neither changes a method signature.

**`CHECKPOINTS`.** Read `outcome.resume_from` before enumerating; call
`outcome.checkpoint_at(version, position)` at a boundary you can honestly restart from. A checkpoint
means something narrower than "how far I got": it is a point at which *every unit before it has
already been yielded*. Publish one only after a whole object and its parts — an issue and its
comments, a page and its attachments — or a resumed attempt will skip the rest of them. `version` is
yours, not the SDK's; bump it when the meaning of a position changes, and the engine will discard
positions it no longer understands rather than misread them.

**`INCREMENTAL`.** Accept `cursors: Mapping[str, Any] | None = None` on `discover` and narrow to what
changed. A scope absent from the mapping has no watermark and must be enumerated in full. Call
`outcome.cursor_at(scope, version, position)` to propose the next watermark; the API stores it only
if the whole scan completes with complete coverage, so you do not have to reason about whether the
rest of the scan succeeded.

Discovery must stay deterministic **with** a cursor as well as without one: the kit runs it twice and
compares. Derive bounds from the source's own data, never from the clock.

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
