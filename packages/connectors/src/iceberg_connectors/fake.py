"""A connector backed by a dict, for driving the pipeline without a network (#45).

Shipped rather than kept in a test directory, for two reasons. The engine worker's
tests (#11) need a connector that behaves like a real one without a Confluence
instance, and they live in a different package. And a fake that lives beside the
protocol gets updated when the protocol changes, instead of quietly rotting until
someone runs the suite that uses it.

It is deliberately not a mock. It really iterates, really yields units, really
tallies skips, and can be told to fail in the specific ways a real source does —
because a double that cannot fail only ever proves the happy path works.
"""

from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

from iceberg_core.enums import CoverageObjectKind, CoverageReason
from iceberg_core.fingerprint import CoarseLocator

from iceberg_connectors.protocol import CredentialError, FetchOutcome, TaskSpec
from iceberg_connectors.units import ContentOrigin, ContentUnit

FAKE_CONNECTOR_TYPE = "fake"


@dataclass(slots=True)
class FakePage:
    """One resource the fake source holds."""

    resource_id: str
    text: str
    origin: ContentOrigin = ContentOrigin.BODY
    #: Named part of the resource — an attachment filename, a comment id.
    sub_resource: str | None = None
    display: dict[str, Any] = field(default_factory=dict)
    #: Raise on fetch, as a page that 500s or a file that cannot be decoded would.
    unreadable: bool = False
    #: Counted as skipped rather than scanned — an image, an unsupported format.
    skip: bool = False


@dataclass(slots=True)
class FakeConnector:
    """A connector over in-memory pages, grouped into discoverable spaces."""

    #: space key -> its pages. Discovery yields one spec per space, which is the
    #: shape the Confluence connector will have.
    spaces: dict[str, list[FakePage]] = field(default_factory=dict)
    #: Credential the fake source accepts. None means it needs none.
    expected_credential: str | None = None
    #: Raise from `discover`, as an unreachable source would.
    discovery_fails: bool = False

    connector_type: str = FAKE_CONNECTOR_TYPE

    def discover(self, connection: dict[str, Any], credential: str | None) -> Iterator[TaskSpec]:
        if self.discovery_fails:
            raise ConnectionError("fake source is unreachable")
        self._check_credential(credential)

        # Honours the same scope filter shape the Confluence connector will, so a
        # test of "only scan these spaces" exercises real filtering logic.
        wanted = connection.get("spaces") or []
        for space in sorted(self.spaces):
            if wanted and space not in wanted:
                continue
            yield TaskSpec(label=f"space {space}", params={"space": space})

    def fetch(
        self,
        connection: dict[str, Any],
        spec: TaskSpec,
        credential: str | None,
        outcome: FetchOutcome,
    ) -> Iterator[ContentUnit]:
        self._check_credential(credential)
        space = str(spec.params.get("space", ""))

        for page in self.spaces.get(space, []):
            if page.skip:
                outcome.skipped_for(
                    CoverageReason.UNSUPPORTED_TYPE,
                    CoverageObjectKind.RECORD,
                    page.resource_id,
                )
                continue
            if page.unreadable:
                # Keep yielding readable neighbors, then let the runner turn this
                # incomplete count into a failed task and partial scan.
                outcome.failed_for(
                    CoverageReason.CONNECTOR_ERROR,
                    CoverageObjectKind.RECORD,
                    page.resource_id,
                )
                continue

            outcome.scanned_for(CoverageObjectKind.RECORD, page.resource_id)
            yield ContentUnit(
                locator=CoarseLocator(
                    connector_type=self.connector_type,
                    resource_id=page.resource_id,
                    sub_resource=page.sub_resource,
                ),
                text=page.text,
                origin=page.origin,
                display={"space": space, **page.display},
            )

    def _check_credential(self, credential: str | None) -> None:
        if self.expected_credential is not None and credential != self.expected_credential:
            raise CredentialError("fake source rejected the credential")
