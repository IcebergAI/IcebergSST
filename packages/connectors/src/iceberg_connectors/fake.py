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

from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from typing import Any

from iceberg_core.enums import CoverageObjectKind, CoverageReason
from iceberg_core.fingerprint import CoarseLocator

from iceberg_connectors.protocol import (
    ConnectorCapability,
    ConnectorMetadata,
    CredentialError,
    FetchOutcome,
    TaskSpec,
)
from iceberg_connectors.units import ContentOrigin, ContentUnit

FAKE_CONNECTOR_TYPE = "fake"

#: The fake's own resume protocol version, independent of the SDK's (#143).
FAKE_CHECKPOINT_VERSION = "1"

#: Stand-in for "the caller did not supply metadata", so `__post_init__` can fold
#: the `resumable`/`incremental` flags into the declared capability set. Frozen, so
#: sharing one instance across every default-constructed fake is safe.
_PLACEHOLDER_METADATA = ConnectorMetadata(connector_type=FAKE_CONNECTOR_TYPE)


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
    #: A monotonic revision tick, not a wall clock: incremental discovery has to
    #: be reproducible, and anything keyed on `now` differs between the two
    #: `discover()` calls the conformance kit compares.
    revision: int = 0


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
    #: Declare CHECKPOINTS and honour `outcome.resume_from` (#143). Off by default
    #: so a case that has not opted in keeps the pre-1.1 capability list.
    resumable: bool = False
    #: Declare INCREMENTAL and accept a `cursors` mapping in discovery (#143).
    incremental: bool = False

    connector_type: str = FAKE_CONNECTOR_TYPE
    #: Replaced in `__post_init__` unless the caller supplied their own. Identity,
    #: not equality: a caller may legitimately pass metadata equal to the default.
    metadata: ConnectorMetadata = _PLACEHOLDER_METADATA

    def __post_init__(self) -> None:
        if self.metadata is not _PLACEHOLDER_METADATA:
            return
        capabilities = {
            ConnectorCapability.DISCOVERY,
            ConnectorCapability.GAP_REPORTING,
            ConnectorCapability.ANONYMOUS_AUTH,
        }
        if self.resumable:
            capabilities.add(ConnectorCapability.CHECKPOINTS)
        if self.incremental:
            capabilities.add(ConnectorCapability.INCREMENTAL)
        self.metadata = ConnectorMetadata(
            connector_type=FAKE_CONNECTOR_TYPE,
            capabilities=frozenset(capabilities),
        )

    def discover(
        self,
        connection: dict[str, Any],
        credential: str | None,
        *,
        cursors: Mapping[str, Any] | None = None,
    ) -> Iterator[TaskSpec]:
        if self.discovery_fails:
            raise ConnectionError("fake source is unreachable")
        self._check_credential(credential)

        # Honours the same scope filter shape the Confluence connector will, so a
        # test of "only scan these spaces" exercises real filtering logic.
        wanted = connection.get("spaces") or []
        for space in sorted(self.spaces):
            if wanted and space not in wanted:
                continue
            since = self._since(space, cursors)
            if since is not None and not any(
                page.revision > since for page in self.spaces.get(space, [])
            ):
                # Nothing in this space changed. Yielding no spec at all is what
                # makes an incremental scan cheap — and why it must never be
                # allowed to auto-resolve.
                continue
            params: dict[str, Any] = {"space": space}
            if since is not None:
                params["since_revision"] = since
            yield TaskSpec(label=f"space {space}", params=params)

    def fetch(
        self,
        connection: dict[str, Any],
        spec: TaskSpec,
        credential: str | None,
        outcome: FetchOutcome,
    ) -> Iterator[ContentUnit]:
        self._check_credential(credential)
        space = str(spec.params.get("space", ""))
        since = spec.params.get("since_revision")
        pages = [
            page
            for page in self.spaces.get(space, [])
            if not isinstance(since, int) or page.revision > since
        ]
        skip_until = self._resume_after(outcome)

        for page in pages:
            if skip_until is not None:
                # Already yielded, already ingested by an earlier attempt's batch.
                # Re-counting it here would double it in the merged coverage.
                if page.resource_id == skip_until:
                    skip_until = None
                continue

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
            if self.resumable:
                # After the yield, never before: the boundary has to mean "this one
                # is out", or a resume here would skip it.
                outcome.checkpoint_at(FAKE_CHECKPOINT_VERSION, {"after": page.resource_id})

        if self.incremental and pages:
            outcome.cursor_at(
                space,
                FAKE_CHECKPOINT_VERSION,
                {"revision": max(page.revision for page in pages)},
            )

    def _resume_after(self, outcome: FetchOutcome) -> str | None:
        """The resource the last attempt finished on, if we can still trust it."""
        resume = outcome.resume_from
        if not self.resumable or resume is None:
            return None
        if resume.version != FAKE_CHECKPOINT_VERSION:
            # A checkpoint from a resume protocol this build no longer speaks.
            # Restarting the spec costs a re-read; guessing costs correctness.
            return None
        after = resume.position.get("after")
        return after if isinstance(after, str) and after else None

    def _since(self, space: str, cursors: Mapping[str, Any] | None) -> int | None:
        """The revision this space was last scanned through, if it has a cursor."""
        if not self.incremental or not cursors:
            return None
        position = cursors.get(space)
        if not isinstance(position, Mapping):
            return None
        revision = position.get("revision")
        return revision if isinstance(revision, int) else None

    def _check_credential(self, credential: str | None) -> None:
        if self.expected_credential is not None and credential != self.expected_credential:
            raise CredentialError("fake source rejected the credential")
