"""The interface every connector implements (#45 — ADR 0002, 0009).

Two methods, because a scan is two-phase:

* :meth:`Connector.discover` splits a source into units of work — one per
  Confluence space, one per share subtree — and returns their specs. The API turns
  each into a fetch task, so this is what makes a scan parallelisable across
  engines.
* :meth:`Connector.fetch` runs one of those specs and yields
  :class:`~iceberg_connectors.units.ContentUnit`\\ s.

Both run **inside an engine**, never the API (ADR 0002). The credential arrives as
an argument, from the task lease — never from the environment, a config file, or
the database, none of which an engine has access to (ADR 0007/0009).

Connectors are generators by contract. A source with fifty thousand pages must not
have to exist in memory before detection sees the first one, and a task that is
cancelled mid-fetch should stop fetching rather than finish and discard.
"""

from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from iceberg_connectors.units import ContentUnit


class ConnectorError(Exception):
    """A connector could not do its job.

    Raised for conditions the *task* cannot recover from — bad credentials, a
    source that does not answer. A single unreadable page is not this: connectors
    skip and count those, because one bad page should not fail a scan of fifty
    thousand (:class:`FetchOutcome`).
    """


class CredentialError(ConnectorError):
    """The source rejected the credential.

    Separate because the operator response is different and specific: rotate the
    credential. Retrying will not help, and the scan should say so rather than
    reporting an empty source.
    """


@dataclass(frozen=True, slots=True)
class TaskSpec:
    """One unit of fetch work, as discovery describes it.

    Crosses the wire twice — engine → API at the end of discovery, API → engine in
    the lease — so it is a plain JSON-able mapping rather than a rich object. The
    ``label`` is for humans watching a scan; everything the connector needs to do
    the work is in ``params``.
    """

    label: str
    params: dict[str, Any] = field(default_factory=dict)

    def as_payload(self) -> dict[str, Any]:
        return {"label": self.label, "params": self.params}

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> "TaskSpec":
        """Rebuild a spec from a lease. Tolerates a bare params mapping.

        A spec written by an older engine may have no ``label``; that is cosmetic,
        so it defaults rather than failing a task over a display string.
        """
        if "params" not in payload:
            return cls(label=str(payload.get("label", "fetch")), params=dict(payload))
        return cls(label=str(payload.get("label", "fetch")), params=dict(payload["params"]))


@dataclass(slots=True)
class FetchOutcome:
    """Tallies a fetch reports alongside its units.

    Skips are counted, never silent. "The scan found nothing" and "the scan could
    not read anything" look identical in a findings list and could not be more
    different, and the only place to tell them apart is here.
    """

    units: int = 0
    #: Resources deliberately not scanned — an image, a binary, an unsupported
    #: format. Expected, not a problem.
    skipped: int = 0
    #: Resources that should have been readable and were not.
    failed: int = 0

    def as_counts(self) -> dict[str, int]:
        """The shape merged into the scan's counts by results ingest."""
        return {"units": self.units, "units_skipped": self.skipped, "units_failed": self.failed}


@runtime_checkable
class Connector(Protocol):
    """What the engine worker needs from any source type.

    A :class:`~typing.Protocol` rather than a base class: connectors have nothing
    to inherit, and structural typing means a test double is a connector without
    importing anything from here.
    """

    #: Matches `SourceType`. Recorded in every fingerprint, so it is a stable
    #: contract — renaming one invalidates every finding from that source type.
    connector_type: str

    def discover(self, connection: dict[str, Any], credential: str | None) -> Iterator[TaskSpec]:
        """Split a source into fetch specs.

        ``connection`` is the source's stored blob — base URL, scope filters.
        Yielding nothing is a legitimate answer (an empty source), and the scan
        will complete having scanned nothing; reconciliation refuses to
        auto-resolve on that evidence alone (ADR 0009 §4).
        """
        ...

    def fetch(
        self,
        connection: dict[str, Any],
        spec: TaskSpec,
        credential: str | None,
        outcome: FetchOutcome,
    ) -> Iterator[ContentUnit]:
        """Yield the content units for one spec, tallying skips into ``outcome``.

        ``outcome`` is passed in rather than returned because this is a generator:
        the caller needs the tallies even if it stops consuming early, which a
        return value could not give it.
        """
        ...
