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

import hashlib
import hmac
import json
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Protocol, runtime_checkable

from iceberg_core.enums import (
    MAX_COVERAGE_GAP_REFERENCES,
    CoverageDisposition,
    CoverageObjectKind,
    CoverageReason,
    ScanTaskKind,
    coverage_reason_allowed,
)

from iceberg_connectors.units import ContentUnit

_REFERENCE_DOMAIN = b"IcebergSST coverage reference v1\0"
CONNECTOR_SDK_VERSION = "1.0"


class ConnectorCapability(StrEnum):
    """Machine-readable behavior an engine/operator may rely on."""

    DISCOVERY = "discovery"
    PAGINATION = "pagination"
    ATTACHMENTS = "attachments"
    COMMENTS = "comments"
    GAP_REPORTING = "gap_reporting"
    CHECKPOINTS = "checkpoints"
    ANONYMOUS_AUTH = "anonymous_auth"


@dataclass(frozen=True, slots=True)
class ConnectorMetadata:
    """Stable SDK identity and explicitly declared optional behavior."""

    connector_type: str
    sdk_version: str = CONNECTOR_SDK_VERSION
    capabilities: frozenset[ConnectorCapability] = frozenset(
        {ConnectorCapability.DISCOVERY, ConnectorCapability.GAP_REPORTING}
    )

    def as_payload(self) -> dict[str, object]:
        return {
            "connector_type": self.connector_type,
            "sdk_version": self.sdk_version,
            "capabilities": sorted(capability.value for capability in self.capabilities),
        }


class ConnectorFailureCode(StrEnum):
    CONNECTOR_ERROR = "connector_error"
    CREDENTIAL_REJECTED = "credential_rejected"
    RATE_LIMITED = "rate_limited"


class ConnectorError(Exception):
    """A connector could not do its job.

    Raised for conditions the *task* cannot recover from — bad credentials, a
    source that does not answer. A single unreadable page is counted in
    :class:`FetchOutcome` instead so the connector can continue and preserve
    findings from readable units. The engine still fails the task afterward,
    making the scan partial and disabling reconciliation and notifications.
    """

    code = ConnectorFailureCode.CONNECTOR_ERROR
    retryable = False


class CredentialError(ConnectorError):
    """The source rejected the credential.

    Separate because the operator response is different and specific: rotate the
    credential. Retrying will not help, and the scan should say so rather than
    reporting an empty source.
    """

    code = ConnectorFailureCode.CREDENTIAL_REJECTED


class RateLimitError(ConnectorError):
    """A source exhausted the connector's bounded throttle wait budget."""

    code = ConnectorFailureCode.RATE_LIMITED
    retryable = True


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
    def from_payload(cls, payload: dict[str, Any]) -> TaskSpec:
        """Rebuild a spec from a lease. Tolerates a bare params mapping.

        A spec written by an older engine may have no ``label``; that is cosmetic,
        so it defaults rather than failing a task over a display string.
        """
        if "params" not in payload:
            return cls(label=str(payload.get("label", "fetch")), params=dict(payload))
        return cls(label=str(payload.get("label", "fetch")), params=dict(payload["params"]))


@dataclass(slots=True)
class TaskCoverage:
    """Typed, content-free coverage accumulated by one engine task.

    Raw source identifiers never enter :meth:`as_payload`.  Gap references are
    domain-separated HMACs under the scan's fingerprint pepper, so operators can
    correlate the same blind spot across exports without learning a page id,
    filename, path, or configured scope value from the manifest itself.
    """

    phase: ScanTaskKind
    reference_key: bytes | None = field(default=None, repr=False)
    requested: int = 0
    discovered: int = 0
    scanned: int = 0
    skipped: int = 0
    failed: int = 0
    scope_requested: int | None = None
    scope_discovered: int = 0
    scope_gaps: int = 0
    reason_counts: Counter[tuple[CoverageDisposition, CoverageReason]] = field(
        default_factory=Counter
    )
    gaps: list[dict[str, str]] = field(default_factory=list)
    gaps_omitted: int = 0

    def scanned_for(self, kind: CoverageObjectKind, reference: object) -> None:
        """Record one enumerated object that detection inspected completely."""
        self._observed()
        self.scanned += 1

    def skipped_for(
        self,
        reason: CoverageReason,
        kind: CoverageObjectKind,
        reference: object | None,
    ) -> None:
        """Record one requested object intentionally excluded by policy."""
        self._require_reason(CoverageDisposition.SKIPPED, reason)
        self._observed()
        self.skipped += 1
        self._gap(CoverageDisposition.SKIPPED, reason, kind, reference)

    def failed_for(
        self,
        reason: CoverageReason,
        kind: CoverageObjectKind,
        reference: object | None,
    ) -> None:
        """Record one enumerated object that could not be inspected."""
        self._require_reason(CoverageDisposition.FAILED, reason)
        self._observed()
        self.failed += 1
        self._gap(CoverageDisposition.FAILED, reason, kind, reference)

    def scanned_but_incomplete(
        self,
        reason: CoverageReason,
        kind: CoverageObjectKind,
        reference: object,
    ) -> None:
        """Replace an already-recorded scan with one incomplete final outcome."""
        self._require_reason(CoverageDisposition.FAILED, reason)
        if self.scanned < 1:  # pragma: no cover - defensive connector/runner contract
            raise ValueError("cannot mark an unrecorded object incomplete")
        self.scanned -= 1
        self.failed += 1
        self._gap(CoverageDisposition.FAILED, reason, kind, reference)

    def scope_found(self, reference: object) -> None:
        """Record one configured or discoverable scope successfully enumerated."""
        self.scope_discovered += 1

    def scope_gap(self, reason: CoverageReason, reference: object | None) -> None:
        """Record work whose object cardinality could not be enumerated honestly."""
        self._require_reason(CoverageDisposition.SCOPE_GAP, reason)
        self.scope_gaps += 1
        self._gap(CoverageDisposition.SCOPE_GAP, reason, CoverageObjectKind.SCOPE, reference)

    def as_payload(self) -> dict[str, Any]:
        """Return the versioned engine/API wire shape; no raw source metadata."""
        reasons = [
            {"outcome": outcome.value, "reason": reason.value, "count": count}
            for (outcome, reason), count in sorted(
                self.reason_counts.items(), key=lambda item: (item[0][0].value, item[0][1].value)
            )
        ]
        return {
            "version": "1",
            "phase": self.phase.value,
            "counts": {
                "requested": self.requested,
                "discovered": self.discovered,
                "scanned": self.scanned,
                "skipped": self.skipped,
                "failed": self.failed,
            },
            "scope": {
                "requested": self.scope_requested,
                "discovered": self.scope_discovered,
                "gaps": self.scope_gaps,
            },
            "reasons": reasons,
            "gaps": list(self.gaps),
            "gaps_omitted": self.gaps_omitted,
        }

    def _observed(self) -> None:
        self.requested += 1
        self.discovered += 1

    def _gap(
        self,
        outcome: CoverageDisposition,
        reason: CoverageReason,
        kind: CoverageObjectKind,
        reference: object | None,
    ) -> None:
        self.reason_counts[(outcome, reason)] += 1
        opaque = self._reference(kind, reference)
        if opaque is None or len(self.gaps) >= MAX_COVERAGE_GAP_REFERENCES:
            self.gaps_omitted += 1
            return
        self.gaps.append(
            {
                "kind": kind.value,
                "outcome": outcome.value,
                "reason": reason.value,
                "reference": opaque,
            }
        )

    @staticmethod
    def _require_reason(
        outcome: CoverageDisposition,
        reason: CoverageReason,
    ) -> None:
        if not coverage_reason_allowed(outcome, reason):
            raise ValueError(f"{reason.value} is not a valid {outcome.value} coverage reason")

    def _reference(self, kind: CoverageObjectKind, reference: object | None) -> str | None:
        if self.reference_key is None or reference is None:
            return None
        canonical = json.dumps(
            reference,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ).encode()
        message = _REFERENCE_DOMAIN + kind.value.encode() + b"\0" + canonical
        return hmac.new(self.reference_key, message, hashlib.sha256).hexdigest()


@dataclass(slots=True)
class FetchOutcome:
    """Tallies a fetch reports alongside its units.

    Skips are counted, never silent. "The scan found nothing" and "the scan could
    not read anything" look identical in a findings list and could not be more
    different, and the only place to tell them apart is here.
    """

    reference_key: bytes | None = field(default=None, repr=False)
    units: int = 0
    #: Resources deliberately not scanned — an image, a binary, an unsupported
    #: format. Expected, not a problem.
    skipped: int = 0
    #: Resources that should have been readable and were not.
    failed: int = 0
    coverage: TaskCoverage = field(init=False)

    def __post_init__(self) -> None:
        self.coverage = TaskCoverage(phase=ScanTaskKind.FETCH, reference_key=self.reference_key)

    def scanned_for(self, kind: CoverageObjectKind, reference: object) -> None:
        self.units += 1
        self.coverage.scanned_for(kind, reference)

    def failed_for(
        self,
        reason: CoverageReason,
        kind: CoverageObjectKind = CoverageObjectKind.RECORD,
        reference: object | None = None,
    ) -> None:
        self.failed += 1
        self.coverage.failed_for(reason, kind, reference)

    def skipped_for(
        self,
        reason: CoverageReason,
        kind: CoverageObjectKind = CoverageObjectKind.RECORD,
        reference: object | None = None,
    ) -> None:
        self.skipped += 1
        self.coverage.skipped_for(reason, kind, reference)

    def scope_gap_for(self, reason: CoverageReason, reference: object | None = None) -> None:
        """Fail the legacy task while keeping unknown object counts out of totals."""
        self.failed += 1
        self.coverage.scope_gap(reason, reference)

    def scanned_but_incomplete(
        self,
        reason: CoverageReason,
        kind: CoverageObjectKind,
        reference: object,
    ) -> None:
        self.coverage.scanned_but_incomplete(reason, kind, reference)

    def as_counts(self) -> dict[str, int]:
        """The shape merged into the scan's counts by results ingest."""
        return {
            "units": self.units,
            "units_skipped": self.skipped,
            "units_failed": self.failed,
        }

    def as_coverage(self) -> dict[str, Any]:
        return self.coverage.as_payload()


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
    metadata: ConnectorMetadata

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
        """Yield units for one spec, tallying skips and failures into ``outcome``.

        ``outcome`` is passed in rather than returned because this is a generator:
        the caller needs the tallies even if it stops consuming early, which a
        return value could not give it.
        """
        ...
