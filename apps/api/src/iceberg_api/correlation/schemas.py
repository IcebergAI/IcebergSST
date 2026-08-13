"""Response shapes for exposure clusters (ADR 0011, #140).

A cluster is derived, not stored: the rows are findings, the grouping is
``correlation_id``. These shapes carry the id itself — an API-minted equality
label — and never ``secret_hash``, the snippet of any member beyond what the
findings API already shows, or anything an engine could recompute.
"""

import uuid
from typing import Literal

from iceberg_core.enums import FindingResolution, FindingState, Severity
from pydantic import BaseModel, ConfigDict

from iceberg_api.findings.schemas import FindingRead
from iceberg_api.schemas import UtcDatetime


class ClusterSummary(BaseModel):
    """One exposure, aggregated: the same secret value wherever it was seen."""

    correlation_id: str
    finding_count: int
    source_count: int
    #: Members still ``open`` — the remediation debt left in this cluster.
    open_count: int
    max_severity: Severity
    #: When the first member was ingested.
    first_seen: UtcDatetime
    #: The latest activity on any member — a sighting refresh or a triage change.
    last_activity: UtcDatetime


class ClusterSourceGroup(BaseModel):
    """A cluster's footprint in one source."""

    source_id: uuid.UUID
    source_name: str
    finding_count: int
    open_count: int


class ClusterDetail(ClusterSummary):
    """The topology: members grouped by source, each independently triageable."""

    sources: list[ClusterSourceGroup]
    #: Every member, `(created_at, id)` order. Findings-API shape — the same
    #: fields the queue shows, so nothing new is exposed by clustering them.
    members: list[FindingRead]


class ClusterExportMember(BaseModel):
    """One location in the export: where, what rule, and its remediation state.

    Deliberately narrower than :class:`FindingRead` — an export travels (ticket
    attachments, audits), so it carries no snippet and no analyst notes.
    """

    model_config = ConfigDict(extra="forbid")

    finding_id: uuid.UUID
    source_id: uuid.UUID
    source_name: str
    rule_id: str
    severity: Severity
    state: FindingState
    resolution: FindingResolution | None
    resource_locator: dict[str, object]
    first_seen_scan_id: uuid.UUID
    last_seen_scan_id: uuid.UUID


class ClusterExportManifest(BaseModel):
    """``GET /correlation/clusters/{id}/export``: the remediation work order.

    Built by a pure function and byte-stable for the same database state, so two
    exports of an unchanged cluster diff clean.
    """

    model_config = ConfigDict(extra="forbid")

    manifest_version: Literal[1] = 1
    correlation_id: str
    finding_count: int
    source_count: int
    open_count: int
    max_severity: Severity
    first_seen: UtcDatetime
    last_activity: UtcDatetime
    members: list[ClusterExportMember]
    #: Members beyond the export ceiling, counted rather than dropped in
    #: silence — ``finding_count`` describes the whole cluster, so without this
    #: a reader could not tell a complete export from a truncated one. Zero for
    #: every cluster small enough to fit, which is nearly all of them.
    members_omitted: int = 0
