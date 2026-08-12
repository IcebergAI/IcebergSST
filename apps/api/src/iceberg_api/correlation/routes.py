"""Exposure-cluster reads and export (ADR 0011, #140).

Analyst+, deliberately stricter than the findings queue a viewer can read. A
cluster view is the one place the API answers "is this the same secret as
that one" — the capability `findings/schemas.py` refuses to hand out casually —
so it is scoped to the roles that remediate. Under this deployment's global
ranked roles, "cluster access follows the strictest member permission" holds
by construction: there is no per-source grant a member could be stricter by.

The export is additionally audited: membership leaving the API as a file is an
administrative act with a name attached.
"""

import uuid
from typing import Annotated

import structlog
from fastapi import APIRouter, HTTPException, Path, Query, Response, status
from iceberg_core.enums import FindingState
from iceberg_core.models import (
    AUDIT_CORRELATION_CLUSTER_EXPORTED,
    AUDIT_TARGET_CORRELATION,
)

from iceberg_api import audit
from iceberg_api.auth.dependencies import SessionDep
from iceberg_api.auth.rbac import AnalystUser
from iceberg_api.correlation import service
from iceberg_api.correlation.manifest import build_cluster_manifest
from iceberg_api.correlation.schemas import (
    ClusterDetail,
    ClusterSourceGroup,
    ClusterSummary,
)
from iceberg_api.findings.schemas import FindingRead
from iceberg_api.pagination import DEFAULT_LIMIT, MAX_LIMIT
from iceberg_api.schemas import Page

router = APIRouter(prefix="/correlation", tags=["correlation"])
logger = structlog.get_logger()

#: What a correlation id looks like on the wire — an HMAC-SHA256 in hex. A
#: request for anything else is malformed, not merely unmatched.
CorrelationIdPath = Annotated[str, Path(pattern=r"^[0-9a-f]{64}$")]


def _summary(aggregate: service.ClusterAggregate) -> ClusterSummary:
    return ClusterSummary(
        correlation_id=aggregate.correlation_id,
        finding_count=aggregate.finding_count,
        source_count=aggregate.source_count,
        open_count=aggregate.open_count,
        max_severity=aggregate.max_severity,
        first_seen=aggregate.first_seen,
        last_activity=aggregate.last_activity,
    )


@router.get("/clusters")
async def list_clusters(
    analyst: AnalystUser,
    db: SessionDep,
    min_findings: Annotated[int, Query(ge=1)] = 1,
    source_id: Annotated[uuid.UUID | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = DEFAULT_LIMIT,
    cursor: Annotated[str | None, Query()] = None,
) -> Page[ClusterSummary]:
    """Every exposure cluster, in stable correlation-id order.

    ``min_findings`` is explicit like every list filter: the default of 1 hides
    nothing, and the console's spread view asks for ``?min_findings=2`` in its
    URL rather than having this endpoint quietly drop singletons.
    """
    aggregates, next_cursor = service.list_clusters(
        db,
        min_findings=min_findings,
        source_id=source_id,
        limit=limit,
        after_correlation_id=cursor,
    )
    return Page(items=[_summary(a) for a in aggregates], next_cursor=next_cursor)


def _load_cluster(db: SessionDep, correlation_id: str) -> service.ClusterAggregate:
    aggregate = service.cluster_aggregate(db, correlation_id)
    if aggregate is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "cluster not found")
    return aggregate


@router.get("/clusters/{correlation_id}")
async def read_cluster(
    correlation_id: CorrelationIdPath,
    analyst: AnalystUser,
    db: SessionDep,
) -> ClusterDetail:
    """One cluster's topology: members grouped by source, each triageable."""
    aggregate = _load_cluster(db, correlation_id)
    members = service.cluster_members(db, correlation_id)

    groups: dict[uuid.UUID, ClusterSourceGroup] = {}
    for finding, source_name in members:
        group = groups.get(finding.source_id)
        if group is None:
            groups[finding.source_id] = group = ClusterSourceGroup(
                source_id=finding.source_id,
                source_name=source_name,
                finding_count=0,
                open_count=0,
            )
        group.finding_count += 1
        if finding.state is FindingState.OPEN:
            group.open_count += 1

    return ClusterDetail(
        **_summary(aggregate).model_dump(),
        sources=list(groups.values()),
        members=[FindingRead.model_validate(finding) for finding, _ in members],
    )


@router.get("/clusters/{correlation_id}/export")
async def export_cluster(
    correlation_id: CorrelationIdPath,
    analyst: AnalystUser,
    db: SessionDep,
) -> Response:
    """Download the cluster as a byte-stable remediation work order.

    No snippet, no notes, no ``secret_hash`` — locations and states only. The
    download is audited with who and how much, because membership leaving the
    API as a file is worth a trail row.
    """
    aggregate = _load_cluster(db, correlation_id)
    manifest = build_cluster_manifest(aggregate, service.cluster_members(db, correlation_id))

    audit.record(
        db,
        actor_id=analyst.id,
        action=AUDIT_CORRELATION_CLUSTER_EXPORTED,
        target_type=AUDIT_TARGET_CORRELATION,
        target_id=None,
        detail={
            "correlation_id": correlation_id,
            "finding_count": str(aggregate.finding_count),
        },
    )
    db.commit()

    return Response(
        content=manifest.model_dump_json(),
        media_type="application/json",
        headers={
            "Cache-Control": "no-store",
            "Content-Disposition": f'attachment; filename="cluster-{correlation_id[:12]}.json"',
        },
    )
