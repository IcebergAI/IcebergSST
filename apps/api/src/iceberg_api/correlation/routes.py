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


@router.get("/clusters/{correlation_id}")
async def read_cluster(
    correlation_id: CorrelationIdPath,
    analyst: AnalystUser,
    db: SessionDep,
) -> ClusterDetail:
    """One cluster's topology: members grouped by source, each triageable.

    **The summary and the breakdown are one statement.** Both come from the
    per-source grouping, the header rolled up from the rows beneath it, so they
    cannot describe different snapshots — and the per-source counts are of the
    whole cluster rather than of whatever fitted on the page, which they were
    not when derived from the member list.

    ``members`` is deliberately still a page (`MAX_DETAIL_MEMBERS`): the counts
    an analyst needs are of the cluster, not of the page, so the header can
    exceed the list and the console renders "showing the first N of M". The
    export is where completeness matters, and it reads no aggregate at all.
    """
    groups = service.cluster_source_aggregates(db, correlation_id)
    if not groups:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "cluster not found")
    aggregate = service.roll_up(correlation_id, groups)
    members = service.cluster_members(db, correlation_id, limit=service.MAX_DETAIL_MEMBERS)

    return ClusterDetail(
        **_summary(aggregate).model_dump(),
        sources=[
            ClusterSourceGroup(
                source_id=group.source_id,
                source_name=group.source_name,
                finding_count=group.finding_count,
                open_count=group.open_count,
            )
            for group in groups
        ],
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

    **Complete or refused, never short.** Somebody works down this file to
    decide the exposure is closed, so a truncated one is a wrong answer wearing
    the shape of a right one. Past `MAX_EXPORT_MEMBERS` the route says so and
    names the paginated query that can walk a cluster of any size.

    **One statement decides everything.** The membership select is the only
    read here — there is no aggregate query to disagree with it. Existence,
    size, the manifest, and the audit row's count all come from the same rows,
    so no concurrent purge can leave the file and its trail entry describing
    different clusters.
    """
    # One row past the ceiling: enough to tell "too big" from "all of it".
    members = service.cluster_members(db, correlation_id, limit=service.MAX_EXPORT_MEMBERS + 1)
    if len(members) > service.MAX_EXPORT_MEMBERS:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"cluster has more than {service.MAX_EXPORT_MEMBERS} members and cannot be "
            f"exported as one work order; walk it with "
            f"GET /findings?correlation_id={correlation_id}",
        )
    if not members:
        # Either the id was never minted or retention purged the last member.
        # Both mean the same thing to a caller: there is no such cluster.
        raise HTTPException(status.HTTP_404_NOT_FOUND, "cluster not found")
    manifest = build_cluster_manifest(correlation_id, members)

    audit.record(
        db,
        actor_id=analyst.id,
        action=AUDIT_CORRELATION_CLUSTER_EXPORTED,
        target_type=AUDIT_TARGET_CORRELATION,
        target_id=None,
        detail={
            # The manifest's count, not a separately queried one: the trail row
            # says how much left the API, which is what it is for.
            "correlation_id": correlation_id,
            "finding_count": str(manifest.finding_count),
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
