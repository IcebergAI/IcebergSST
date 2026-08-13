"""Cluster queries: GROUP BY over ``finding.correlation_id`` (ADR 0011, #140).

Clusters are derived on read rather than materialized. A cluster table would be
one more thing for ingest, re-key, backfill, and reindex to keep consistent;
the index on ``correlation_id`` makes the grouping cheap, and a view that is
always derived can never be stale.
"""

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from iceberg_core.enums import FindingState, Severity
from iceberg_core.models import Finding, Source
from sqlalchemy import Select, case, func
from sqlalchemy import select as sa_select
from sqlmodel import Session, col, select

#: More members than any remediation view usefully renders; the detail says so
#: via ``finding_count`` rather than silently truncating.
MAX_DETAIL_MEMBERS = 500

#: The largest cluster that can be exported as one file. An export is a work
#: order somebody remediates from, so a *short* one is worse than none: it reads
#: as the full list of places the secret lives. The export therefore never
#: truncates — past this bound it refuses and points at the paginated findings
#: query instead (`routes.export_cluster`).
MAX_EXPORT_MEMBERS = 25_000

#: Severity ordered for SQL aggregation — the enum is stored as text, and
#: ``max('critical', 'low')`` in collation order would elect the wrong one.
_SEVERITY_RANK = case(
    {
        Severity.LOW.value: 0,
        Severity.MEDIUM.value: 1,
        Severity.HIGH.value: 2,
        Severity.CRITICAL.value: 3,
    },
    value=col(Finding.severity),
)
_SEVERITY_BY_RANK = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]

_OPEN = case((col(Finding.state) == FindingState.OPEN, 1), else_=0)


@dataclass(frozen=True, slots=True)
class ClusterAggregate:
    """One GROUP BY row, shaped for the response schemas."""

    correlation_id: str
    finding_count: int
    source_count: int
    open_count: int
    max_severity: Severity
    first_seen: datetime
    last_activity: datetime


def _aggregate_query() -> Select[Any]:
    # `sqlalchemy.select`: sqlmodel's overloads stop short of a seven-column
    # aggregate, and no ORM entity is selected here anyway.
    return (
        sa_select(
            col(Finding.correlation_id),
            func.count(col(Finding.id)),
            func.count(col(Finding.source_id).distinct()),
            func.sum(_OPEN),
            func.max(_SEVERITY_RANK),
            func.min(col(Finding.created_at)),
            func.max(col(Finding.updated_at)),
        )
        .where(col(Finding.correlation_id).is_not(None))
        .group_by(col(Finding.correlation_id))
    )


def _to_aggregate(row: Any) -> ClusterAggregate:
    correlation, findings, sources, open_count, severity_rank, first_seen, last_activity = row
    return ClusterAggregate(
        correlation_id=correlation,
        finding_count=int(findings),
        source_count=int(sources),
        open_count=int(open_count),
        max_severity=_SEVERITY_BY_RANK[int(severity_rank)],
        first_seen=first_seen,
        last_activity=last_activity,
    )


def list_clusters(
    db: Session,
    *,
    min_findings: int,
    source_id: uuid.UUID | None,
    limit: int,
    after_correlation_id: str | None,
) -> tuple[list[ClusterAggregate], str | None]:
    """One page of clusters in ``correlation_id`` order, plus the next cursor.

    The order is stable and arbitrary — correlation ids are opaque — which is
    exactly what a keyset needs. ``min_findings`` is an explicit filter like
    every other list filter; the API default of 1 hides nothing.
    """
    query = _aggregate_query()
    if source_id is not None:
        # Membership filter: clusters with at least one member in this source.
        # Aggregates still describe the whole cluster — a spread view filtered
        # to a source that then hid the spread would defeat its own point.
        in_source = (
            select(col(Finding.correlation_id))
            .where(col(Finding.source_id) == source_id)
            .where(col(Finding.correlation_id).is_not(None))
            .distinct()
        )
        query = query.where(col(Finding.correlation_id).in_(in_source))
    if after_correlation_id is not None:
        query = query.where(col(Finding.correlation_id) > after_correlation_id)
    query = (
        query.having(func.count(col(Finding.id)) >= min_findings)
        .order_by(col(Finding.correlation_id))
        .limit(limit + 1)
    )

    rows = [_to_aggregate(row) for row in db.execute(query)]
    page, has_more = rows[:limit], len(rows) > limit
    return page, page[-1].correlation_id if has_more and page else None


@dataclass(frozen=True, slots=True)
class SourceAggregate:
    """A cluster's footprint in one source, over the whole cluster."""

    source_id: uuid.UUID
    source_name: str
    finding_count: int
    open_count: int
    severity_rank: int
    first_seen: datetime
    last_activity: datetime


def cluster_source_aggregates(db: Session, correlation_id: str) -> list[SourceAggregate]:
    """Per-source counts for the whole cluster, in one statement.

    Two things follow from this being cluster-wide rather than derived from the
    member page, and both were wrong before. A cluster larger than
    `MAX_DETAIL_MEMBERS` used to report the *page's* per-source counts under a
    whole-cluster header; and the header and the groups came from two separate
    statements, so a concurrent purge could leave them disagreeing. Rolling the
    header up from these rows (`roll_up`) makes one query the source of both.
    """
    rows = db.execute(
        sa_select(
            col(Finding.source_id),
            col(Source.name),
            func.count(col(Finding.id)),
            func.sum(_OPEN),
            func.max(_SEVERITY_RANK),
            func.min(col(Finding.created_at)),
            func.max(col(Finding.updated_at)),
        )
        .join(Source, col(Finding.source_id) == col(Source.id))
        .where(col(Finding.correlation_id) == correlation_id)
        .group_by(col(Finding.source_id), col(Source.name))
        .order_by(col(Source.name))
    )
    return [_to_source_aggregate(row) for row in rows]


def _to_source_aggregate(row: Any) -> SourceAggregate:
    source_id, source_name, findings, open_count, severity_rank, first_seen, last_activity = row
    return SourceAggregate(
        source_id=source_id,
        source_name=source_name,
        finding_count=int(findings),
        open_count=int(open_count),
        severity_rank=int(severity_rank),
        first_seen=first_seen,
        last_activity=last_activity,
    )


def roll_up(correlation_id: str, groups: list[SourceAggregate]) -> ClusterAggregate:
    """The cluster summary as the sum of its per-source rows.

    Pure, and derived from the same statement the groups came from, so the
    header can never describe a different snapshot than the breakdown under it.
    Every field is expressible this way — that is why one grouped query can
    serve both.
    """
    return ClusterAggregate(
        correlation_id=correlation_id,
        finding_count=sum(group.finding_count for group in groups),
        source_count=len(groups),
        open_count=sum(group.open_count for group in groups),
        max_severity=_SEVERITY_BY_RANK[max(group.severity_rank for group in groups)],
        first_seen=min(group.first_seen for group in groups),
        last_activity=max(group.last_activity for group in groups),
    )


def cluster_members(db: Session, correlation_id: str, *, limit: int) -> list[tuple[Finding, str]]:
    """Members with their source names, `(created_at, id)` order, capped.

    The cap is a required parameter rather than a default because the two
    callers mean different things by it, and neither should inherit the other's
    silently. The detail screen's is a rendering budget: it shows a page and
    says so. The export's is a refusal threshold — it asks for one row more
    than it will accept, so that "the cluster is too big" and "here is the
    whole cluster" are distinguishable without a second count query.
    """
    return list(
        db.exec(
            select(Finding, col(Source.name))
            .join(Source, col(Finding.source_id) == col(Source.id))
            .where(col(Finding.correlation_id) == correlation_id)
            .order_by(col(Finding.created_at), col(Finding.id))
            .limit(limit)
        )
    )
