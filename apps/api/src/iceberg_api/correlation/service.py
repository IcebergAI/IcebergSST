"""Cluster queries: GROUP BY over ``finding.correlation_id`` (ADR 0010, #140).

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


def cluster_aggregate(db: Session, correlation_id: str) -> ClusterAggregate | None:
    """The whole-cluster aggregate, or None when no finding carries the id."""
    row = db.execute(
        _aggregate_query().where(col(Finding.correlation_id) == correlation_id)
    ).first()
    return None if row is None else _to_aggregate(row)


def cluster_members(db: Session, correlation_id: str) -> list[tuple[Finding, str]]:
    """Members with their source names, `(created_at, id)` order, capped."""
    return list(
        db.exec(
            select(Finding, col(Source.name))
            .join(Source, col(Finding.source_id) == col(Source.id))
            .where(col(Finding.correlation_id) == correlation_id)
            .order_by(col(Finding.created_at), col(Finding.id))
            .limit(MAX_DETAIL_MEMBERS)
        )
    )
