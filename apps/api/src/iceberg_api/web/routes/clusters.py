"""Exposure clusters: the spread view and one cluster's topology (#140).

Analyst screens — the rail shows them to analysts and admins, and
`web_require_role` enforces it (the rail reflects permissions; rbac enforces
them). The API's `min_findings` filter is explicit like every other, so the
console's default — "show me secrets that have actually spread" — is a
*redirect into* `?min_findings=2` rather than a hidden server-side default:
the URL always says what the table shows.
"""

from typing import Annotated

from fastapi import APIRouter, Query, Request, Response
from fastapi.responses import RedirectResponse

from iceberg_api.auth.dependencies import SessionDep
from iceberg_api.correlation import routes as api
from iceberg_api.findings.schemas import FindingRead
from iceberg_api.pagination import DEFAULT_LIMIT
from iceberg_api.web.dependencies import CurrentViewer, WebAnalyst
from iceberg_api.web.templating import render_page

router = APIRouter(include_in_schema=False)

#: The screen's default: clusters that have spread beyond one finding. `1`
#: (via "Show all") is every cluster, singletons included.
DEFAULT_MIN_FINDINGS = 2


def _min_findings(value: str | None) -> int | None:
    """The filter from the query string, or None for "redirect to the default".

    Junk degrades to the default view rather than a 422 — same contract as the
    findings filters.
    """
    if value is None:
        return None
    try:
        return max(1, int(value))
    except ValueError:
        return None


@router.get("/clusters")
async def clusters_page(
    request: Request,
    viewer: CurrentViewer,
    analyst: WebAnalyst,
    db: SessionDep,
    min_findings: Annotated[str | None, Query()] = None,
    cursor: Annotated[str | None, Query()] = None,
) -> Response:
    """The spread view: one row per secret value, counted across its locations."""
    minimum = _min_findings(min_findings)
    if minimum is None:
        return RedirectResponse(f"/clusters?min_findings={DEFAULT_MIN_FINDINGS}", status_code=303)

    page = await api.list_clusters(
        analyst=analyst,
        db=db,
        min_findings=minimum,
        source_id=None,
        limit=DEFAULT_LIMIT,
        cursor=cursor,
    )
    return render_page(
        request,
        "correlation/list.html",
        viewer,
        {
            "clusters": page.items,
            "next_cursor": page.next_cursor,
            "min_findings": minimum,
            "showing_all": minimum <= 1,
        },
    )


@router.get("/clusters/{correlation_id}")
async def cluster_detail(
    request: Request,
    correlation_id: str,
    viewer: CurrentViewer,
    analyst: WebAnalyst,
    db: SessionDep,
) -> Response:
    """One exposure: every location of the same secret, grouped by source."""
    cluster = await api.read_cluster(correlation_id=correlation_id, analyst=analyst, db=db)

    members_by_source: dict[str, list[FindingRead]] = {}
    names = {group.source_id: group.source_name for group in cluster.sources}
    for member in cluster.members:
        members_by_source.setdefault(names.get(member.source_id, str(member.source_id)), []).append(
            member
        )

    return render_page(
        request,
        "correlation/detail.html",
        viewer,
        {
            "cluster": cluster,
            "members_by_source": members_by_source,
            "truncated": len(cluster.members) < cluster.finding_count,
            "export_url": f"/api/v1/correlation/clusters/{cluster.correlation_id}/export",
        },
    )
