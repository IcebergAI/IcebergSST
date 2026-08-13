"""The cluster export manifest, built pure for byte-stability (ADR 0011).

Mirrors the coverage-manifest split (`scans/coverage.py`): the route loads
rows, this module shapes them, and a test can assert two builds of the same
state serialize identically — the property that makes an export diffable and
worth attaching to a remediation ticket.

Every summary number is derived from the members handed in, deliberately: an
export whose header is computed separately from its body can disagree with it,
and a work order that under-lists the places a secret lives is worse than no
export at all. The route's job is to hand over the complete membership or
refuse; this function's job is to describe exactly what it was given.
"""

from iceberg_core.enums import SEVERITY_RANK, FindingState, Severity
from iceberg_core.models import Finding

from iceberg_api.correlation.schemas import ClusterExportManifest, ClusterExportMember


def build_cluster_manifest(
    correlation_id: str,
    members: list[tuple[Finding, str]],
) -> ClusterExportManifest:
    """Shape one cluster as its export. Pure — no session, no clock.

    ``members`` must be the cluster's whole membership, and non-empty: every
    summary field here is an aggregate *over* the members, so there is no
    honest manifest for none of them. The route answers 404 in that case, which
    is what an emptied cluster means; this guard is so a future caller finds
    the contract rather than a bare `min() arg is an empty sequence`.
    """
    if not members:
        raise ValueError("a cluster manifest needs at least one member")
    findings = [finding for finding, _ in members]
    return ClusterExportManifest(
        correlation_id=correlation_id,
        finding_count=len(findings),
        source_count=len({finding.source_id for finding in findings}),
        open_count=sum(1 for finding in findings if finding.state is FindingState.OPEN),
        max_severity=_max_severity(findings),
        first_seen=min(finding.created_at for finding in findings),
        last_activity=max(finding.updated_at for finding in findings),
        members=[
            ClusterExportMember(
                finding_id=finding.id,
                source_id=finding.source_id,
                source_name=source_name,
                rule_id=finding.rule_id,
                severity=finding.severity,
                state=finding.state,
                resolution=finding.resolution,
                resource_locator=finding.resource_locator,
                first_seen_scan_id=finding.first_seen_scan_id,
                last_seen_scan_id=finding.last_seen_scan_id,
            )
            for finding, source_name in members
        ],
    )


def _max_severity(findings: list[Finding]) -> Severity:
    """The worst severity in the cluster, ranked rather than compared as text."""
    return max(findings, key=lambda finding: SEVERITY_RANK[finding.severity]).severity


__all__ = ["build_cluster_manifest"]
