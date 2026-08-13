"""The cluster export manifest, built pure for byte-stability (ADR 0011).

Mirrors the coverage-manifest split (`scans/coverage.py`): the route loads
rows, this module shapes them, and a test can assert two builds of the same
state serialize identically — the property that makes an export diffable and
worth attaching to a remediation ticket.
"""

from iceberg_core.models import Finding

from iceberg_api.correlation.schemas import ClusterExportManifest, ClusterExportMember
from iceberg_api.correlation.service import ClusterAggregate


def build_cluster_manifest(
    aggregate: ClusterAggregate,
    members: list[tuple[Finding, str]],
) -> ClusterExportManifest:
    """Shape one cluster as its export. Pure — no session, no clock.

    ``members_omitted`` is derived from the gap between the aggregate's count
    and the rows actually loaded, so a truncated export says so in the file.
    """
    return ClusterExportManifest(
        members_omitted=max(0, aggregate.finding_count - len(members)),
        correlation_id=aggregate.correlation_id,
        finding_count=aggregate.finding_count,
        source_count=aggregate.source_count,
        open_count=aggregate.open_count,
        max_severity=aggregate.max_severity,
        first_seen=aggregate.first_seen,
        last_activity=aggregate.last_activity,
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
