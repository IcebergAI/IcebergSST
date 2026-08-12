"""Deterministic, privacy-bounded scan coverage manifests (#148).

Only typed task coverage and scan identity fields enter this module.  In
particular it never serializes source rows, task specs/errors, finding locators,
or the legacy arbitrary ``Scan.counts`` mapping.
"""

from collections import Counter
from collections.abc import Sequence

from iceberg_core.enums import (
    MAX_COVERAGE_GAP_REFERENCES,
    CoverageDisposition,
    CoverageReason,
    CoverageState,
    ScanStatus,
    ScanTaskKind,
    ScanTaskStatus,
)
from iceberg_core.models import Scan, ScanTask
from pydantic import ValidationError

from iceberg_api.engines.schemas import (
    CoverageCounts,
    CoverageReasonCount,
    CoverageScope,
    TaskCoverageReport,
)
from iceberg_api.scans.schemas import (
    CoverageManifest,
    CoverageManifestGap,
    CoverageTaskCounts,
)


def build_manifest(scan: Scan, tasks: Sequence[ScanTask]) -> CoverageManifest:
    """Build the same allowlisted manifest for the same frozen terminal rows."""
    counts = Counter[str]()
    reasons: Counter[tuple[CoverageDisposition, CoverageReason]] = Counter()
    gaps: list[CoverageManifestGap] = []
    gaps_omitted = 0
    reported = 0
    unreported = 0
    discovery_requested = 0
    discovery_requested_known = True
    scope_discovered = 0
    scope_gaps = 0
    fetch_scope_gap = False

    ordered = sorted(tasks, key=lambda task: (task.created_at, str(task.id)))
    for task in ordered:
        report = _validated_report(task)
        if report is None:
            unreported += 1
            scope_gaps += 1
            gaps_omitted += 1
            reasons[(CoverageDisposition.SCOPE_GAP, CoverageReason.UNREPORTED)] += 1
            if task.kind is ScanTaskKind.DISCOVERY:
                discovery_requested_known = False
            else:
                fetch_scope_gap = True
            continue

        reported += 1
        for name in ("requested", "discovered", "scanned", "skipped", "failed"):
            counts[name] += int(getattr(report.counts, name))
        scope_discovered += report.scope.discovered
        scope_gaps += report.scope.gaps
        gaps_omitted += report.gaps_omitted
        if task.kind is ScanTaskKind.DISCOVERY:
            if report.scope.requested is None:
                discovery_requested_known = False
            else:
                discovery_requested += report.scope.requested
        elif report.scope.gaps:
            fetch_scope_gap = True

        for entry in report.reasons:
            reasons[(entry.outcome, entry.reason)] += entry.count
        retained = report.gaps[: MAX_COVERAGE_GAP_REFERENCES - len(gaps)]
        gaps_omitted += len(report.gaps) - len(retained)
        gaps.extend(
            CoverageManifestGap(
                task_id=task.id,
                phase=report.phase,
                kind=gap.kind,
                outcome=gap.outcome,
                reason=gap.reason,
                reference=gap.reference,
            )
            for gap in retained
        )

    task_statuses = Counter(task.status for task in ordered)
    requested_scope = (
        discovery_requested if discovery_requested_known and not fetch_scope_gap else None
    )
    # A requested total that excludes an unknown fetch collection is worse than
    # null: it would look exact.  With no fetch-level gaps, the known discovery
    # equation remains meaningful and is validated by CoverageScope.
    if requested_scope is not None and requested_scope != scope_discovered + scope_gaps:
        requested_scope = None

    manifest = CoverageManifest(
        scan_id=scan.id,
        source_id=scan.source_id,
        scan_status=scan.status,
        coverage_state=_coverage_state(
            scan.status,
            skipped=counts["skipped"],
            failed=counts["failed"],
            scope_gaps=scope_gaps,
            unreported=unreported,
        ),
        source_configuration_version=scan.source_configuration_version,
        rulepack_version=scan.rulepack_version,
        finalized_at=scan.finished_at or scan.updated_at,
        counts=CoverageCounts(
            requested=counts["requested"],
            discovered=counts["discovered"],
            scanned=counts["scanned"],
            skipped=counts["skipped"],
            failed=counts["failed"],
        ),
        scope=CoverageScope(
            requested=requested_scope,
            discovered=scope_discovered,
            gaps=scope_gaps,
        ),
        reasons=[
            CoverageReasonCount(outcome=outcome, reason=reason, count=count)
            for (outcome, reason), count in sorted(
                reasons.items(), key=lambda item: (item[0][0].value, item[0][1].value)
            )
        ],
        task_counts=CoverageTaskCounts(
            total=len(ordered),
            completed=task_statuses[ScanTaskStatus.COMPLETED],
            failed=task_statuses[ScanTaskStatus.FAILED],
            cancelled=task_statuses[ScanTaskStatus.CANCELLED],
            reported=reported,
            unreported=unreported,
        ),
        gaps=gaps,
        gaps_omitted=gaps_omitted,
    )
    return manifest


def frozen_or_built_manifest(scan: Scan, tasks: Sequence[ScanTask]) -> CoverageManifest:
    """Read a frozen new manifest, falling back honestly for historic rows."""
    if scan.coverage_manifest:
        try:
            return CoverageManifest.model_validate(scan.coverage_manifest)
        except ValidationError:
            # A corrupt/old manifest can never be presented as trustworthy. The
            # task rows still let the fallback surface explicit unreported gaps.
            pass
    return build_manifest(scan, tasks)


def failure_report(
    phase: ScanTaskKind,
    reason: CoverageReason,
) -> dict[str, object]:
    """API-origin terminal evidence when no engine result can be accepted."""
    return {
        "version": "1",
        "phase": phase.value,
        "counts": {
            "requested": 0,
            "discovered": 0,
            "scanned": 0,
            "skipped": 0,
            "failed": 0,
        },
        "scope": {"requested": None, "discovered": 0, "gaps": 1},
        "reasons": [
            {
                "outcome": CoverageDisposition.SCOPE_GAP.value,
                "reason": reason.value,
                "count": 1,
            }
        ],
        "gaps": [],
        "gaps_omitted": 1,
    }


def _validated_report(task: ScanTask) -> TaskCoverageReport | None:
    if not task.coverage:
        return None
    try:
        report = TaskCoverageReport.model_validate(task.coverage)
    except ValidationError:
        return None
    return report if report.phase is task.kind else None


def _coverage_state(
    status: ScanStatus,
    *,
    skipped: int,
    failed: int,
    scope_gaps: int,
    unreported: int,
) -> CoverageState:
    if status is ScanStatus.CANCELLED:
        return CoverageState.CANCELLED
    if status is ScanStatus.FAILED:
        return CoverageState.FAILED
    if status is ScanStatus.PARTIAL:
        return CoverageState.PARTIAL
    if skipped or failed or scope_gaps or unreported:
        return CoverageState.PARTIAL
    return CoverageState.COMPLETE
