"""Engine-side suppression pre-filter (#44 — ADR 0008, 0009).

An engine has no database and no allowlist file. The suppressions applicable to
the task it holds arrive in the **lease response**, and this module applies them
to detection output before results are transmitted, so bandwidth is not spent on
matches nobody will look at.

This is an optimisation, not the enforcement point. The API applies the same
suppressions again at ingest, reading them at that moment — which is what makes a
suppression created after this engine took its lease still take effect. The
engine's snapshot can only ever be more permissive than the API's, never less,
and that asymmetry is deliberate: dropping something the API would have kept is a
finding that silently never existed, while keeping something the API will drop
costs one wasted payload.

Consistency is by construction rather than by agreement — the matching itself is
:mod:`iceberg_core.suppression`, the same module the API calls at ingest.
"""

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

import structlog
from iceberg_core.suppression import SuppressionRule, first_match

logger = structlog.get_logger()


class Detected(Protocol):
    """What the pre-filter needs to know about a candidate finding.

    A protocol rather than a concrete type so this module does not depend on the
    detection engine's shape: the worker assembles fingerprint and locator around
    a :class:`~iceberg_detect.DetectedSecret`, and only these three fields decide
    suppression.
    """

    @property
    def fingerprint(self) -> str: ...

    @property
    def rule_id(self) -> str: ...

    @property
    def resource_locator(self) -> dict[str, Any]: ...


@dataclass(frozen=True, slots=True)
class PrefilterResult[FindingT]:
    """What survived, and what did not."""

    kept: list[FindingT]
    #: Kept as pairs rather than a count: the log line names the suppression that
    #: fired, which is the difference between "12 suppressed" and an answer to
    #: "why did my scan report nothing?".
    suppressed: list[tuple[FindingT, SuppressionRule]]

    @property
    def suppressed_count(self) -> int:
        return len(self.suppressed)


def rules_from_lease(payloads: Iterable[dict[str, str]]) -> list[SuppressionRule]:
    """Parse the suppressions carried in a lease response.

    Raises on an entry it cannot interpret rather than skipping it: an engine that
    quietly ignored an unrecognised scope would pre-filter differently from the
    API, and a version skew would show up as findings that inexplicably stopped
    appearing rather than as an error.
    """
    return [SuppressionRule.from_payload(payload) for payload in payloads]


def prefilter[FindingT: Detected](
    findings: Sequence[FindingT],
    rules: Sequence[SuppressionRule],
) -> PrefilterResult[FindingT]:
    """Split detection output into what to report and what a suppression covers."""
    if not rules:
        return PrefilterResult(kept=list(findings), suppressed=[])

    ruleset = list(rules)
    kept: list[FindingT] = []
    suppressed: list[tuple[FindingT, SuppressionRule]] = []

    for finding in findings:
        rule = first_match(
            ruleset,
            fingerprint=finding.fingerprint,
            rule_id=finding.rule_id,
            resource_locator=finding.resource_locator,
        )
        if rule is None:
            kept.append(finding)
        else:
            suppressed.append((finding, rule))

    if suppressed:
        logger.info(
            "findings_prefiltered",
            suppressed=len(suppressed),
            kept=len(kept),
            suppression_ids=sorted({str(rule.id) for _, rule in suppressed}),
        )
    return PrefilterResult(kept=kept, suppressed=suppressed)
