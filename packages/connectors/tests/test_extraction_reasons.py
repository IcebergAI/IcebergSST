"""One extraction outcome, one manifest reason, for every connector (#197).

Each connector used to carry its own copy of this table, and they had drifted: a
compression bomb was a `size_limit` to the file-share connector and a
`parse_error` to the other two, so what a manifest said depended on which
connector met the file. Since the table is now shared there is nothing left to
diverge — what these guard is the table itself staying complete as
`ExtractionOutcome` grows.
"""

import pytest
from iceberg_connectors.extraction import ExtractionOutcome, coverage_reason
from iceberg_core.enums import CoverageReason


@pytest.mark.parametrize(
    "outcome",
    [outcome for outcome in ExtractionOutcome if outcome is not ExtractionOutcome.EXTRACTED],
)
def test_every_unsuccessful_outcome_has_a_reason(outcome: ExtractionOutcome) -> None:
    """A new member with no entry would otherwise reach a connector and fall into
    whatever its default was — which is how the drift happened."""
    assert isinstance(coverage_reason(outcome), CoverageReason)


def test_a_successful_extraction_has_no_reason_to_report() -> None:
    """Nothing went wrong, so asking is a caller bug rather than something to
    paper over with a default that would land in a manifest."""
    with pytest.raises(ValueError, match="extracted"):
        coverage_reason(ExtractionOutcome.EXTRACTED)


def test_a_refusal_to_expand_is_a_size_limit_not_a_parse_error() -> None:
    """The drift, pinned to the reading the enum's own names point at:
    `REJECTED_*` is a decision this code made about how big something would
    become, `FAILED_*` is something that broke. An operator sent to look for a
    malformed file by a `parse_error` would find a perfectly well-formed one."""
    assert coverage_reason(ExtractionOutcome.REJECTED_BOMB) is CoverageReason.SIZE_LIMIT
    assert coverage_reason(ExtractionOutcome.REJECTED_TOO_LARGE) is CoverageReason.SIZE_LIMIT
    assert coverage_reason(ExtractionOutcome.FAILED_PARSE) is CoverageReason.PARSE_ERROR


@pytest.mark.parametrize(
    ("outcome", "reason"),
    [
        (ExtractionOutcome.SKIPPED_BINARY, CoverageReason.BINARY_CONTENT),
        (ExtractionOutcome.SKIPPED_EMPTY, CoverageReason.EMPTY_CONTENT),
        (ExtractionOutcome.SKIPPED_UNSUPPORTED, CoverageReason.UNSUPPORTED_TYPE),
        (ExtractionOutcome.FAILED_TIMEOUT, CoverageReason.TIMEOUT),
    ],
)
def test_the_rest_of_the_table(outcome: ExtractionOutcome, reason: CoverageReason) -> None:
    assert coverage_reason(outcome) is reason


@pytest.mark.parametrize(
    "outcome",
    [outcome for outcome in ExtractionOutcome if outcome is not ExtractionOutcome.EXTRACTED],
)
def test_the_disposition_follows_is_incomplete(outcome: ExtractionOutcome) -> None:
    """The reason and the disposition are two halves of one decision: a policy
    skip is a `skipped_*` reason, and something that should have been readable is
    a failure, which is what stops reconciliation auto-resolving its findings."""
    policy_skips = {
        CoverageReason.BINARY_CONTENT,
        CoverageReason.EMPTY_CONTENT,
        CoverageReason.UNSUPPORTED_TYPE,
    }

    assert (coverage_reason(outcome) in policy_skips) is not outcome.is_incomplete
