"""The engine pre-filter and server ingest agree, on shared fixtures (#44).

This lives in the root suite rather than under either app: it is the one test that
has to import both roles at once, and putting it in `apps/api/tests` would give the
API package a test-time dependency on the engine that its own metadata does not
declare.

The property is not "the two implementations happen to agree". They are one
implementation — :mod:`iceberg_core.suppression` — and this asserts that the two
call sites feed it the same things, which is the part refactoring can break.
"""

import uuid
from dataclasses import dataclass
from typing import Any

import pytest
from iceberg_api import suppressions
from iceberg_core.enums import SourceType, SuppressionScope
from iceberg_core.models import Source, Suppression
from iceberg_core.suppression import SuppressionRule
from iceberg_engine.suppression import prefilter, rules_from_lease
from sqlmodel import Session


@dataclass(frozen=True, slots=True)
class Candidate:
    """What the engine holds before it submits: a fingerprint, a rule, a locator."""

    fingerprint: str
    rule_id: str
    resource_locator: dict[str, Any]


#: One fixture set, exercised through both paths. Each entry is a candidate and
#: whether the suppressions below should cover it.
CANDIDATES: tuple[tuple[Candidate, bool], ...] = (
    (Candidate("a" * 64, "aws-access-key-id", {"path": "/space/SANDBOX/page-1"}), True),
    (Candidate("b" * 64, "aws-access-key-id", {"path": "/space/PROD/page-2"}), False),
    (Candidate("c" * 64, "generic-high-entropy", {"path": "/space/PROD/page-3"}), True),
    (Candidate("d" * 64, "github-token", {"url": "https://wiki.test/SANDBOX/x"}), False),
    (Candidate("e" * 64, "github-token", {"path": "/space/PROD/page-4"}), True),
    (Candidate("f" * 64, "slack-token", {}), False),
    (Candidate("f" * 63 + "0", "slack-token", {"title": "runbook"}), False),
)

SUPPRESSION_SPECS: tuple[tuple[SuppressionScope, str], ...] = (
    (SuppressionScope.PATH_GLOB, "/space/SANDBOX/*"),
    (SuppressionScope.RULE, "generic-high-entropy"),
    (SuppressionScope.FINGERPRINT, "e" * 64),
)


def _source(session: Session) -> Source:
    source = Source(
        name=f"confluence-{uuid.uuid4().hex[:6]}",
        type=SourceType.CONFLUENCE,
        connection={"base_url": "https://example.atlassian.net/wiki"},
    )
    session.add(source)
    session.commit()
    return source


@pytest.fixture(name="rules")
def rules_fixture() -> list[SuppressionRule]:
    return [
        SuppressionRule(id=uuid.uuid4(), scope=scope, pattern=pattern)
        for scope, pattern in SUPPRESSION_SPECS
    ]


def test_the_engine_prefilter_matches_the_expected_outcomes(
    rules: list[SuppressionRule],
) -> None:
    result = prefilter([candidate for candidate, _ in CANDIDATES], rules)

    assert {found.fingerprint for found in result.kept} == {
        candidate.fingerprint for candidate, suppressed in CANDIDATES if not suppressed
    }
    assert result.suppressed_count == sum(1 for _, suppressed in CANDIDATES if suppressed)


def test_ingest_and_the_engine_prefilter_reach_the_same_verdict(session: Session) -> None:
    """The same candidates, through the database path and the lease path.

    A divergence here means an engine dropping a match the API would have kept —
    a finding that silently never existed, with nothing anywhere to say so.
    """
    source = _source(session)
    for scope, pattern in SUPPRESSION_SPECS:
        session.add(
            Suppression(scope=scope, pattern=pattern, source_id=source.id, reason="fixture")
        )
    session.commit()

    # The API's view: what it would apply at ingest.
    live = suppressions.applicable_suppressions(session, source.id)
    server_verdict = {
        candidate.fingerprint: suppressions.first_match(
            live,
            fingerprint=candidate.fingerprint,
            rule_id=candidate.rule_id,
            resource_locator=candidate.resource_locator,
        )
        is not None
        for candidate, _ in CANDIDATES
    }

    # The engine's view: the same rules, serialised through a lease and back.
    leased = rules_from_lease([rule.as_payload() for rule in live])
    result = prefilter([candidate for candidate, _ in CANDIDATES], leased)
    engine_verdict = {
        candidate.fingerprint: candidate.fingerprint
        not in {found.fingerprint for found in result.kept}
        for candidate, _ in CANDIDATES
    }

    assert engine_verdict == server_verdict
    assert server_verdict == {
        candidate.fingerprint: suppressed for candidate, suppressed in CANDIDATES
    }


def test_a_lease_payload_round_trips(rules: list[SuppressionRule]) -> None:
    """The wire format is the only thing between the two call sites."""
    assert rules_from_lease([rule.as_payload() for rule in rules]) == rules


def test_ingest_applies_what_the_engine_could_not_have_known_about(session: Session) -> None:
    """A suppression created after the lease is still enforced at ingest.

    The engine's snapshot may only ever be *more* permissive than the API's:
    keeping something the API will drop costs one wasted payload, while dropping
    something the API would have kept loses a finding entirely.
    """
    source = _source(session)
    leased = rules_from_lease(
        [rule.as_payload() for rule in suppressions.applicable_suppressions(session, source.id)]
    )
    assert leased == []  # nothing to pre-filter with

    session.add(
        Suppression(
            scope=SuppressionScope.RULE,
            pattern="aws-access-key-id",
            source_id=source.id,
            reason="created mid-scan",
        )
    )
    session.commit()

    candidate = Candidate("a" * 64, "aws-access-key-id", {})
    assert prefilter([candidate], leased).kept == [candidate]  # engine reports it

    at_ingest = suppressions.applicable_suppressions(session, source.id)
    assert (
        suppressions.first_match(
            at_ingest,
            fingerprint=candidate.fingerprint,
            rule_id=candidate.rule_id,
            resource_locator=candidate.resource_locator,
        )
        is not None
    )  # ...and the API suppresses it anyway


def test_an_unusable_lease_entry_raises_rather_than_being_skipped() -> None:
    """A silently-ignored scope would make the engine quietly more aggressive than
    the API, which is the one direction that loses findings."""
    from iceberg_core.suppression import SuppressionPayloadError

    with pytest.raises(SuppressionPayloadError):
        rules_from_lease([{"id": str(uuid.uuid4()), "scope": "telepathy", "pattern": "x"}])


def test_no_rules_keeps_everything(rules: list[SuppressionRule]) -> None:
    candidates = [candidate for candidate, _ in CANDIDATES]

    assert prefilter(candidates, []).kept == candidates
