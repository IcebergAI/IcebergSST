"""A fake connector drives the pipeline end to end (#45).

The acceptance criterion for the connector protocol, and the first test that runs
the engine's whole chain in one place: connector → detect → fingerprint → redact →
suppression pre-filter → the payload the API ingests.

It lives in the root suite because it is the only test that spans every package at
once, and because that is exactly where the seams are. Each piece has its own
tests; what nothing else covers is whether the shapes actually fit together — that
a `ContentUnit`'s locator is what `fingerprint` wants, that a `DetectedSecret`
carries what `FindingPayload` requires, that the pre-filter recognises a locator a
connector produced.

The worker that will run this loop for real is #11. This asserts the parts compose
before that lands, so #11 is wiring rather than discovery.
"""

import uuid
from dataclasses import dataclass
from typing import Any

import pytest
from iceberg_api.engines.schemas import FindingPayload
from iceberg_connectors import ContentOrigin, ContentUnit, FakeConnector, FakePage, FetchOutcome
from iceberg_core.enums import SuppressionScope
from iceberg_core.fingerprint import fingerprint, secret_hash
from iceberg_core.suppression import SuppressionRule
from iceberg_detect import detect, load_named_pack
from iceberg_engine.suppression import prefilter

PACK = load_named_pack()
PEPPER = b"0123456789abcdef0123456789abcdef"

#: A page with a credential in it, and one without. The secret is AWS's own
#: documented example key — it has never authenticated anything.
LEAKY_PAGE = "Deployment notes: set aws access key AKIAIOSFODNN7EXAMPLE in the runbook."
CLEAN_PAGE = "The fix landed in commit 3f2b1c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b on main."


@dataclass(frozen=True, slots=True)
class Candidate:
    """A detected secret, fingerprinted — what the worker holds before submitting."""

    fingerprint: str
    rule_id: str
    resource_locator: dict[str, Any]
    payload: FindingPayload
    #: Kept only so the test can assert it never reaches the payload.
    plaintext: str


def _scan(unit: ContentUnit, *, threshold: float = 0.5) -> list[Candidate]:
    """The engine's per-unit loop: detect, fingerprint, build the payload.

    This is the sequence #11 will run. Written out rather than imported because
    the module that owns it does not exist yet; when it does, this test becomes
    its contract.
    """
    result = detect(unit.text, PACK, threshold=threshold)
    candidates: list[Candidate] = []

    for found in result.secrets:
        hashed = secret_hash(found.secret, pepper=PEPPER)
        identity = fingerprint(
            locator=unit.locator, rule_id=found.rule_id, secret_hash=hashed, pepper=PEPPER
        )
        locator = unit.resource_locator() | {"line_offset": found.span.start}
        candidates.append(
            Candidate(
                fingerprint=identity,
                rule_id=found.rule_id,
                resource_locator=locator,
                plaintext=found.secret,
                payload=FindingPayload(
                    fingerprint=identity,
                    rule_id=found.rule_id,
                    rulepack_version=PACK.version,
                    resource_locator=locator,
                    redacted_snippet=found.redacted_snippet,
                    secret_hash=hashed,
                    entropy=found.entropy,
                    confidence=found.confidence,
                    severity=found.severity,  # type: ignore[arg-type]  # StrEnum value
                ),
            )
        )
    return candidates


@pytest.fixture(name="source")
def source_fixture() -> FakeConnector:
    return FakeConnector(
        spaces={
            "DOCS": [
                FakePage("page-1", LEAKY_PAGE, display={"url": "https://wiki.test/page/1"}),
                FakePage("page-2", CLEAN_PAGE),
                FakePage(
                    "page-3",
                    LEAKY_PAGE,
                    origin=ContentOrigin.ATTACHMENT,
                    sub_resource="runbook.txt",
                ),
                FakePage("page-4", "", skip=True),
            ]
        }
    )


def _fetch_all(source: FakeConnector) -> tuple[list[ContentUnit], FetchOutcome]:
    outcome = FetchOutcome()
    units: list[ContentUnit] = []
    for spec in source.discover({}, None):
        units.extend(source.fetch({}, spec, None, outcome))
    return units, outcome


def test_a_secret_in_a_fake_source_reaches_a_valid_finding_payload(
    source: FakeConnector,
) -> None:
    """The end-to-end path, and the shape assertion that matters: what detection
    produces validates as what the API's ingest route accepts."""
    units, outcome = _fetch_all(source)
    candidates = [candidate for unit in units for candidate in _scan(unit)]

    assert outcome.as_counts() == {"units": 3, "units_skipped": 1, "units_failed": 0}
    assert [candidate.rule_id for candidate in candidates] == [
        "aws-access-key-id",
        "aws-access-key-id",
    ]
    payload = candidates[0].payload
    assert payload.rulepack_version == PACK.version
    assert payload.resource_locator["url"] == "https://wiki.test/page/1"
    assert payload.severity.value == "high"


def test_no_plaintext_survives_into_the_payload(source: FakeConnector) -> None:
    """ADR 0004, asserted over the real chain rather than a unit of it: the
    payload type has no field for a secret, and the snippet must not smuggle one."""
    units, _ = _fetch_all(source)

    for candidate in (c for unit in units for c in _scan(unit)):
        serialised = candidate.payload.model_dump_json()
        assert candidate.plaintext not in serialised
        assert "AKIAIOSFODNN7EXAMPLE" not in serialised


def test_the_same_secret_in_two_resources_gets_two_fingerprints(
    source: FakeConnector,
) -> None:
    """Identical text on a page and in its attachment is two findings — an analyst
    has to fix both, so they cannot collapse into one."""
    units, _ = _fetch_all(source)
    candidates = [candidate for unit in units for candidate in _scan(unit)]

    assert candidates[0].fingerprint != candidates[1].fingerprint
    assert candidates[0].payload.secret_hash == candidates[1].payload.secret_hash


def test_a_rescan_of_unchanged_content_produces_identical_fingerprints(
    source: FakeConnector,
) -> None:
    """The property triage survival rests on (ADR 0006). Fingerprints are computed
    from the coarse locator, so a second scan of the same source must reproduce
    them exactly — otherwise every re-scan orphans the previous decisions."""
    first = [c.fingerprint for unit in _fetch_all(source)[0] for c in _scan(unit)]
    second = [c.fingerprint for unit in _fetch_all(source)[0] for c in _scan(unit)]

    assert first == second


def test_a_moved_line_does_not_change_the_fingerprint() -> None:
    """Offsets are display metadata. Editing a paragraph above a secret must not
    produce a "new" finding and auto-resolve the old one."""
    from iceberg_core.fingerprint import CoarseLocator

    locator = CoarseLocator("fake", "page-1")
    original = ContentUnit(locator=locator, text=LEAKY_PAGE)
    edited = ContentUnit(locator=locator, text="A new opening paragraph.\n\n" + LEAKY_PAGE)

    assert _scan(original)[0].fingerprint == _scan(edited)[0].fingerprint
    # ...while the display offset does move, which is the point of keeping it out.
    assert (
        _scan(original)[0].resource_locator["line_offset"]
        != _scan(edited)[0].resource_locator["line_offset"]
    )


def test_the_engine_prefilter_recognises_a_locator_a_connector_produced(
    source: FakeConnector,
) -> None:
    """A path glob is matched against the locator blob, so the keys a connector
    populates decide whether analysts can write one at all."""
    units, _ = _fetch_all(source)
    candidates = [candidate for unit in units for candidate in _scan(unit)]
    by_space = SuppressionRule(
        id=uuid.uuid4(), scope=SuppressionScope.PATH_GLOB, pattern="https://wiki.test/page/*"
    )

    result = prefilter(candidates, [by_space])

    assert result.suppressed_count == 1
    assert [candidate.resource_locator["resource_id"] for candidate in result.kept] == ["page-3"]


def test_a_fingerprint_suppression_matches_what_the_pipeline_computed(
    source: FakeConnector,
) -> None:
    """The other half of the seam: the fingerprint an analyst suppresses is the
    one this chain produces, byte for byte."""
    units, _ = _fetch_all(source)
    candidates = [candidate for unit in units for candidate in _scan(unit)]
    exact = SuppressionRule(
        id=uuid.uuid4(),
        scope=SuppressionScope.FINGERPRINT,
        pattern=candidates[0].fingerprint,
    )

    result = prefilter(candidates, [exact])

    assert result.suppressed_count == 1
    assert result.kept[0].fingerprint == candidates[1].fingerprint


def test_a_clean_source_produces_nothing(source: FakeConnector) -> None:
    """The common case, and the one an empty findings list has to be trusted for."""
    clean = FakeConnector(spaces={"DOCS": [FakePage("page-1", CLEAN_PAGE)]})
    units, outcome = _fetch_all(clean)

    assert [c for unit in units for c in _scan(unit)] == []
    assert outcome.units == 1  # it did look
