"""The detection loop over a content unit (#42, ADR 0003/0004).

Uses small inline packs rather than the shipped one: these tests are about the
loop — gates, threshold, overlap, redaction — and a rule change should not be able
to break them. The shipped pack has its own tests in `test_seed_rulepack.py`.
"""

import textwrap

import pytest
from iceberg_core.redaction import Span
from iceberg_detect.engine import detect
from iceberg_detect.rules import RulePack, load_pack

TOKEN_PACK = load_pack(
    textwrap.dedent("""
        version: "test.1"
        rules:
          - id: test-token
            description: A test token
            severity: high
            regex: 'TKN[0-9A-Z]{16}'
            redaction: keep_prefix
            base_confidence: 0.8
    """)
)

GATED_PACK = load_pack(
    textwrap.dedent("""
        version: "test.2"
        rules:
          - id: gated-token
            description: Needs entropy and a keyword
            severity: medium
            regex: '\\b[A-Za-z0-9]{16,64}\\b'
            entropy_min: 3.5
            keywords: [secret, token]
            requires_keyword: true
            base_confidence: 0.5
    """)
)


def test_a_match_is_reported_with_its_rule_severity_and_version() -> None:
    result = detect("here is TKN0123456789ABCDEF in a page", TOKEN_PACK)

    assert len(result.secrets) == 1
    found = result.secrets[0]
    assert found.rule_id == "test-token"
    assert found.severity == "high"
    assert found.secret == "TKN0123456789ABCDEF"  # gitleaks:allow
    assert found.span == Span(8, 27)


def test_the_snippet_is_redacted_and_the_plaintext_is_not_in_it() -> None:
    """Redaction happens here, before anything can transmit or log the match."""
    result = detect("here is TKN0123456789ABCDEF in a page", TOKEN_PACK)

    snippet = result.secrets[0].redacted_snippet
    assert "TKN0123456789ABCDEF" not in snippet
    assert snippet.startswith("here is TKN")  # keep_prefix, and the context survives
    assert "in a page" in snippet


def test_every_match_in_a_unit_is_masked_in_every_snippet() -> None:
    """A snippet that hides its own secret and prints the neighbouring one in full
    would be a leak by a different route (ADR 0004)."""
    text = "first TKN0123456789ABCDEF then TKNZZZZZZZZZZZZZZZZ"

    result = detect(text, TOKEN_PACK)

    assert len(result.secrets) == 2
    for found in result.secrets:
        assert "TKN0123456789ABCDEF" not in found.redacted_snippet
        assert "TKNZZZZZZZZZZZZZZZZ" not in found.redacted_snippet


def test_a_gate_dropped_match_is_still_masked_in_a_neighbours_snippet() -> None:
    """A candidate that lost its own rule's keyword gate is still secret material;
    it must not survive unmasked in the context window of a reported finding
    (ADR 0004)."""
    pack = load_pack(
        textwrap.dedent("""
            version: "test.gate-leak"
            rules:
              - id: aws-key
                description: AWS access key id
                severity: high
                regex: 'AKIA[0-9A-Z]{16}'
                redaction: keep_prefix
              - id: generic-entropy
                description: Generic high-entropy, keyword-gated
                severity: medium
                regex: '[A-Za-z0-9+/]{24,}'
                entropy_min: 4.2
                keywords: [secret, token]
                requires_keyword: true
        """)
    )
    high_entropy = "8f3Kd0aQ2mVx7Lp9Zr4Ts6Yw1Bn5Cj0H"
    text = f"noise {high_entropy} and also AKIAIOSFODNN7EXAMPLE here"

    result = detect(text, pack)

    assert [found.rule_id for found in result.secrets] == ["aws-key"]
    assert result.dropped_no_keyword == 1
    assert high_entropy not in result.secrets[0].redacted_snippet


def test_a_match_past_the_report_cap_is_still_masked_in_a_neighbours_snippet() -> None:
    """The max_matches cap bounds what is *reported*, never what is *masked*: a
    secret found after the cap must not ride along as context in a reported one."""
    text = "TKN0123456789ABCDEF and TKNFFFFFFFFFFFFFFFF"

    result = detect(text, TOKEN_PACK, max_matches=1)

    assert result.truncated
    assert len(result.secrets) == 1
    assert "TKN0123456789ABCDEF" not in result.secrets[0].redacted_snippet
    assert "TKNFFFFFFFFFFFFFFFF" not in result.secrets[0].redacted_snippet


def test_a_detected_secret_never_reprs_its_plaintext() -> None:
    result = detect("here is TKN0123456789ABCDEF", TOKEN_PACK)

    assert result.secrets
    assert "TKN0123456789ABCDEF" not in repr(result.secrets[0])
    assert "TKN0123456789ABCDEF" not in repr(result)


def test_a_candidate_below_the_entropy_gate_is_dropped_and_counted() -> None:
    result = detect("secret aaaaaaaaaaaaaaaaaa here", GATED_PACK)

    assert result.secrets == []
    assert result.dropped_low_entropy == 1


def test_a_candidate_with_no_nearby_keyword_is_dropped_when_the_rule_requires_one() -> None:
    """Without this the generic rule reports every git sha in the corpus."""
    result = detect("the commit 8f3Kd0aQ2mVx7Lp9Zr4T landed", GATED_PACK)

    assert result.secrets == []
    assert result.dropped_no_keyword == 1


def test_the_same_candidate_with_a_keyword_is_reported() -> None:
    result = detect("the secret is 8f3Kd0aQ2mVx7Lp9Zr4T", GATED_PACK)

    assert [found.rule_id for found in result.secrets] == ["gated-token"]
    assert result.secrets[0].keyword == "secret"


def test_matches_below_the_threshold_are_dropped_and_counted() -> None:
    result = detect("here is TKN0123456789ABCDEF", TOKEN_PACK, threshold=0.9)

    assert result.secrets == []
    assert result.dropped_below_threshold == 1


def test_overlapping_matches_collapse_to_the_strongest() -> None:
    """Two rules matching overlapping text found the same secret. Reporting both
    puts one credential in the queue twice under two rule ids."""
    pack = load_pack(
        textwrap.dedent("""
            version: "test.3"
            rules:
              - id: specific-token
                description: The specific rule
                severity: critical
                regex: 'TKN[0-9A-Z]{16}'
                base_confidence: 0.9
              - id: generic-blob
                description: The generic catch-all
                severity: low
                regex: '\\b[A-Z0-9]{10,30}\\b'
                base_confidence: 0.6
        """)
    )

    result = detect("here is TKN0123456789ABCDEF", pack)

    assert [found.rule_id for found in result.secrets] == ["specific-token"]
    assert result.dropped_overlapping == 1


def test_a_collapsed_duplicate_is_still_masked_in_the_surviving_snippet() -> None:
    """Losing the overlap contest does not make a match less secret."""
    pack = load_pack(
        textwrap.dedent("""
            version: "test.4"
            rules:
              - id: narrow
                description: Narrow
                severity: high
                regex: 'TKN[0-9A-Z]{16}'
                base_confidence: 0.9
              - id: wide
                description: Wider, overlapping
                severity: low
                regex: 'TKN[0-9A-Z]{16}=='
                base_confidence: 0.6
        """)
    )

    result = detect("value TKN0123456789ABCDEF== end", pack)

    assert [found.rule_id for found in result.secrets] == ["narrow"]
    assert result.dropped_overlapping == 1
    snippet = result.secrets[0].redacted_snippet
    assert "TKN0123456789ABCDEF" not in snippet
    # The wider match reached past the narrow one; the part outside it is masked
    # too, or the trailing characters of a secret would ride along as context.
    assert "==" not in snippet


def test_distinct_secrets_are_both_reported() -> None:
    """Only *overlapping* matches collapse — two secrets on one page are two findings."""
    text = "first TKN0123456789ABCDEF and second TKNZZZZZZZZZZZZZZZZ"

    result = detect(text, TOKEN_PACK)

    assert len(result.secrets) == 2
    assert result.dropped_overlapping == 0


def test_findings_come_back_in_document_order() -> None:
    text = "one TKNAAAAAAAAAAAAAAAA two TKNBBBBBBBBBBBBBBBB three TKNCCCCCCCCCCCCCCCC"

    result = detect(text, TOKEN_PACK)

    starts = [found.span.start for found in result.secrets]
    assert starts == sorted(starts)


def test_a_named_secret_group_reports_only_the_secret() -> None:
    """A rule needing context to match must not report the context: the fingerprint
    would change when the spacing did."""
    pack = load_pack(
        textwrap.dedent("""
            version: "test.5"
            rules:
              - id: assigned-token
                description: Token in an assignment
                severity: high
                regex: 'token\\s*=\\s*(?P<secret>[A-Za-z0-9]{12,})'
                base_confidence: 0.8
        """)
    )

    result = detect("token   =   abcDEF123456xyz", pack)  # gitleaks:allow

    assert result.secrets[0].secret == "abcDEF123456xyz"  # gitleaks:allow
    assert "token" in result.secrets[0].redacted_snippet


def test_a_pathological_unit_is_truncated_rather_than_unbounded() -> None:
    """A generated key file is not a page anyone will triage, and one submission
    should not carry ten thousand findings."""
    text = " ".join(f"TKN{index:016X}" for index in range(50))

    result = detect(text, TOKEN_PACK, max_matches=10)

    assert result.truncated is True
    assert len(result.secrets) == 10


def test_an_empty_unit_finds_nothing() -> None:
    result = detect("", TOKEN_PACK)

    assert result.secrets == []
    assert result.truncated is False


def test_text_with_no_secrets_finds_nothing() -> None:
    result = detect("The quick brown fox jumps over the lazy dog.", TOKEN_PACK)

    assert result.secrets == []


@pytest.mark.parametrize("pack", [TOKEN_PACK, GATED_PACK])
def test_no_reported_finding_ever_contains_its_own_plaintext(pack: RulePack) -> None:
    """The invariant ADR 0004 exists for, asserted over both packs."""
    text = "secret TKN0123456789ABCDEF and secret 8f3Kd0aQ2mVx7Lp9Zr4T"

    for found in detect(text, pack).secrets:
        assert found.secret not in found.redacted_snippet


def test_the_default_threshold_matches_the_api_setting() -> None:
    """Two defaults that drift would have the engine and the API silently
    disagreeing about what counts as noise.

    The constant cannot simply live in one place: `iceberg_core.config` cannot
    import this package, which depends on core. So it is duplicated and kept in
    step here, where the dependency runs the right way.
    """
    from iceberg_core.config import ApiSettings
    from iceberg_detect import DEFAULT_CONFIDENCE_THRESHOLD

    assert ApiSettings.model_fields["confidence_threshold"].default == (
        DEFAULT_CONFIDENCE_THRESHOLD
    )
