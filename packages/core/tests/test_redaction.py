"""Redaction: what may be revealed, and the guarantee that nothing else is."""

import string

import pytest
from iceberg_core.redaction import (
    MAX_SNIPPET_CHARS,
    RedactionError,
    RedactionPolicy,
    RedactionStrategy,
    Span,
    mask_secret,
    redact_snippet,
)

AWS_KEY = "AKIAsampleSAMPLEkey1"  # 20 chars, AWS-shaped but deliberately not a real id
# Assembled rather than written as a literal: a 40-character bearer-token-shaped
# constant is exactly what this project's own gitleaks job looks for, and a test
# fixture is not worth teaching the scanner to ignore.
LONG_TOKEN = "-".join(("tokn", "1234567890", string.ascii_lowercase[:24]))
KEEP_PREFIX = RedactionPolicy(strategy=RedactionStrategy.KEEP_PREFIX)
KEEP_SUFFIX = RedactionPolicy(strategy=RedactionStrategy.KEEP_SUFFIX)


def test_full_strategy_reveals_nothing() -> None:
    masked = mask_secret(AWS_KEY)

    assert AWS_KEY[0] not in masked.replace("chars redacted", "")
    assert masked == "[20 chars redacted]"


def test_keep_prefix_reveals_the_configured_prefix_only() -> None:
    masked = mask_secret(AWS_KEY, KEEP_PREFIX)

    assert masked == "AKIA…[16 chars redacted]"
    assert AWS_KEY not in masked


def test_keep_suffix_reveals_the_tail_only() -> None:
    masked = mask_secret(AWS_KEY, KEEP_SUFFIX)

    assert masked == "[16 chars redacted]…key1"


def test_short_secrets_reveal_nothing_even_under_keep_prefix() -> None:
    """Four characters of a short password is a quarter of the password."""
    assert mask_secret("hunter2", KEEP_PREFIX) == "[7 chars redacted]"
    assert mask_secret("Tr0ub4dor&3", KEEP_PREFIX) == "[11 chars redacted]"


def test_no_more_than_a_third_of_a_secret_is_ever_revealed() -> None:
    greedy = RedactionPolicy(
        strategy=RedactionStrategy.KEEP_PREFIX, keep=100, min_length_to_reveal=1
    )

    for length in range(2, 60):
        secret = "a" * length
        masked = mask_secret(secret, greedy)
        revealed = masked.split("…")[0] if "…" in masked else ""
        assert len(revealed) <= length // 3
        assert secret not in masked


def test_masking_is_stable_across_calls() -> None:
    assert mask_secret(LONG_TOKEN, KEEP_PREFIX) == mask_secret(LONG_TOKEN, KEEP_PREFIX)


def test_empty_secret_is_a_programming_error() -> None:
    with pytest.raises(ValueError, match="empty secret"):
        mask_secret("")


def test_snippet_keeps_context_and_masks_the_secret() -> None:
    text = f"Deploy notes: use aws_access_key_id = {AWS_KEY} for the staging account."
    span = Span(text.index(AWS_KEY), text.index(AWS_KEY) + len(AWS_KEY))

    snippet = redact_snippet(text, span, policy=KEEP_PREFIX)

    assert "aws_access_key_id" in snippet
    assert "staging account" in snippet
    assert "AKIA…[16 chars redacted]" in snippet
    assert AWS_KEY not in snippet


def test_snippet_context_is_bounded_and_marked_as_truncated() -> None:
    text = "x" * 500 + AWS_KEY + "y" * 500
    span = Span(500, 500 + len(AWS_KEY))

    snippet = redact_snippet(text, span, policy=RedactionPolicy(context_chars=10))

    assert snippet.startswith("…xxxxxxxxxx")
    assert snippet.endswith("yyyyyyyyyy…")


def test_snippet_masks_a_neighbouring_secret_in_the_same_window() -> None:
    text = f"api_key={AWS_KEY} backup_key={LONG_TOKEN}"
    target = Span(text.index(AWS_KEY), text.index(AWS_KEY) + len(AWS_KEY))
    neighbour = Span(text.index(LONG_TOKEN), text.index(LONG_TOKEN) + len(LONG_TOKEN))

    snippet = redact_snippet(text, target, policy=KEEP_PREFIX, other_spans=(neighbour,))

    assert AWS_KEY not in snippet
    assert LONG_TOKEN not in snippet
    assert "backup_key=" in snippet


def test_snippet_scrubs_an_unmatched_repeat_of_the_secret() -> None:
    """Only one copy was matched; the other must not ride along in the context."""
    text = f"prod: {AWS_KEY} (same as staging: {AWS_KEY})"
    first = Span(text.index(AWS_KEY), text.index(AWS_KEY) + len(AWS_KEY))

    snippet = redact_snippet(text, first, policy=KEEP_PREFIX)

    assert AWS_KEY not in snippet
    assert snippet.count("[16 chars redacted]") == 2


def test_snippet_is_a_single_line() -> None:
    text = f"config:\n  password:\n\t{LONG_TOKEN}\n\nother: value"
    span = Span(text.index(LONG_TOKEN), text.index(LONG_TOKEN) + len(LONG_TOKEN))

    snippet = redact_snippet(text, span)

    assert "\n" not in snippet
    assert "\t" not in snippet
    assert "password:" in snippet


def test_multiline_pem_block_is_masked_whole() -> None:
    body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ\nDbEXAMPLEKEY\n"
    pem = f"-----BEGIN RSA PRIVATE KEY-----\n{body}-----END RSA PRIVATE KEY-----"
    text = f"Attached key:\n{pem}\nRotate it."
    span = Span(text.index(pem), text.index(pem) + len(pem))

    snippet = redact_snippet(text, span)

    assert body.strip() not in snippet
    assert "Rotate it." in snippet


def test_snippet_never_exceeds_the_hard_ceiling() -> None:
    text = "context " * 200 + AWS_KEY
    span = Span(text.index(AWS_KEY), text.index(AWS_KEY) + len(AWS_KEY))

    snippet = redact_snippet(text, span, policy=RedactionPolicy(context_chars=10_000))

    assert len(snippet) <= MAX_SNIPPET_CHARS


def test_span_past_the_end_of_the_content_is_rejected() -> None:
    with pytest.raises(ValueError, match="past the end"):
        redact_snippet("short", Span(2, 99))


def test_invalid_spans_are_rejected() -> None:
    with pytest.raises(ValueError, match="invalid span"):
        Span(5, 5)
    with pytest.raises(ValueError, match="invalid span"):
        Span(-1, 3)


def test_strategy_names_come_from_rule_packs_and_typos_fail_loudly() -> None:
    assert (
        RedactionPolicy.from_strategy_name("keep_prefix").strategy is RedactionStrategy.KEEP_PREFIX
    )

    with pytest.raises(ValueError, match="unknown redaction strategy"):
        RedactionPolicy.from_strategy_name("keep_pefix")


def test_redaction_error_is_raised_rather_than_leaking(monkeypatch: pytest.MonkeyPatch) -> None:
    """If masking ever regressed, the engine must fail rather than transmit."""
    monkeypatch.setattr("iceberg_core.redaction.mask_secret", lambda secret, policy=None: secret)
    text = f"key={AWS_KEY}"

    with pytest.raises(RedactionError):
        redact_snippet(text, Span(4, 4 + len(AWS_KEY)))
