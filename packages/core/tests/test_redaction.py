"""Issue #25 acceptance: never returns plaintext; per-rule strategies; unit-tested."""

import pytest
from iceberg_core.redaction import RedactionStrategy, mask_secret, redact_snippet

# Obviously fake, low-entropy: keeps the repo's own gitleaks scan quiet.
FAKE_SECRET = "AKIAFAKEFAKEFAKEFAKE"  # noqa: S105  # fake AWS-shaped id, not a credential
TEXT = f"config follows\naws_secret_access_key = {FAKE_SECRET}\nregion = eu-west-2"
START = TEXT.index(FAKE_SECRET)
END = START + len(FAKE_SECRET)


@pytest.mark.parametrize("strategy", list(RedactionStrategy))
def test_no_strategy_ever_returns_the_plaintext(strategy: RedactionStrategy) -> None:
    """The core ADR 0004 guarantee, asserted across every strategy."""
    assert FAKE_SECRET not in mask_secret(FAKE_SECRET, strategy)
    assert FAKE_SECRET not in redact_snippet(TEXT, START, END, strategy=strategy)


def test_full_strategy_reveals_nothing_but_length() -> None:
    masked = mask_secret(FAKE_SECRET, RedactionStrategy.FULL)
    assert masked == "••••••••(20 chars)"


def test_keep_prefix_keeps_only_the_leading_characters() -> None:
    """`keep_prefix` is what makes an AWS key recognisable during triage."""
    assert mask_secret(FAKE_SECRET, RedactionStrategy.KEEP_PREFIX) == "AKIA••••••••(20 chars)"


def test_keep_last_keeps_only_the_trailing_characters() -> None:
    assert mask_secret(FAKE_SECRET, RedactionStrategy.KEEP_LAST) == "••••••••FAKE(20 chars)"


@pytest.mark.parametrize("strategy", [RedactionStrategy.KEEP_PREFIX, RedactionStrategy.KEEP_LAST])
def test_short_secrets_fall_back_to_full_masking(strategy: RedactionStrategy) -> None:
    """A 3-char secret must not be 100% disclosed by a keep-4 strategy."""
    assert mask_secret("abc", strategy) == "••••••••(3 chars)"


def test_unknown_strategy_fails_closed() -> None:
    """A rule that forgets to declare a strategy must not leak."""
    assert mask_secret(FAKE_SECRET, "not-a-strategy") == "••••••••(20 chars)"  # type: ignore[arg-type]  # deliberately invalid


def test_snippet_keeps_surrounding_context_for_triage() -> None:
    snippet = redact_snippet(TEXT, START, END, strategy=RedactionStrategy.KEEP_PREFIX)
    assert "aws_secret_access_key =" in snippet
    assert "region = eu-west-2" in snippet
    assert "AKIA••••••••(20 chars)" in snippet


def test_snippet_is_single_line() -> None:
    """Findings render in a table; embedded newlines break the row."""
    assert "\n" not in redact_snippet(TEXT, START, END)


def test_context_window_is_bounded_and_elided() -> None:
    text = "x" * 200 + FAKE_SECRET + "y" * 200
    snippet = redact_snippet(text, 200, 200 + len(FAKE_SECRET), context_chars=10)
    assert snippet == "…xxxxxxxxxx••••••••(20 chars)yyyyyyyyyy…"


def test_zero_context_returns_only_the_mask() -> None:
    """Ellipses still flag that surrounding content exists but was elided."""
    assert redact_snippet(TEXT, START, END, context_chars=0) == "…••••••••(20 chars)…"


@pytest.mark.parametrize(
    "start,end",
    [(-1, 5), (5, 5), (10, 5), (0, len(TEXT) + 1)],
)
def test_invalid_spans_raise_rather_than_returning_raw_text(start: int, end: int) -> None:
    """Junk offsets must fail loudly, never fall through to unmasked output."""
    with pytest.raises(ValueError, match="invalid match span"):
        redact_snippet(TEXT, start, end)


def test_negative_context_is_rejected() -> None:
    with pytest.raises(ValueError, match="context_chars"):
        redact_snippet(TEXT, START, END, context_chars=-1)
