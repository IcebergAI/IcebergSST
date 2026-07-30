"""The three detection signals and the confidence they combine into (#42, ADR 0003).

Each signal is tested on its own before the formula that combines them, because
"why is this 0.85?" has to have an answer, and the answer is these functions.
"""

import pytest
from iceberg_detect.signals import (
    ENTROPY_WEIGHT,
    PROXIMITY_BONUS,
    PROXIMITY_PENALTY,
    Signals,
    confidence,
    keyword_near,
    shannon_entropy,
)


def test_entropy_is_zero_for_a_repeated_character() -> None:
    assert shannon_entropy("aaaaaaaa") == 0.0


def test_entropy_is_zero_for_empty_text() -> None:
    """Callers pass match text, which is never empty — but a crash here would be
    a poor way to find that out."""
    assert shannon_entropy("") == 0.0


def test_entropy_ranks_key_material_above_prose_above_repetition() -> None:
    """The ordering is the whole point; the absolute values are calibration."""
    repetitive = shannon_entropy("abababababababab")
    prose = shannon_entropy("the quick brown fox jumps over")
    key_material = shannon_entropy("8f3Kd0aQ2mVx7Lp9Zr4Ts6Yw1Bn5Cj0H")

    assert repetitive < prose < key_material


def test_entropy_is_measured_in_bits_per_character() -> None:
    """Four equally-likely characters is exactly two bits each."""
    assert shannon_entropy("abcd") == pytest.approx(2.0)


def test_a_keyword_is_found_within_the_window() -> None:
    text = "the api_key is 8f3Kd0aQ2mVx"
    start = text.index("8f3K")

    assert keyword_near(text, start, len(text), ("apikey", "api_key"), 64) == "api_key"


def test_a_keyword_outside_the_window_does_not_count() -> None:
    """The window is what makes proximity mean proximity."""
    text = "password" + " " * 200 + "8f3Kd0aQ2mVx"
    start = text.index("8f3K")

    assert keyword_near(text, start, len(text), ("password",), 64) is None


def test_a_keyword_matches_on_word_boundaries_not_substrings() -> None:
    """`key` should fire on `api_key` and not on `monkey`."""
    monkey = "the monkey ate 8f3Kd0aQ2mVx"
    api_key = "the api_key is 8f3Kd0aQ2mVx"

    assert keyword_near(monkey, monkey.index("8f3K"), len(monkey), ("key",), 64) is None
    assert keyword_near(api_key, api_key.index("8f3K"), len(api_key), ("key",), 64) == "key"


def test_keyword_search_is_case_insensitive() -> None:
    text = "SECRET: 8f3Kd0aQ2mVx"  # gitleaks:allow

    assert keyword_near(text, text.index("8f3K"), len(text), ("secret",), 64) == "secret"


def test_no_keywords_means_no_keyword_found() -> None:
    text = "8f3Kd0aQ2mVx"

    assert keyword_near(text, 0, len(text), (), 64) is None


def test_a_rule_with_no_signals_scores_its_base() -> None:
    """A pure-regex rule's confidence is the author's stated confidence in it."""
    score = confidence(
        base=0.8,
        signals=Signals(entropy=3.7, keyword_nearby=False),
        entropy_min=None,
        has_keywords=False,
    )

    assert score == pytest.approx(0.8)


def test_clearing_the_entropy_gate_by_more_scores_higher() -> None:
    barely = confidence(
        base=0.5,
        signals=Signals(entropy=4.05, keyword_nearby=False),
        entropy_min=4.0,
        has_keywords=False,
    )
    comfortably = confidence(
        base=0.5,
        signals=Signals(entropy=5.8, keyword_nearby=False),
        entropy_min=4.0,
        has_keywords=False,
    )

    assert barely < comfortably
    # The bonus is capped, so a wildly random string cannot swamp the base.
    assert comfortably == pytest.approx(0.5 + ENTROPY_WEIGHT)


def test_a_nearby_keyword_raises_and_its_absence_lowers() -> None:
    with_keyword = confidence(
        base=0.5,
        signals=Signals(entropy=0.0, keyword_nearby=True),
        entropy_min=None,
        has_keywords=True,
    )
    without = confidence(
        base=0.5,
        signals=Signals(entropy=0.0, keyword_nearby=False),
        entropy_min=None,
        has_keywords=True,
    )

    assert with_keyword == pytest.approx(0.5 + PROXIMITY_BONUS)
    assert without == pytest.approx(0.5 - PROXIMITY_PENALTY)


def test_the_absence_penalty_is_gentler_than_the_presence_bonus() -> None:
    """Prose near a secret is strong evidence; its absence is weak — secrets live
    in config blocks with no prose anywhere near them."""
    assert PROXIMITY_PENALTY < PROXIMITY_BONUS


def test_a_rule_without_keywords_is_not_penalised_for_having_none() -> None:
    score = confidence(
        base=0.6,
        signals=Signals(entropy=0.0, keyword_nearby=False),
        entropy_min=None,
        has_keywords=False,
    )

    assert score == pytest.approx(0.6)


@pytest.mark.parametrize(("base", "keyword_nearby"), [(1.0, True), (0.0, False)])
def test_confidence_stays_within_the_unit_interval(base: float, keyword_nearby: bool) -> None:
    """It is a score an analyst filters on, so it has to mean the same thing every
    time — a rule with a high base and every signal firing must not exceed 1."""
    score = confidence(
        base=base,
        signals=Signals(entropy=9.0, keyword_nearby=keyword_nearby),
        entropy_min=1.0,
        has_keywords=True,
    )

    assert 0.0 <= score <= 1.0
