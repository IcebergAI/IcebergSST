"""The three detection signals and how they become one confidence score (ADR 0003).

Regex says *what shape* a candidate has. Entropy says *how random* it looks.
Proximity says *what the surrounding prose calls it*. None of them is sufficient
alone — a 40-character hex string is a secret, a git sha, or a checksum, and only
the words around it tell you which — so the engine combines them into a single
number an analyst can filter on.

The formula is deliberately additive and shallow:

    confidence = clip(base + entropy_bonus + proximity_adjustment, 0, 1)

A learned model would score better and explain worse. "Why is this 0.85?" has to
have an answer an analyst can act on, because the answer is what tells them
whether to tune the rule or fix the secret, and every term below is one sentence.
"""

import math
import re
from dataclasses import dataclass

#: What clearing the entropy gate is worth, and how much headroom earns all of it.
#: A rule that gates at 3.0 gives full marks at 4.5 — roughly the difference
#: between a lowercase English word and a base64 key.
ENTROPY_WEIGHT = 0.2
ENTROPY_HEADROOM = 1.5

#: A nearby keyword raises confidence; its absence lowers it, but only for rules
#: that asked for keywords at all. The penalty is smaller than the bonus: prose
#: near a secret is a strong positive signal, while its absence is weak evidence —
#: secrets appear in config blocks with no prose anywhere near them.
PROXIMITY_BONUS = 0.15
PROXIMITY_PENALTY = 0.1

_WORD_BOUNDARY_CACHE: dict[str, re.Pattern[str]] = {}


@dataclass(frozen=True, slots=True)
class Signals:
    """What the three detectors said about one candidate.

    Carried onto the finding so a confidence score can be explained after the
    fact, rather than being a number with no derivation.
    """

    entropy: float
    keyword_nearby: bool
    #: The keyword that fired, for the log line and for rule tuning.
    keyword: str | None = None


def shannon_entropy(text: str) -> float:
    """Shannon entropy of ``text`` in bits per character.

    Zero for a single repeated character, ~4 for lowercase English, ~5-6 for
    base64 key material. Computed over the string's own alphabet rather than a
    fixed one, which is what makes it comparable across charsets.
    """
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def keyword_near(
    text: str,
    start: int,
    end: int,
    keywords: tuple[str, ...],
    window: int,
) -> str | None:
    """The first keyword appearing within ``window`` characters of the match.

    Matched on word boundaries: ``key`` should fire on ``api_key =`` and not on
    ``monkey``, and a rule author writing "key" means the word, not the substring.
    Underscores count as boundaries here even though ``\\b`` disagrees — ``api_key``
    is one identifier to Python and two words to a human reading the page.
    """
    if not keywords:
        return None
    lo = max(0, start - window)
    hi = min(len(text), end + window)
    # Slice a little wider than the window — by the longest keyword — so the
    # boundary lookarounds see the real neighbouring characters. Slicing exactly
    # to the window would fabricate a word boundary at the cut, matching `auth`
    # inside a clipped `oauth` (a false positive that can flip a requires_keyword
    # gate) or missing a keyword the edge runs through.
    pad = max(len(keyword) for keyword in keywords)
    offset = max(0, lo - pad)
    haystack = text[offset : min(len(text), hi + pad)].lower()
    window_lo, window_hi = lo - offset, hi - offset
    for keyword in keywords:
        for match in _boundary_pattern(keyword).finditer(haystack):
            # Only count a keyword that actually falls within the window; padding
            # exists to give the boundary real context, not to widen the reach.
            if match.start() < window_hi and match.end() > window_lo:
                return keyword
    return None


def confidence(
    *,
    base: float,
    signals: Signals,
    entropy_min: float | None,
    has_keywords: bool,
) -> float:
    """Combine the signals into a score in ``[0, 1]``.

    ``entropy_min`` is the rule's gate, not a threshold applied here: a candidate
    that failed it never reaches this function. What the gate does here is scale
    the bonus, so a value that barely scraped through scores below one well clear
    of it.
    """
    score = base

    if entropy_min is not None:
        headroom = max(0.0, signals.entropy - entropy_min)
        score += ENTROPY_WEIGHT * min(1.0, headroom / ENTROPY_HEADROOM)

    if has_keywords:
        score += PROXIMITY_BONUS if signals.keyword_nearby else -PROXIMITY_PENALTY

    return min(1.0, max(0.0, score))


def _boundary_pattern(keyword: str) -> re.Pattern[str]:
    pattern = _WORD_BOUNDARY_CACHE.get(keyword)
    if pattern is None:
        escaped = re.escape(keyword)
        pattern = re.compile(rf"(?<![a-z0-9]){escaped}(?![a-z0-9])")
        _WORD_BOUNDARY_CACHE[keyword] = pattern
    return pattern
