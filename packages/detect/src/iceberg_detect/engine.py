"""Running a rule pack over a content unit (ADR 0003, 0004).

This is the whole detection loop: every rule's regex over the text, each candidate
gated on entropy and proximity, survivors scored and redacted. What comes out is
:class:`DetectedSecret` — a masked snippet and the plaintext, kept apart on
purpose, because the caller needs the plaintext exactly twice (to hash it and to
throw it away) and never after.

Two properties this module owns:

* **Nothing leaves without a redacted snippet.** Redaction happens here, with
  every other match in the unit passed as a neighbour, so a snippet cannot print
  the secret next door while masking its own (ADR 0004).
* **The confidence threshold is applied here and again at ingest.** An engine
  running an older threshold cannot flood the queue, and the API cannot silently
  keep something the engine already decided was noise (#70).
"""

import re
from collections.abc import Iterator
from dataclasses import dataclass, field

import structlog
from iceberg_core.redaction import RedactionError, Span, redact_snippet

from iceberg_detect.rules import Rule, RulePack
from iceberg_detect.signals import Signals, confidence, keyword_near, shannon_entropy

logger = structlog.get_logger()

#: Below this, a match is noise by default. Overridable per scan (#70); the same
#: value is applied at ingest so the two roles cannot disagree.
DEFAULT_CONFIDENCE_THRESHOLD = 0.5

#: A single content unit yielding more than this is a pathological input — a
#: generated key file, a base64 blob — not a page an analyst will triage. Cutting
#: it off bounds both the work and the size of one results submission.
MAX_MATCHES_PER_UNIT = 500


@dataclass(frozen=True, slots=True)
class DetectedSecret:
    """One match, redacted and scored.

    ``secret`` is the plaintext. It exists so the caller can hash it
    (:mod:`iceberg_core.fingerprint`) and must not be logged, stored, or put in a
    payload — :class:`~iceberg_api.engines.schemas.FindingPayload` has no field
    for it, which is the structural half of that guarantee.
    """

    rule_id: str
    severity: str
    span: Span
    #: The plaintext, kept out of every repr so a stray ``repr(result)`` in a log
    #: line or a test diff cannot print it.
    secret: str = field(repr=False)
    redacted_snippet: str
    entropy: float
    confidence: float
    keyword: str | None = None


@dataclass(slots=True)
class DetectionResult:
    """What one content unit produced, plus the tallies the scan counts on."""

    secrets: list[DetectedSecret] = field(default_factory=list)
    #: Candidates that matched a regex but lost a gate — the number that says
    #: whether a rule is too loose before anyone looks at the queue.
    dropped_below_threshold: int = 0
    dropped_no_keyword: int = 0
    dropped_low_entropy: int = 0
    #: Matches collapsed into a stronger, overlapping one — the same secret found
    #: by more than one rule.
    dropped_overlapping: int = 0
    truncated: bool = False


@dataclass(frozen=True, slots=True)
class _Candidate:
    rule: Rule
    span: Span
    text: str = field(repr=False)
    signals: Signals = field(repr=False)
    score: float


def detect(
    text: str,
    pack: RulePack,
    *,
    threshold: float = DEFAULT_CONFIDENCE_THRESHOLD,
    max_matches: int = MAX_MATCHES_PER_UNIT,
) -> DetectionResult:
    """Run every rule in ``pack`` over ``text``.

    Redaction is a second pass on purpose. A snippet has to mask every secret in
    its window, including ones found by other rules, so the full match set has to
    exist before the first snippet can be built.
    """
    result = DetectionResult()
    found: list[_Candidate] = []

    for candidate in _candidates(text, pack, result):
        if len(found) >= max_matches:
            result.truncated = True
            logger.warning(
                "detection_truncated",
                rulepack_version=pack.version,
                max_matches=max_matches,
                reason="content unit produced more matches than one finding set should carry",
            )
            break
        found.append(candidate)

    above = [candidate for candidate in found if candidate.score >= threshold]
    result.dropped_below_threshold = len(found) - len(above)

    reportable = _strongest_of_each_overlap(above)
    result.dropped_overlapping = len(above) - len(reportable)

    # Neighbours are every regex match in the unit — not just the reported ones,
    # and not just the ones that survived gating or the max_matches cap. A match
    # that lost its rule's entropy/keyword gate, was collapsed as a duplicate, or
    # fell past the cap is still secret material, and it must not survive in
    # someone else's context window (ADR 0004). Reporting is capped; masking is not.
    all_spans = _match_spans(text, pack)
    for candidate in reportable:
        neighbours = tuple(span for span in all_spans if span != candidate.span)
        try:
            snippet = redact_snippet(
                text, candidate.span, policy=candidate.rule.redaction, other_spans=neighbours
            )
        except RedactionError, ValueError:
            # Redaction failing is a bug in the masking logic, and the only safe
            # response is to drop the finding: a raw snippet must never be the
            # fallback (ADR 0004).
            logger.exception(
                "redaction_failed",
                rule_id=candidate.rule.id,
                rulepack_version=pack.version,
            )
            continue
        result.secrets.append(
            DetectedSecret(
                rule_id=candidate.rule.id,
                severity=candidate.rule.severity.value,
                span=candidate.span,
                secret=candidate.text,
                redacted_snippet=snippet,
                entropy=candidate.signals.entropy,
                confidence=candidate.score,
                keyword=candidate.signals.keyword,
            )
        )

    return result


def _strongest_of_each_overlap(candidates: list[_Candidate]) -> list[_Candidate]:
    """Collapse overlapping matches to the strongest one.

    Two rules matching overlapping text have found the *same* secret — distinct
    secrets cannot occupy the same characters. Reporting both would put one
    credential in the queue twice under two rule ids, and the analyst who triages
    the first has no way to know the second is the same thing.

    "Strongest" is highest confidence, then longest span, then earliest in the
    pack: a specific vendor rule beats the generic entropy catch-all, which is the
    case this exists for.
    """
    ranked = sorted(
        candidates,
        key=lambda c: (-c.score, -(c.span.end - c.span.start), c.span.start),
    )
    kept: list[_Candidate] = []
    for candidate in ranked:
        if any(candidate.span.overlaps(other.span) for other in kept):
            continue
        kept.append(candidate)
    # Back into document order, so a snippet list reads down the page.
    return sorted(kept, key=lambda c: c.span.start)


def _match_spans(text: str, pack: RulePack) -> tuple[Span, ...]:
    """Every rule's secret span over the unit, gated or not, deduplicated.

    This is the mask set for redaction: a match dropped by a gate or by the report
    cap is still a secret that must not appear unmasked in a neighbour's snippet.
    It is a separate, cheaper pass than :func:`_candidates` — no entropy or keyword
    work — so completeness here never depends on how many matches were reported.
    """
    spans: dict[tuple[int, int], Span] = {}
    for rule in pack.rules:
        for match in rule.pattern.finditer(text):
            span, candidate_text = _secret_span(rule, match)
            if span is not None and candidate_text:
                spans[(span.start, span.end)] = span
    return tuple(spans.values())


def _candidates(text: str, pack: RulePack, result: DetectionResult) -> Iterator[_Candidate]:
    """Every regex match that survives its rule's entropy and keyword gates."""
    for rule in pack.rules:
        for match in rule.pattern.finditer(text):
            span, candidate_text = _secret_span(rule, match)
            if span is None or not candidate_text:
                continue

            entropy = shannon_entropy(candidate_text)
            if rule.entropy_min is not None and entropy < rule.entropy_min:
                result.dropped_low_entropy += 1
                continue

            keyword = keyword_near(text, span.start, span.end, rule.keywords, rule.keyword_window)
            if rule.requires_keyword and keyword is None:
                # The generic high-entropy rule without this is a machine for
                # reporting git shas (docs/rules.md).
                result.dropped_no_keyword += 1
                continue

            signals = Signals(entropy=entropy, keyword_nearby=keyword is not None, keyword=keyword)
            yield _Candidate(
                rule=rule,
                span=span,
                text=candidate_text,
                signals=signals,
                score=confidence(
                    base=rule.base_confidence,
                    signals=signals,
                    entropy_min=rule.entropy_min,
                    has_keywords=bool(rule.keywords),
                ),
            )


def _secret_span(rule: Rule, match: re.Match[str]) -> tuple[Span | None, str]:
    """The part of a match that is the secret.

    A rule that needs context to match — ``password\\s*=\\s*(?P<secret>\\S+)`` — must
    not report the context as the secret: the fingerprint would then change when
    the spacing did, and the snippet would mask the word "password" instead of what
    follows it.
    """
    group = Rule.SECRET_GROUP if Rule.SECRET_GROUP in rule.pattern.groupindex else 0
    start, end = match.span(group)
    if start < 0 or end <= start:
        return None, ""
    return Span(start, end), match.group(group)
