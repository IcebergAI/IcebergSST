"""Turn a detected match into a snippet that is safe to store (ADR 0004).

This runs **inside the engine**, before any result leaves the worker: the
plaintext secret never crosses the wire and never reaches the database. What is
stored is a masked snippet plus a peppered hash (see
:mod:`iceberg_core.fingerprint`).

Two competing needs shape the output. An analyst triaging a finding needs enough
context to recognise it — is this a real credential or an example in a runbook?
And nothing that reaches storage may be usable as a secret. So the snippet keeps
the surrounding *non-secret* text and replaces the secret itself with a mask that
reveals, at most, a short structural prefix (``AKIA…``) that identifies the kind
of key without helping anyone authenticate with it.

Rules declare their own strategy (``redaction: keep_prefix`` in a rule pack, see
``docs/rules.md``), because what is safe to reveal depends on the secret: the
first four characters of an AWS key id are a vendor tag, the first four of a
password are a quarter of the password.
"""

import re
from dataclasses import dataclass
from enum import StrEnum

#: Hard ceiling on a stored snippet. Context is already bounded by the policy;
#: this is the backstop for a match inside a pathological single-line blob.
MAX_SNIPPET_CHARS = 300

_WHITESPACE_RUN = re.compile(r"\s+")
_ELLIPSIS = "…"


class RedactionError(Exception):
    """Raised when redaction could not produce a safe snippet.

    Reaching this means a bug in the masking logic, so the engine drops the
    finding rather than transmitting something that might contain plaintext.
    """


class RedactionStrategy(StrEnum):
    """How much of a matched secret may survive into the snippet."""

    FULL = "full"
    KEEP_PREFIX = "keep_prefix"
    KEEP_SUFFIX = "keep_suffix"


@dataclass(frozen=True, slots=True)
class Span:
    """A half-open ``[start, end)`` match range within a content unit."""

    start: int
    end: int

    def __post_init__(self) -> None:
        if self.start < 0 or self.end <= self.start:
            raise ValueError(f"invalid span: [{self.start}, {self.end})")

    def overlaps(self, other: Span) -> bool:
        return self.start < other.end and other.start < self.end


@dataclass(frozen=True, slots=True)
class RedactionPolicy:
    """Per-rule masking parameters.

    ``keep`` is an upper bound, not a promise: :func:`mask_secret` also refuses to
    reveal more than a third of a secret, and reveals nothing at all from a secret
    shorter than ``min_length_to_reveal``. A four-character prefix of a
    twelve-character password is a meaningful head start for a cracker; of a
    forty-character token, it is a vendor tag.
    """

    strategy: RedactionStrategy = RedactionStrategy.FULL
    keep: int = 4
    context_chars: int = 48
    min_length_to_reveal: int = 16

    @classmethod
    def from_strategy_name(cls, name: str, **overrides: int) -> RedactionPolicy:
        """Build a policy from a rule pack's ``redaction:`` value.

        Unknown names raise: a typo in a rule pack must fail at load time, not
        silently fall back to revealing more than intended.
        """
        try:
            strategy = RedactionStrategy(name)
        except ValueError as exc:
            known = ", ".join(member.value for member in RedactionStrategy)
            raise ValueError(f"unknown redaction strategy {name!r}; known: {known}") from exc
        return cls(strategy=strategy, **overrides)


def revealable_length(secret_length: int, policy: RedactionPolicy) -> int:
    """How many characters of a secret of this length may be revealed."""
    if policy.strategy is RedactionStrategy.FULL:
        return 0
    if secret_length < policy.min_length_to_reveal:
        return 0
    return max(0, min(policy.keep, secret_length // 3))


def mask_secret(secret: str, policy: RedactionPolicy | None = None) -> str:
    """Return the masked form of ``secret``.

    Examples (with ``keep_prefix``/``keep=4``)::

        AKIAIOSFODNN7EXAMPLE  ->  AKIA…[16 chars redacted]
        hunter2               ->  [7 chars redacted]
    """
    resolved = policy or RedactionPolicy()
    if not secret:
        raise ValueError("nothing to mask: empty secret")

    revealed = revealable_length(len(secret), resolved)
    hidden = len(secret) - revealed
    marker = f"[{hidden} chars redacted]"
    if revealed == 0:
        return marker
    if resolved.strategy is RedactionStrategy.KEEP_SUFFIX:
        return f"{marker}{_ELLIPSIS}{secret[-revealed:]}"
    return f"{secret[:revealed]}{_ELLIPSIS}{marker}"


def redact_snippet(
    text: str,
    target: Span,
    *,
    policy: RedactionPolicy | None = None,
    other_spans: tuple[Span, ...] = (),
) -> str:
    """Return a storable snippet: bounded context around a masked match.

    ``other_spans`` are the other matches found in the same content unit. Any
    that fall inside the context window are masked too — a snippet that hides
    its own secret while printing the neighbouring one in full would be a leak by
    a different route. Callers should pass every match they found; matches
    outside the window cost nothing.

    Whitespace in the context is collapsed to single spaces so a snippet is one
    readable line in the UI (and in a log, if it ever ends up in one).
    """
    resolved = policy or RedactionPolicy()
    if target.end > len(text):
        raise ValueError(f"target span {target} runs past the end of the content")

    window = Span(
        max(0, target.start - resolved.context_chars),
        min(len(text), target.end + resolved.context_chars),
    )
    # A copy of a secret that the window edge cuts through would have its in-window
    # half stored as plaintext — the scrub and the final assert both look for whole
    # secrets and miss a clipped one. Pull each edge back to the copy's outer
    # boundary so nothing partial is ever emitted (the target defines the window,
    # so it never straddles).
    window = _clip_to_secret_boundaries(text, window, target, other_spans)
    masked = _masked_pieces(text, target, other_spans, window, resolved)
    snippet = "".join(masked)

    if window.start > 0:
        snippet = _ELLIPSIS + snippet
    if window.end < len(text):
        snippet += _ELLIPSIS

    # Assert on the whole snippet, then truncate: truncation can only remove
    # already-proven-safe content, never smuggle a partial secret past the check.
    _assert_no_plaintext(snippet, text, target, other_spans)
    return snippet[:MAX_SNIPPET_CHARS]


def _clip_to_secret_boundaries(
    text: str, window: Span, target: Span, other_spans: tuple[Span, ...]
) -> Span:
    """Shrink ``window`` so neither edge bisects a literal copy of a matched secret.

    A copy straddling an edge sits *outside* the target (a copy overlapping the
    target is masked as a neighbour, not emitted as context), so pulling the edge
    inward past it never eats into the match itself.
    """
    secrets = {t for span in (target, *other_spans) if len(t := text[span.start : span.end]) > 1}
    if not secrets:
        return window

    start, end = window.start, window.end
    moved = True
    while moved and end > target.end:
        moved = False
        for secret in secrets:
            hit = _straddler(text, end, secret)
            if hit is not None and hit[0] >= target.end:
                end, moved = hit[0], True
    moved = True
    while moved and start < target.start:
        moved = False
        for secret in secrets:
            hit = _straddler(text, start, secret)
            if hit is not None and hit[1] <= target.start:
                start, moved = hit[1], True
    return Span(start, end)


def _straddler(text: str, boundary: int, secret: str) -> tuple[int, int] | None:
    """The leftmost occurrence of ``secret`` that contains ``boundary`` strictly
    inside it, or ``None``. Every match in the searched slice necessarily straddles
    ``boundary``, so no per-hit check is needed."""
    length = len(secret)
    index = text.find(secret, max(0, boundary - length + 1), boundary + length - 1)
    return (index, index + length) if index != -1 else None


def _masked_pieces(
    text: str,
    target: Span,
    other_spans: tuple[Span, ...],
    window: Span,
    policy: RedactionPolicy,
) -> list[str]:
    """Walk the window, emitting collapsed context and masked secrets in order."""
    # The target's mask wins over any overlapping neighbour, but a neighbour that
    # reaches beyond the target — a generic entropy match around a narrower
    # vendor match, say — still owns the parts outside it. Those parts are kept
    # as spans of their own rather than dropped, or their text would be emitted
    # as ordinary context.
    neighbours: list[Span] = []
    for span in other_spans:
        if not span.overlaps(window):
            continue
        if not span.overlaps(target):
            neighbours.append(span)
            continue
        if span.start < target.start:
            neighbours.append(Span(span.start, target.start))
        if span.end > target.end:
            neighbours.append(Span(target.end, span.end))
    neighbours.sort(key=lambda span: span.start)

    # Neighbours are masked with the conservative default policy: this code has no
    # way to know which rule produced them, so it assumes nothing is revealable.
    plan: list[tuple[Span, str]] = [(target, mask_secret(text[target.start : target.end], policy))]
    plan += [
        (span, mask_secret(text[span.start : span.end], RedactionPolicy())) for span in neighbours
    ]
    plan.sort(key=lambda item: item[0].start)

    # The same secret often appears more than once in a page ("same as prod: …")
    # and only one occurrence need have been matched. Scrubbing every literal
    # occurrence out of the context keeps a stray copy from riding along. Every
    # match's full text is scrubbed — not only the ones overlapping the window —
    # so a stray copy of a match found elsewhere in the unit is caught here rather
    # than tripping the plaintext assert and dropping the finding.
    replacements = tuple((text[span.start : span.end], mask) for span, mask in plan) + tuple(
        (text[span.start : span.end], mask_secret(text[span.start : span.end], RedactionPolicy()))
        for span in other_spans
    )

    pieces: list[str] = []
    cursor = window.start
    for span, mask in plan:
        pieces.append(_context(text[cursor : max(cursor, span.start)], replacements))
        pieces.append(mask)
        cursor = max(cursor, span.end)
    pieces.append(_context(text[cursor : max(cursor, window.end)], replacements))
    return pieces


def _context(fragment: str, replacements: tuple[tuple[str, str], ...]) -> str:
    """Collapse whitespace and scrub any literal repeat of a matched secret."""
    scrubbed = fragment
    # Longest first, so a secret that contains another is replaced as a whole.
    for secret, mask in sorted(replacements, key=lambda item: len(item[0]), reverse=True):
        if len(secret) > 1:
            scrubbed = scrubbed.replace(secret, mask)
    return _WHITESPACE_RUN.sub(" ", scrubbed)


def _assert_no_plaintext(
    snippet: str, text: str, target: Span, other_spans: tuple[Span, ...]
) -> None:
    """Defence in depth: refuse to return a snippet containing a whole secret.

    Single-character matches are skipped — one character is certain to appear in
    ordinary context text, so checking it would only produce false alarms.
    """
    for span in (target, *other_spans):
        secret = text[span.start : span.end]
        if len(secret) > 1 and secret in snippet:
            raise RedactionError("redaction failed: snippet still contains a matched secret")
