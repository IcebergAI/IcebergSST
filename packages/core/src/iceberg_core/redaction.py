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


def context_window(length: int, target: Span, policy: RedactionPolicy | None = None) -> Span:
    """The span :func:`redact_snippet` draws its context from.

    Public because a caller redacting many matches in one unit needs it to work
    out which of them reach a given snippet: passing every match in the unit to
    every call is a pass over the whole match set per finding.
    """
    resolved = policy or RedactionPolicy()
    return Span(
        max(0, target.start - resolved.context_chars),
        min(length, target.end + resolved.context_chars),
    )


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
    a different route. Callers must pass every match reaching the window
    (:func:`context_window` says which those are); matches outside it cost nothing
    but need not be passed.

    Whitespace in the context is collapsed to single spaces so a snippet is one
    readable line in the UI (and in a log, if it ever ends up in one).
    """
    resolved = policy or RedactionPolicy()
    if target.end > len(text):
        raise ValueError(f"target span {target} runs past the end of the content")

    window = context_window(len(text), target, resolved)
    secrets = _matched_texts(text, target, other_spans)
    # A copy of a secret that the window edge cuts through would have its in-window
    # half stored as plaintext — the scrub and the final assert both look for whole
    # secrets and miss a clipped one. Pull each edge back past the copy so nothing
    # partial is ever emitted.
    window = _clip_to_secret_boundaries(text, window, target, secrets)
    masked = _masked_pieces(text, target, other_spans, window, resolved)
    snippet = "".join(masked)

    if window.start > 0:
        snippet = _ELLIPSIS + snippet
    if window.end < len(text):
        snippet += _ELLIPSIS

    # Assert on the whole snippet, then truncate: truncation can only remove
    # already-proven-safe content, never smuggle a partial secret past the check.
    _assert_no_plaintext(snippet, secrets)
    _assert_no_bisected_secret(text, window, target, secrets)
    return snippet[:MAX_SNIPPET_CHARS]


def _matched_texts(text: str, target: Span, other_spans: tuple[Span, ...]) -> set[str]:
    """The distinct plaintext of every match, single characters excluded.

    One character is certain to appear in ordinary context text, so scrubbing or
    checking it would only produce false alarms.
    """
    return {t for span in (target, *other_spans) if len(t := text[span.start : span.end]) > 1}


def _clip_to_secret_boundaries(text: str, window: Span, target: Span, secrets: set[str]) -> Span:
    """Shrink ``window`` so neither edge bisects a literal copy of a matched secret.

    A copy that overlaps the target cannot be pulled past without eating into the
    match, so for that one the edge stops at the target instead: everything from
    the target's own boundary inward is covered by its mask, and none of it is
    emitted as context.
    """
    if not secrets:
        return window

    start, end = window.start, window.end
    moved = True
    while moved and end > target.end:
        moved = False
        for secret in secrets:
            hit = _straddler(text, end, secret)
            if hit is not None:
                end, moved = max(hit[0], target.end), True
    moved = True
    while moved and start < target.start:
        moved = False
        for secret in secrets:
            hit = _straddler(text, start, secret)
            if hit is not None:
                start, moved = min(hit[1], target.start), True
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
    # occurrence out of the context keeps a stray copy from riding along. Built
    # once per snippet, longest first so a secret that contains another is replaced
    # as a whole, and the plan's masks win over a neighbour's default one.
    replacements: dict[str, str] = {}
    for span, mask in plan:
        replacements.setdefault(text[span.start : span.end], mask)
    for span in other_spans:
        secret = text[span.start : span.end]
        if secret not in replacements:
            replacements[secret] = mask_secret(secret, RedactionPolicy())
    by_length = sorted(replacements.items(), key=lambda item: len(item[0]), reverse=True)
    ordered = tuple((secret, mask) for secret, mask in by_length if len(secret) > 1)

    pieces: list[str] = []
    cursor = window.start
    for span, mask in plan:
        pieces.append(_context(text[cursor : max(cursor, span.start)], ordered))
        pieces.append(mask)
        cursor = max(cursor, span.end)
    pieces.append(_context(text[cursor : max(cursor, window.end)], ordered))
    return pieces


def _context(fragment: str, replacements: tuple[tuple[str, str], ...]) -> str:
    """Collapse whitespace and scrub any literal repeat of a matched secret."""
    scrubbed = fragment
    for secret, mask in replacements:
        scrubbed = scrubbed.replace(secret, mask)
    return _WHITESPACE_RUN.sub(" ", scrubbed)


def _assert_no_plaintext(snippet: str, secrets: set[str]) -> None:
    """Defence in depth: refuse to return a snippet containing a whole secret."""
    for secret in secrets:
        if secret in snippet:
            raise RedactionError("redaction failed: snippet still contains a matched secret")


def _assert_no_bisected_secret(text: str, window: Span, target: Span, secrets: set[str]) -> None:
    """Defence in depth for the clip: refuse a window edge that cuts through a copy.

    The whole-secret check above cannot see a bisected copy, and half of a forty-
    character token is still key material. Checking the boundary rather than the
    snippet text is deliberate: a secret's own boilerplate — a PEM header, an
    assignment prefix — legitimately recurs in the context around it, so "a long
    run of the secret appears in the snippet" would refuse honest findings.

    Only edges that emit context are checked. An edge clamped to the target sits
    against the target's mask, and nothing beyond it is emitted at all.
    """
    edges = (
        (window.end, window.end > target.end),
        (window.start, window.start < target.start),
    )
    for boundary, emits_context in edges:
        if not emits_context:
            continue
        for secret in secrets:
            if _straddler(text, boundary, secret) is not None:
                raise RedactionError("redaction failed: window edge cuts through a matched secret")
