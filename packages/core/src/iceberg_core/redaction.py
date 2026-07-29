"""Redaction: turn a raw match into a storable snippet (issue #25, ADR 0004).

This runs **inside the engine**, before any result leaves the worker. The
plaintext secret is never persisted, never transmitted, and never logged — a
finding carries only what these functions return plus the salted hash from
:mod:`iceberg_core.fingerprint`.

Strategies are per-rule: a rule pack declares ``redaction: keep_prefix`` (see
``docs/rules.md``) and the engine looks the strategy up by name here. The default
for an unknown or unset strategy is total masking — failing closed, so a new rule
that forgets to declare a strategy cannot leak.

Distinct from :func:`iceberg_core.logging.redact_sensitive`, which masks whole
values by *key name* in log events. This module masks the secret *inside* a span
of surrounding text.
"""

from collections.abc import Callable
from enum import StrEnum

MASK_CHAR = "•"
MASK_RUN = MASK_CHAR * 8
DEFAULT_CONTEXT_CHARS = 32
_KEEP_PREFIX_CHARS = 4
_KEEP_LAST_CHARS = 4


class RedactionStrategy(StrEnum):
    """How a rule's matches are masked. Values match the rule-pack YAML field."""

    FULL = "full"
    KEEP_PREFIX = "keep_prefix"
    KEEP_LAST = "keep_last"


def _full(secret: str) -> str:
    return f"{MASK_RUN}({len(secret)} chars)"


def _keep_prefix(secret: str) -> str:
    if len(secret) <= _KEEP_PREFIX_CHARS:
        return _full(secret)
    return f"{secret[:_KEEP_PREFIX_CHARS]}{MASK_RUN}({len(secret)} chars)"


def _keep_last(secret: str) -> str:
    if len(secret) <= _KEEP_LAST_CHARS:
        return _full(secret)
    return f"{MASK_RUN}{secret[-_KEEP_LAST_CHARS:]}({len(secret)} chars)"


_STRATEGIES: dict[RedactionStrategy, Callable[[str], str]] = {
    RedactionStrategy.FULL: _full,
    RedactionStrategy.KEEP_PREFIX: _keep_prefix,
    RedactionStrategy.KEEP_LAST: _keep_last,
}


def mask_secret(secret: str, strategy: RedactionStrategy = RedactionStrategy.FULL) -> str:
    """Mask a secret value on its own, e.g. ``AKIA••••••••(20 chars)``.

    Every strategy is length-preserving in *description* only: the output states
    how long the secret was but reveals at most a few structural characters, which
    is what makes a masked snippet useful for triage (ADR 0004).
    """
    return _STRATEGIES.get(strategy, _full)(secret)


def redact_snippet(
    text: str,
    start: int,
    end: int,
    *,
    strategy: RedactionStrategy = RedactionStrategy.FULL,
    context_chars: int = DEFAULT_CONTEXT_CHARS,
) -> str:
    """Return ``text[start:end]`` masked, with surrounding non-secret context.

    ``start``/``end`` are the match offsets within ``text``. The context either
    side is what an analyst triages on (``password = ••••••••(18 chars)`` reads
    very differently from a bare hash), and it is safe because it is the content
    *around* the match, not the match itself.

    Raises ``ValueError`` on offsets that do not describe a real span — a caller
    passing junk offsets must not silently get unmasked text back.
    """
    if not 0 <= start < end <= len(text):
        raise ValueError(f"invalid match span [{start}:{end}] for text of length {len(text)}")
    if context_chars < 0:
        raise ValueError("context_chars must not be negative")

    secret = text[start:end]
    lead = text[max(0, start - context_chars) : start]
    trail = text[end : end + context_chars]
    if start - context_chars > 0:
        lead = f"…{lead}"
    if end + context_chars < len(text):
        trail = f"{trail}…"
    return f"{lead}{mask_secret(secret, strategy)}{trail}".replace("\n", " ").strip()
