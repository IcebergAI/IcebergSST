"""Turning an HTML form into an API request body, and an API failure into words.

Forms are the awkward seam of a server-rendered UI. A browser posts flat strings
— an unchecked box sends nothing at all, and every value arrives as ``str`` — but
the API's contract is typed pydantic models. This module holds that translation
in one place so no route re-derives "what does an absent checkbox mean".

Nothing here validates. Validation belongs to the API's models, which is the
whole point of routing the UI through them: a rule enforced in a template is a
rule an API client can walk straight past.
"""

from typing import Any

from fastapi import HTTPException
from pydantic import ValidationError

#: What a checked box posts. An unchecked one posts nothing, so absence is False.
CHECKED = frozenset({"on", "true", "1", "yes"})


def checkbox(value: str | None) -> bool:
    return value is not None and value.strip().lower() in CHECKED


def optional(value: str | None) -> str | None:
    """A text field that was left blank is absent, not an empty string.

    ``""`` and ``None`` mean different things to a ``PATCH`` model — one is "set
    this to nothing", the other "leave it alone" — and a browser cannot express
    the difference. Blank means "not supplied" everywhere in this UI.
    """
    if value is None:
        return None
    trimmed = value.strip()
    return trimmed or None


def string_list(values: list[str] | None) -> list[str]:
    """Repeated inputs of the same name, blanks dropped."""
    return [item.strip() for item in (values or []) if item.strip()]


def error_text(exc: Exception) -> str:
    """A single sentence a person can act on, from whatever the API raised.

    ``HTTPException(422, [...])`` carries pydantic's per-field errors; a form
    that only said "invalid" would send an analyst hunting through six fields for
    the one with a typo, so the field name is kept.
    """
    if isinstance(exc, HTTPException):
        # Starlette types `detail` as `str`, but FastAPI lets a route raise any
        # JSON-serialisable value and the 422s here are lists of field errors.
        detail: object = exc.detail
        if isinstance(detail, str):
            return detail
        if isinstance(detail, list):
            return "; ".join(_one_error(entry) for entry in detail) or "The request was rejected."
        return "The request was rejected."
    if isinstance(exc, ValidationError):
        return "; ".join(
            f"{_field(error.get('loc', ()))}: {error.get('msg', 'is not valid')}"
            for error in exc.errors()
        )
    return "The request could not be completed."  # pragma: no cover — defensive


def _one_error(entry: Any) -> str:
    if not isinstance(entry, dict):
        return str(entry)
    return f"{_field(entry.get('loc', ()))}: {entry.get('msg', 'is not valid')}"


def _field(loc: Any) -> str:
    """The last addressable part of a pydantic location — the field name.

    ``('body', 'connection', 'base_url')`` reads better to an operator as
    ``base_url`` than as the whole path through the request model.
    """
    parts = [str(part) for part in loc if not isinstance(part, int)]
    return parts[-1] if parts else "request"
