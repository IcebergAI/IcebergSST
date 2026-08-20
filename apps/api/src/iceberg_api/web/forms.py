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
from urllib.parse import quote

from fastapi import HTTPException, Response
from iceberg_core.config import ApiSettings
from pydantic import ValidationError

from iceberg_api.auth.session import issue_flash
from iceberg_api.web.templating import hx_redirect

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
    if isinstance(exc, ValueError):
        # Checked after ValidationError, which subclasses it. A route raising a
        # bare ValueError ("choose a source") is writing the sentence it wants the
        # analyst to read; discarding it for a generic one would lose the only
        # copy anybody authored.
        return str(exc)
    return "The request could not be completed."  # pragma: no cover — defensive


def redirect_with_error(path: str, exc: Exception, settings: ApiSettings) -> Response:
    """Send the browser to ``path`` carrying the reason the request failed.

    The message rides in the query string rather than a swapped fragment because
    these forms sit on a listing: a full reload is what shows the analyst the rows
    their change did — or did not — affect.

    **Signed, not carried as text** (#197). The listing pages render whatever
    arrives here inside the console's own chrome, so plain text meant a crafted
    link could put attacker-chosen words in a trusted frame — autoescaped, so not
    script, but a `/login?error=Your account is locked, call 555-0100` reads
    exactly as though this console said it. The token is minted for a
    two-minute window under the same key as the session cookie, and a page shows
    nothing at all for anything it cannot verify.
    """
    token = issue_flash(error_text(exc), settings)
    return hx_redirect(f"{path}?error={quote(token, safe='')}")


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
