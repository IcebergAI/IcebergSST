"""CSRF protection for session-authenticated mutations.

Cookie-based auth means a browser attaches credentials to cross-site requests
automatically, so every mutating route needs proof the request came from our own
UI. The token lives in the session cookie (so it cannot be read by script from
another origin) and must be echoed in the ``X-CSRF-Token`` header or a
``csrf_token`` form field — the double-submit pattern, with the authoritative
copy signed inside the session rather than in a second cookie an attacker on a
sibling subdomain could set.

Read-only requests are exempt: they change nothing, and requiring a token on
``GET`` would break ordinary navigation.
"""

import hmac

from fastapi import Request

CSRF_HEADER = "X-CSRF-Token"  # a header name
CSRF_FORM_FIELD = "csrf_token"  # a form field name

#: Methods that cannot change state, and so need no token.
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})


class CsrfError(Exception):
    """The request carried no CSRF token, or the wrong one."""


async def presented_token(request: Request) -> str | None:
    """Return the token the client presented, header first then form body.

    Form parsing is attempted only for form content types: reading the body of a
    JSON request here would consume the stream the route handler needs.
    """
    header = request.headers.get(CSRF_HEADER)
    if header:
        return header

    content_type = request.headers.get("content-type", "")
    if content_type.startswith(("application/x-www-form-urlencoded", "multipart/form-data")):
        form = await request.form()
        value = form.get(CSRF_FORM_FIELD)
        if isinstance(value, str):
            return value
    return None


def verify(expected: str, presented: str | None) -> None:
    """Compare tokens in constant time, or raise :class:`CsrfError`."""
    if not presented or not hmac.compare_digest(expected, presented):
        raise CsrfError("missing or invalid CSRF token")
