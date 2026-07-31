"""The Jinja environment, and the two ways a web route answers (#54).

**The partial convention.** A route that a browser navigates to renders a full
page; a route HTMX calls renders a fragment. Which one is not guessed from
headers — it is the route's decision, expressed by calling :func:`render` (a page
template that extends ``base.html``) or :func:`render_partial` (a template under
``templates/partials/``, which extends nothing). Sniffing ``HX-Request`` to
decide would mean every template had two shapes and every bug had two places to
hide; a fragment URL that returns the same fragment to curl, to HTMX, and to a
browser's address bar is one you can debug.

**The conventions a fragment follows.**

* Fragments live in ``partials/`` and are named ``_thing.html``.
* A fragment owns one element with a stable id; the route that mutates it swaps
  it whole (``hx-target="#thing" hx-swap="outerHTML"``).
* A mutation answers with the fragment its change affected, so the browser never
  re-requests to find out what happened.
* Where the change is bigger than one region, the mutation answers
  :func:`hx_redirect` and the browser does a normal navigation.

Autoescaping is on for every template, which is what makes it safe to render a
redacted snippet or a Confluence page title — strings that came out of somebody
else's system and are the reason this UI is a stored-XSS target at all.
"""

import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import Request, Response
from fastapi.responses import HTMLResponse
from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape

from iceberg_api.web.assets import TEMPLATES_DIR, asset_manifest

APP_NAME = "IcebergSST"


def _format_datetime(value: datetime | None) -> str:
    """An absolute UTC timestamp. Never a local one.

    Every timestamp in this system is UTC, engines and analysts are in different
    places, and a triage decision recorded at "14:02" is only useful if everyone
    reading it means the same 14:02.
    """
    if value is None:
        return "—"
    aware = value if value.tzinfo else value.replace(tzinfo=UTC)
    return aware.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC")


def _format_ago(value: datetime | None) -> str:
    """Coarse relative time, for "is this engine still alive?" at a glance."""
    if value is None:
        return "never"
    aware = value if value.tzinfo else value.replace(tzinfo=UTC)
    seconds = (datetime.now(UTC) - aware).total_seconds()
    if seconds < 0:
        # A clock skew between the API and the reader, or a scheduled future time.
        return "in the future"
    for limit, divisor, unit in (
        (60, 1, "s"),
        (3600, 60, "m"),
        (86400, 3600, "h"),
    ):
        if seconds < limit:
            return f"{int(seconds // divisor)}{unit} ago"
    return f"{int(seconds // 86400)}d ago"


def _shorten(value: object, length: int = 12) -> str:
    """A uuid's leading characters — enough to recognise, short enough to scan."""
    text = str(value)
    return text if len(text) <= length else text[:length] + "…"


def _humanize(value: object) -> str:
    """``accepted_risk`` → ``Accepted risk``. Enum values are wire format, not copy."""
    return str(value).replace("_", " ").capitalize()


def _person(value: object, names: dict[uuid.UUID, str]) -> str:
    """A user id recorded on an audit event, rendered as the person's name.

    An assignment event stores the assignee's id in ``to_value``, because that is
    what stays correct when somebody is renamed. A trail that reads
    "assign — → 966d7342-…" is technically complete and practically useless, so
    the name is substituted wherever the reader is allowed to know it, and the id
    is shortened rather than dropped when they are not.
    """
    if value in (None, ""):
        return "unassigned"
    try:
        key = uuid.UUID(str(value))
    except ValueError:
        return str(value)
    return names.get(key, f"{str(value)[:12]}…")


def build_environment() -> Environment:
    """The template environment.

    ``StrictUndefined`` turns a typo'd variable into a loud failure at render time
    rather than a silently empty cell — in a findings table, a blank where a
    severity should be is indistinguishable from a finding with no severity.
    """
    env = Environment(
        loader=FileSystemLoader(TEMPLATES_DIR),
        autoescape=select_autoescape(default_for_string=True, default=True),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
        auto_reload=False,
    )
    env.filters["dt"] = _format_datetime
    env.filters["ago"] = _format_ago
    env.filters["short"] = _shorten
    env.filters["humanize"] = _humanize
    env.filters["person"] = _person
    env.globals["app_name"] = APP_NAME
    return env


_environment = build_environment()


def base_context(request: Request, **extra: Any) -> dict[str, Any]:
    """What every template gets, whether it is a page or a fragment.

    ``csrf_token`` is here rather than passed per route because every mutating
    form and every ``hx-`` request needs it, and a token supplied by hand is one
    somebody eventually forgets.
    """
    context: dict[str, Any] = {
        "request": request,
        "path": request.url.path,
        "assets": asset_manifest(),
        "user": None,
        "role": None,
        "csrf_token": "",
    }
    context.update(extra)
    return context


def render(
    request: Request,
    template: str,
    context: dict[str, Any] | None = None,
    *,
    status_code: int = 200,
    headers: dict[str, str] | None = None,
) -> HTMLResponse:
    """Render a full page (a template that extends ``base.html``)."""
    body = _environment.get_template(template).render(base_context(request, **(context or {})))
    return HTMLResponse(body, status_code=status_code, headers=headers)


def render_partial(
    request: Request,
    template: str,
    context: dict[str, Any] | None = None,
    *,
    status_code: int = 200,
    headers: dict[str, str] | None = None,
) -> HTMLResponse:
    """Render a fragment from ``partials/`` — no layout, no ``<html>``."""
    return render(
        request,
        f"partials/{template}",
        context,
        status_code=status_code,
        headers=headers,
    )


def viewer_context(viewer: Any) -> dict[str, Any]:
    """Identity for the shell: who is signed in, their role, and their token.

    Takes the :class:`~iceberg_api.web.dependencies.Viewer` structurally rather
    than by import, so the template layer stays free of the auth layer.
    """
    return {
        "user": viewer.user,
        "role": viewer.user.role.value,
        "csrf_token": viewer.csrf_token,
    }


def render_page(
    request: Request,
    template: str,
    viewer: Any,
    context: dict[str, Any] | None = None,
    *,
    status_code: int = 200,
    headers: dict[str, str] | None = None,
) -> HTMLResponse:
    """Render a page inside the authenticated shell."""
    return render(
        request,
        template,
        viewer_context(viewer) | (context or {}),
        status_code=status_code,
        headers=headers,
    )


def render_fragment(
    request: Request,
    template: str,
    viewer: Any,
    context: dict[str, Any] | None = None,
    *,
    status_code: int = 200,
    headers: dict[str, str] | None = None,
) -> HTMLResponse:
    """Render a fragment with the same identity a page would have.

    A fragment needs ``user``, ``role``, and ``csrf_token`` for exactly the
    reasons a page does: it contains forms that must carry a token and controls
    that only some roles are offered. Without this, a partial rendered by a
    mutation would differ from the identical markup rendered inside its page.
    """
    return render_partial(
        request,
        template,
        viewer_context(viewer) | (context or {}),
        status_code=status_code,
        headers=headers,
    )


def hx_redirect(url: str) -> Response:
    """Tell HTMX to navigate rather than swap.

    A 302 would be followed by ``fetch`` and the login page (or the new detail
    page) would be swapped into whatever element issued the request. ``HX-Redirect``
    is the header that makes the browser actually go there.
    """
    return Response(status_code=204, headers={"HX-Redirect": url})


def hx_refresh() -> Response:
    """Tell HTMX to reload the current page — for a change with no single target."""
    return Response(status_code=204, headers={"HX-Refresh": "true"})


def is_htmx(request: Request) -> bool:
    """Whether HTMX issued this request.

    Used only to choose the *failure* shape — a redirect header instead of a
    redirect response — never to choose which template renders.
    """
    return request.headers.get("HX-Request") == "true"


def id_or_none(value: str | None) -> uuid.UUID | None:
    """Parse an optional uuid from a query string, treating junk as absent.

    A filter arriving as a non-uuid is a stale bookmark or a hand-edited URL. The
    honest answer is the unfiltered list, not a 422 on a read-only page.
    """
    if not value:
        return None
    try:
        return uuid.UUID(value)
    except ValueError:
        return None
