"""Turning API-shaped failures into pages a person can act on.

Two handlers, both scoped to the browser surface. Anything under ``/api/v1``
keeps FastAPI's JSON error shape untouched: the OpenAPI schema is the contract
(docs/api.md), and a client parsing an error body must not start receiving HTML
because the UI was added alongside it.

The HTMX cases are the subtle half. A ``fetch`` follows a 3xx transparently, so a
plain redirect to the login page ends up *swapped into whatever element issued
the request* — a login form inside a table cell. ``HX-Redirect`` is the header
that makes the browser navigate instead, and it needs a 2xx to be honoured.
"""

import structlog
from fastapi import FastAPI, HTTPException, Request, Response, status
from fastapi.exception_handlers import http_exception_handler
from fastapi.responses import RedirectResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from iceberg_api.auth.session import safe_return_path
from iceberg_api.web.dependencies import LoginRequired
from iceberg_api.web.templating import is_htmx, render

logger = structlog.get_logger()

#: What each status means to somebody looking at a screen. Anything not listed
#: falls back to the generic message — an error page that invents an explanation
#: is worse than one that admits it does not have a specific one.
_EXPLANATIONS = {
    status.HTTP_403_FORBIDDEN: (
        "Your role does not allow this",
        "Ask an administrator if you need access to this part of the console.",
    ),
    status.HTTP_404_NOT_FOUND: (
        "Not found",
        "The page or record you asked for does not exist. It may have been deleted.",
    ),
    status.HTTP_409_CONFLICT: (
        "That conflicts with the current state",
        "Something changed since this page was loaded. Reload and try again.",
    ),
    status.HTTP_503_SERVICE_UNAVAILABLE: (
        "A dependency is unavailable",
        "The identity provider or the secret store did not answer. Check the API logs.",
    ),
}


def login_url(return_path: str) -> str:
    """The login page, remembering where the visitor was going.

    ``safe_return_path`` runs here as well as in the auth routes: this value is
    built from the request URL, and reducing it to a local path at the point it
    becomes a redirect target is what keeps a crafted path from becoming an open
    redirect at the far end of the login round trip.
    """
    target = safe_return_path(return_path)
    return "/login" if target == "/" else f"/login?next={target}"


async def login_required_handler(request: Request, exc: Exception) -> Response:
    """Send an unauthenticated browser to the login page."""
    return_path = exc.return_path if isinstance(exc, LoginRequired) else "/"
    destination = login_url(return_path)
    if is_htmx(request):
        return Response(
            status_code=status.HTTP_204_NO_CONTENT, headers={"HX-Redirect": destination}
        )
    return RedirectResponse(destination, status_code=status.HTTP_303_SEE_OTHER)


async def web_http_exception_handler(request: Request, exc: Exception) -> Response:
    """Render a browser-facing failure as a page; leave the API's JSON alone.

    Split by path, not by ``Accept``. The API's contract is JSON errors for every
    caller (docs/api.md), and the browser surface is HTML for every caller — a
    handler that switched on a request header would answer the same URL two
    different ways depending on who asked, which is the kind of thing that makes
    an error report impossible to reproduce.
    """
    if not isinstance(exc, StarletteHTTPException):  # pragma: no cover — defensive
        raise exc
    if request.url.path.startswith(("/api/", "/healthz", "/metrics")):
        return await http_exception_handler(request, exc)

    if exc.status_code == status.HTTP_401_UNAUTHORIZED:
        # A session that expired between page load and click. Same destination as
        # LoginRequired; this path is reached when an API handler raises it from
        # inside a web route rather than a dependency raising it up front.
        return await login_required_handler(request, LoginRequired(request.url.path))

    title, explanation = _EXPLANATIONS.get(
        exc.status_code, ("Something went wrong", "The console could not complete that request.")
    )
    # The detail is the API's own message ("source has no stored credential to
    # test"), which is written for a person and is the most useful thing on the
    # page. Autoescaping makes rendering it safe.
    detail = exc.detail if isinstance(exc.detail, str) else None
    if exc.status_code >= status.HTTP_500_INTERNAL_SERVER_ERROR:
        logger.warning("web_error_page", status=exc.status_code, path=request.url.path)

    return render(
        request,
        "error.html",
        {
            "status_code": exc.status_code,
            "title": title,
            "explanation": explanation,
            "detail": detail,
        },
        status_code=exc.status_code,
    )


def register(app: FastAPI) -> None:
    """Attach both handlers. Called from the application factory."""
    app.add_exception_handler(LoginRequired, login_required_handler)
    app.add_exception_handler(HTTPException, web_http_exception_handler)
    app.add_exception_handler(StarletteHTTPException, web_http_exception_handler)
