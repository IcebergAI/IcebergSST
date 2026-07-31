"""Security response headers for the browser-facing surface.

The policy is **strict**: ``script-src 'self'`` with no ``'unsafe-inline'`` and no
``'unsafe-eval'``. That is only possible because the UI carries no inline
JavaScript at all — Alpine runs from its CSP build (directive expressions are
interpreted, never ``eval``\\ ed), every component is registered in
``static/js/tags.js``, and server data reaches Alpine through
``<script type="application/json">`` islands rather than attributes. A finding
viewer is exactly the kind of page where a stored-XSS would be worth the most:
it renders attacker-influenced strings (page titles, resource paths, redacted
snippets) that came out of somebody else's Confluence.

``style-src`` keeps ``'unsafe-inline'`` deliberately, and only for that: the
templates set dynamic ``style=`` attributes (a progress-bar width), inline style
*attributes* cannot be nonced, and CSS injection is a far smaller problem than
script injection. This is the standard "strict CSP targets scripts" carve-out.

The headers are owned by the application rather than a reverse proxy: nginx's
``add_header`` appends rather than overrides, so setting them in both layers
emits duplicates, and the app is the only layer that knows its own content
surface. HSTS is the exception that is emitted only in production — behind a
TLS-terminating proxy the app sees ``http``, so it cannot key off the request
scheme and uses the operator's ``is_prod`` assertion instead, mirroring the
Secure-cookie gate.
"""

from collections.abc import Awaitable, Callable

from fastapi import Request, Response
from iceberg_core.config import CoreSettings, get_core_settings

#: FastAPI's interactive docs load Swagger UI/ReDoc from a CDN and bootstrap them
#: with an inline script. They are a developer tool, not part of the product
#: surface, and a policy loose enough to run them would be no policy at all — so
#: they are exempted by path instead of weakening the header everywhere.
DOCS_PATHS = frozenset({"/docs", "/docs/oauth2-redirect", "/redoc"})

#: Browser features the UI never uses. An empty allowlist denies every origin,
#: this one included, so a future injection cannot reach them either.
PERMISSIONS_POLICY = ", ".join(
    f"{feature}=()"
    for feature in (
        "accelerometer",
        "autoplay",
        "camera",
        "display-capture",
        "encrypted-media",
        "geolocation",
        "gyroscope",
        "magnetometer",
        "microphone",
        "midi",
        "payment",
        "usb",
        "xr-spatial-tracking",
    )
)

#: In declaration order. ``upgrade-insecure-requests`` is appended in production
#: only, so plain-http static assets still load in local development.
CSP_DIRECTIVES: tuple[tuple[str, str], ...] = (
    ("default-src", "'self'"),
    # No 'unsafe-inline' / 'unsafe-eval': Alpine's CSP build + external JS only.
    ("script-src", "'self'"),
    # 'unsafe-inline' permits dynamic style= attributes and nothing else.
    ("style-src", "'self' 'unsafe-inline'"),
    # data: for the inline SVG chevron on <select class="field">.
    ("img-src", "'self' data:"),
    ("font-src", "'self'"),
    # HTMX and Alpine only ever talk to this origin.
    ("connect-src", "'self'"),
    ("object-src", "'none'"),
    ("base-uri", "'self'"),
    ("form-action", "'self'"),
    ("frame-ancestors", "'none'"),
)


def build_csp(*, is_prod: bool) -> str:
    parts = [f"{name} {value}" for name, value in CSP_DIRECTIVES]
    if is_prod:
        parts.append("upgrade-insecure-requests")
    return "; ".join(parts)


def build_security_headers(settings: CoreSettings) -> dict[str, str]:
    """Every security header, as a pure function of settings.

    Takes :class:`CoreSettings` rather than :class:`ApiSettings` because
    ``environment`` is the only thing it reads, and requiring a database URL to
    answer "should this response carry HSTS?" would tie the browser policy to a
    role it does not depend on.
    """
    is_prod = settings.environment == "prod"
    headers = {
        "Content-Security-Policy": build_csp(is_prod=is_prod),
        # Legacy backstop for frame-ancestors 'none' (pre-CSP-Level-2 browsers).
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        # The findings UI puts source names and resource paths in the URL; a
        # cross-origin referer would leak them to whatever an analyst clicks.
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": PERMISSIONS_POLICY,
        "Cross-Origin-Opener-Policy": "same-origin",
    }
    if is_prod:
        headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return headers


def security_headers_middleware(
    settings: CoreSettings | None,
) -> Callable[[Request, Callable[[Request], Awaitable[Response]]], Awaitable[Response]]:
    """Build the middleware, closing over the settings the app was created with.

    ``None`` is how the uvicorn factory entrypoint builds the app, so the headers
    are resolved from the environment on first use and kept — middleware runs on
    every request, and the environment cannot change underneath a live process.
    """
    resolved: dict[str, str] | None = build_security_headers(settings) if settings else None

    async def middleware(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        nonlocal resolved
        if resolved is None:
            resolved = build_security_headers(get_core_settings())

        response = await call_next(request)
        if request.url.path in DOCS_PATHS:
            return response
        for name, value in resolved.items():
            # setdefault, never overwrite: a route that set a header deliberately
            # (a per-download nosniff, say) knows something this layer does not.
            response.headers.setdefault(name, value)
        return response

    return middleware
