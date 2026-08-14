"""FastAPI application factory.

Establishes what every route inherits — JSON logs with a per-request correlation
id (#67), the browser security headers (#53), and the Prometheus exposition
endpoint — and mounts the routers.

Human-facing routes live under ``/api/v1`` from day one (docs/api.md
§ Conventions); ``/healthz`` and ``/metrics`` stay unversioned because operators
and scrapers are not API clients. The M3 web UI mounts at the root and is
excluded from the OpenAPI schema: the schema is the API's contract, and HTML
endpoints in it would describe a second one (docs/web.md).
"""

import re
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, Request, Response
from fastapi.staticfiles import StaticFiles
from iceberg_core import metrics as _metrics  # noqa: F401  # registers iceberg_* series
from iceberg_core.config import ApiSettings
from iceberg_core.logging import configure_logging
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from iceberg_api import ratelimit
from iceberg_api.auth.routes import router as auth_router
from iceberg_api.correlation.routes import router as correlation_router
from iceberg_api.engines.routes import router as engines_router
from iceberg_api.findings.routes import router as findings_router
from iceberg_api.findings.suppression_routes import router as suppressions_router
from iceberg_api.maintenance import background_maintenance
from iceberg_api.notifications.routes import router as notifications_router
from iceberg_api.remediation.guidance import load_catalog
from iceberg_api.remediation.routes import router as remediation_router
from iceberg_api.rules import router as rules_router
from iceberg_api.scans.routes import router as scans_router
from iceberg_api.sources.cursor_routes import router as source_cursors_router
from iceberg_api.sources.routes import router as sources_router
from iceberg_api.sources.schedule_routes import router as schedules_router
from iceberg_api.users.routes import router as users_router
from iceberg_api.validation.routes import router as validation_policies_router
from iceberg_api.web import errors as web_errors
from iceberg_api.web.assets import STATIC_DIR
from iceberg_api.web.routes import router as web_router
from iceberg_api.web.security import security_headers_middleware

API_PREFIX = "/api/v1"

REQUEST_ID_HEADER = "X-Request-ID"

# An inbound correlation id is caller-controlled, and it lands in every log line
# for the request and in the response header. Accept only a bounded, boring
# token so a caller cannot bloat the log stream or smuggle framing characters
# into anything downstream that parses it; anything else gets a fresh id.
REQUEST_ID_MAX_LENGTH = 64
REQUEST_ID_RE = re.compile(rf"\A[A-Za-z0-9._-]{{1,{REQUEST_ID_MAX_LENGTH}}}\Z")

logger = structlog.get_logger()


def _resolve_request_id(supplied: str | None) -> str:
    if supplied is not None and REQUEST_ID_RE.match(supplied):
        return supplied
    return uuid.uuid4().hex


def create_app(settings: ApiSettings | None = None, *, background: bool = True) -> FastAPI:
    """Build the application.

    ``background=False`` leaves the scheduler and lease-reclaim loop unstarted —
    what tests want, since they drive those directly and would otherwise race a
    timer against their own fixtures.
    """
    configure_logging(role="api")

    # The packaged guidance catalog is validated here rather than on the first
    # request that needs it (ADR 0012 says loud failure, and lazily loud is not
    # loud). A packaging mistake is a deploy-time fact: it should stop the
    # rollout, not wait to surface as a 500 on somebody's finding page.
    load_catalog()

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        if not background:
            yield
            return
        async with background_maintenance(settings):
            yield

    app = FastAPI(title="IcebergSST API", lifespan=lifespan)

    # Registered before the request-context middleware, so it runs outermost and
    # stamps the headers on error responses the inner layers produce too.
    app.middleware("http")(security_headers_middleware(settings))

    @app.middleware("http")
    async def request_context(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        request_id = _resolve_request_id(request.headers.get(REQUEST_ID_HEADER))
        structlog.contextvars.bind_contextvars(request_id=request_id)
        try:
            response = await call_next(request)
        finally:
            structlog.contextvars.unbind_contextvars("request_id")
        response.headers[REQUEST_ID_HEADER] = request_id
        # Advisory RateLimit-* headers for requests that were allowed (#63); a
        # refused one carries them on the 429 itself. Here rather than in each
        # route so no rate-limited endpoint can forget them.
        ratelimit.attach_headers(request, response)
        return response

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/metrics")
    async def metrics() -> Response:
        return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)

    app.include_router(auth_router, prefix=API_PREFIX)
    app.include_router(correlation_router, prefix=API_PREFIX)
    app.include_router(engines_router, prefix=API_PREFIX)
    app.include_router(findings_router, prefix=API_PREFIX)
    app.include_router(notifications_router, prefix=API_PREFIX)
    app.include_router(remediation_router, prefix=API_PREFIX)
    app.include_router(rules_router, prefix=API_PREFIX)
    app.include_router(scans_router, prefix=API_PREFIX)
    app.include_router(schedules_router, prefix=API_PREFIX)
    app.include_router(source_cursors_router, prefix=API_PREFIX)
    app.include_router(sources_router, prefix=API_PREFIX)
    app.include_router(suppressions_router, prefix=API_PREFIX)
    app.include_router(users_router, prefix=API_PREFIX)
    app.include_router(validation_policies_router, prefix=API_PREFIX)

    # The browser surface, last: its routes live at the root, and mounting them
    # after the API guarantees no web path can shadow an /api/v1 one.
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    app.include_router(web_router)
    web_errors.register(app)

    return app
