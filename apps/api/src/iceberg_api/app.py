"""FastAPI application factory.

Establishes what every route inherits — JSON logs with a per-request correlation
id (#67) and the Prometheus exposition endpoint — and mounts the routers.

Human-facing routes live under ``/api/v1`` from day one (docs/api.md
§ Conventions); ``/healthz`` and ``/metrics`` stay unversioned because operators
and scrapers are not API clients.
"""

import re
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, Request, Response
from iceberg_core import metrics as _metrics  # noqa: F401  # registers iceberg_* series
from iceberg_core.config import ApiSettings
from iceberg_core.logging import configure_logging
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from iceberg_api.auth.routes import router as auth_router
from iceberg_api.engines.routes import router as engines_router
from iceberg_api.maintenance import background_maintenance
from iceberg_api.scans.routes import router as scans_router
from iceberg_api.sources.routes import router as sources_router
from iceberg_api.sources.schedule_routes import router as schedules_router
from iceberg_api.users.routes import router as users_router

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

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        if not background:
            yield
            return
        async with background_maintenance(settings):
            yield

    app = FastAPI(title="IcebergSST API", lifespan=lifespan)

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
        return response

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/metrics")
    async def metrics() -> Response:
        return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)

    app.include_router(auth_router, prefix=API_PREFIX)
    app.include_router(engines_router, prefix=API_PREFIX)
    app.include_router(scans_router, prefix=API_PREFIX)
    app.include_router(schedules_router, prefix=API_PREFIX)
    app.include_router(sources_router, prefix=API_PREFIX)
    app.include_router(users_router, prefix=API_PREFIX)

    return app
