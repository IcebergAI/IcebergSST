"""FastAPI application factory.

Establishes what every route inherits — JSON logs with a per-request correlation
id (#67) and the Prometheus exposition endpoint — and mounts the routers.

Human-facing routes live under ``/api/v1`` from day one (docs/api.md
§ Conventions); ``/healthz`` and ``/metrics`` stay unversioned because operators
and scrapers are not API clients.
"""

import re
import uuid
from collections.abc import Awaitable, Callable

import structlog
from fastapi import FastAPI, Request, Response
from iceberg_core import metrics as _metrics  # noqa: F401  # registers iceberg_* series
from iceberg_core.logging import configure_logging
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from iceberg_api.auth.routes import router as auth_router
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


def create_app() -> FastAPI:
    configure_logging(role="api")
    app = FastAPI(title="IcebergSST API")

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
    app.include_router(users_router, prefix=API_PREFIX)

    return app
