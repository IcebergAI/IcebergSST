"""FastAPI application factory — observability baseline only (issue #67).

Real routes arrive with M1; this module establishes the skeleton every route
will inherit: JSON logs with a per-request correlation id and the Prometheus
exposition endpoint.
"""

import uuid
from collections.abc import Awaitable, Callable

import structlog
from fastapi import FastAPI, Request, Response
from iceberg_core import metrics as _metrics  # noqa: F401  # registers iceberg_* series
from iceberg_core.logging import configure_logging
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

REQUEST_ID_HEADER = "X-Request-ID"

logger = structlog.get_logger()


def create_app() -> FastAPI:
    configure_logging(role="api")
    app = FastAPI(title="IcebergSST API")

    @app.middleware("http")
    async def request_context(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        request_id = request.headers.get(REQUEST_ID_HEADER) or uuid.uuid4().hex
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

    return app
