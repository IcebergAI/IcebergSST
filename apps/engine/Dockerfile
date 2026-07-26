# syntax=docker/dockerfile:1
# Scanner engine (issue #20). Build from the repository root:
#   docker build -f apps/engine/Dockerfile .
#
# This image deliberately contains **no database driver and no schema**: the
# engine depends on bare `iceberg-core`, not `iceberg-core[db]`, so asyncpg and
# sqlmodel are never installed here (ADR 0002). `make verify-engine-image`
# asserts that. Nothing below copies alembic.ini, migrations/, or apps/api.

FROM ghcr.io/astral-sh/uv:python3.14-trixie-slim AS builder

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never

WORKDIR /app

COPY pyproject.toml uv.lock ./
COPY packages/ packages/
COPY apps/ apps/

RUN uv sync --locked --no-dev --no-editable --package iceberg-engine


FROM python:3.14-slim-trixie AS runtime

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app
COPY --from=builder /app/.venv /app/.venv

RUN useradd --system --create-home --uid 10001 iceberg
USER iceberg

# Prometheus scrape target (iceberg_core.config.EngineSettings.metrics_port).
EXPOSE 9191

# The dramatiq CLI imports this module and expects a registered global broker,
# which iceberg_engine.worker now sets up at import time.
CMD ["dramatiq", "iceberg_engine.worker"]
