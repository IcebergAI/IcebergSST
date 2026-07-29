# syntax=docker/dockerfile:1
#
# The engine image: connectors, detection, redaction. It reaches Redis and the
# API and nothing else — no database driver, no database configuration, no
# migrations (ADR 0002). That is a property of this file as much as of the code:
# tests/test_deploy_invariants.py fails if a DATABASE/POSTGRES variable appears
# here or in the compose service.
#
# Build from the repository root:
#   docker build -f deploy/docker/engine.Dockerfile -t icebergsst/engine .

FROM python:3.14-slim AS builder

COPY --from=ghcr.io/astral-sh/uv:0.8.17 /uv /usr/local/bin/uv

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never

WORKDIR /app

# Dependency layer first — see api.Dockerfile for why. --package iceberg-engine
# means the api's dependencies (and its Postgres driver) are not installed here.
COPY pyproject.toml uv.lock ./
COPY apps/api/pyproject.toml apps/api/
COPY apps/engine/pyproject.toml apps/engine/
COPY packages/core/pyproject.toml packages/core/
COPY packages/detect/pyproject.toml packages/detect/
COPY packages/connectors/pyproject.toml packages/connectors/
RUN uv sync --locked --no-dev --no-install-workspace --package iceberg-engine

COPY apps/ apps/
COPY packages/ packages/
RUN uv sync --locked --no-dev --package iceberg-engine


FROM python:3.14-slim AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/app/.venv/bin:$PATH" \
    ICEBERG_METRICS_PORT=9191

RUN useradd --create-home --uid 10001 iceberg

WORKDIR /app
COPY --from=builder --chown=iceberg:iceberg /app /app

USER iceberg
EXPOSE 9191

# Engines have no HTTP API, so the metrics endpoint is the liveness signal: if the
# process is up and its Prometheus server answers, the worker is alive.
HEALTHCHECK --interval=10s --timeout=3s --start-period=20s --retries=5 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:9191/metrics').read()"]

# Replaced by `dramatiq iceberg_engine.worker` when the consumer lands (#50).
CMD ["python", "-m", "iceberg_engine.worker"]
