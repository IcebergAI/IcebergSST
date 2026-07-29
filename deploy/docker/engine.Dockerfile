# syntax=docker/dockerfile:1
#
# The engine role: Dramatiq scanner worker. Talks to Redis and the API only.
# Build from the repository root:
#   docker build -f deploy/docker/engine.Dockerfile -t icebergsst/engine .
#
# ADR 0002: this image must never carry database credentials, a database
# client, or anything that could open a DB connection. deploy/docker/verify-images.sh
# asserts that; CI runs it on every build.

FROM ghcr.io/astral-sh/uv:0.8.17 AS uv

FROM python:3.14-slim AS builder

COPY --from=uv /uv /usr/local/bin/uv

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never

WORKDIR /src

# Manifests before sources, so editing code does not re-resolve dependencies.
COPY pyproject.toml uv.lock ./
COPY apps/api/pyproject.toml apps/api/
COPY apps/engine/pyproject.toml apps/engine/
COPY packages/core/pyproject.toml packages/core/
COPY packages/detect/pyproject.toml packages/detect/
COPY packages/connectors/pyproject.toml packages/connectors/
RUN uv sync --locked --no-dev --no-install-workspace --package iceberg-engine

COPY . .
# --no-editable: see the note in api.Dockerfile. Syncing the engine package
# alone is also what keeps the api's dependency graph — and with it any future
# database driver — out of this image.
RUN uv sync --locked --no-dev --no-editable --package iceberg-engine


FROM python:3.14-slim AS runtime

RUN groupadd --system --gid 10001 iceberg \
    && useradd --system --uid 10001 --gid iceberg --no-create-home iceberg

COPY --from=builder --chown=iceberg:iceberg /src/.venv /app/.venv

ENV PATH="/app/.venv/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    ICEBERG_METRICS_PORT=9191

USER iceberg
WORKDIR /app
EXPOSE 9191

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:9191/metrics').read()"]

# --processes 1: the worker binds a single Prometheus endpoint per container,
# so one worker process owns it. Throughput scales by adding replicas
# (compose --scale, or the Helm HPA), which is the documented model in
# docs/deployment.md.
CMD ["dramatiq", "iceberg_engine.worker:broker", "--processes", "1", "--threads", "8"]
