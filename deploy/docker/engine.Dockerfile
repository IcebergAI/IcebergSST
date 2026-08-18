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

# Same path as the runtime stage — a venv is not relocatable. See api.Dockerfile.
WORKDIR /app

# Dependency layer first — see api.Dockerfile for why. --package iceberg-engine
# means the api's dependencies are not installed here: no Postgres driver, no
# alembic, and no ORM, because iceberg-core carries sqlmodel in its `db` extra
# and only apps/api asks for it.
COPY pyproject.toml uv.lock ./
COPY apps/api/pyproject.toml apps/api/
COPY apps/engine/pyproject.toml apps/engine/
COPY packages/core/pyproject.toml packages/core/
COPY packages/detect/pyproject.toml packages/detect/
COPY packages/connectors/pyproject.toml packages/connectors/
RUN uv sync --locked --no-dev --no-editable --no-install-workspace --package iceberg-engine

COPY apps/ apps/
COPY packages/ packages/
RUN uv sync --locked --no-dev --no-editable --package iceberg-engine


FROM python:3.14-slim AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/app/.venv/bin:$PATH" \
    ICEBERG_METRICS_PORT=9191

RUN useradd --create-home --uid 10001 iceberg

WORKDIR /app
# The venv alone — see api.Dockerfile. Here it also carries the ADR 0002
# boundary: deploy/docker/verify-images.sh proves no database package is
# importable in this image, which is only true because nothing copies one in.
COPY --from=builder --chown=iceberg:iceberg /app/.venv /app/.venv

USER iceberg
EXPOSE 9191

# Engines have no HTTP API, so the metrics endpoint is the liveness signal: if the
# process is up and its Prometheus server answers, the worker is alive.
# The port from the same env var the worker reads, so overriding
# ICEBERG_METRICS_PORT does not leave the probe checking a port nobody serves.
HEALTHCHECK --interval=10s --timeout=3s --start-period=20s --retries=5 \
    CMD ["python", "-c", "import os, urllib.request; urllib.request.urlopen(f\"http://127.0.0.1:{os.environ.get('ICEBERG_METRICS_PORT', '9191')}/metrics\").read()"]

# Deliberately not the `dramatiq` CLI: the worker starts its own consumer so that
# importing the module stays side-effect free (see iceberg_engine.worker.main),
# and so SIGTERM is a clean shutdown that finishes leased work first.
CMD ["python", "-m", "iceberg_engine.worker"]
