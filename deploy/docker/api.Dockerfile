# syntax=docker/dockerfile:1
#
# The api role: FastAPI control plane. Owns Postgres and runs migrations.
# Build from the repository root:
#   docker build -f deploy/docker/api.Dockerfile -t icebergsst/api .

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
RUN uv sync --locked --no-dev --no-install-workspace --package iceberg-api

COPY . .
# --no-editable so the virtualenv is self-contained and survives being copied
# into the runtime stage; an editable install leaves .pth files pointing back
# at this stage's /src, which does not exist there.
RUN uv sync --locked --no-dev --no-editable --package iceberg-api


FROM python:3.14-slim AS runtime

# Unprivileged: nothing this role does needs root, and it parses input from the
# network.
RUN groupadd --system --gid 10001 iceberg \
    && useradd --system --uid 10001 --gid iceberg --no-create-home iceberg

COPY --from=builder --chown=iceberg:iceberg /src/.venv /app/.venv

ENV PATH="/app/.venv/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

USER iceberg
WORKDIR /app
EXPOSE 8000

# urllib rather than curl: the slim base ships no HTTP client and the
# virtualenv is already on PATH.
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz').read()"]

CMD ["uvicorn", "iceberg_api.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
