# syntax=docker/dockerfile:1
# API control plane (issue #20). Build from the repository root:
#   docker build -f apps/api/Dockerfile .

FROM ghcr.io/astral-sh/uv:python3.14-trixie-slim AS builder

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never

WORKDIR /app

# Workspace members must all be present for uv to resolve the workspace, even
# though --package installs only this one.
COPY pyproject.toml uv.lock ./
COPY packages/ packages/
COPY apps/ apps/

# --no-dev keeps test tooling out; --no-editable copies real packages into the
# venv so the runtime stage needs no source tree.
RUN uv sync --locked --no-dev --no-editable --package iceberg-api


FROM python:3.14-slim-trixie AS runtime

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Alembic lives with the api: it owns the schema and is the only role that
# migrates (docs/deployment.md).
WORKDIR /app
COPY --from=builder /app/.venv /app/.venv
COPY alembic.ini ./
COPY migrations/ migrations/

RUN useradd --system --create-home --uid 10001 iceberg
USER iceberg

EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=5 \
    CMD python -c "import urllib.request as u; u.urlopen('http://127.0.0.1:8000/healthz')"

# --factory because app.py exposes create_app(), not a module-level `app`.
CMD ["uvicorn", "--factory", "iceberg_api.app:create_app", "--host", "0.0.0.0", "--port", "8000"]
