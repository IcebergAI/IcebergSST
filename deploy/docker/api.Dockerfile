# syntax=docker/dockerfile:1
#
# The api image: FastAPI control plane, HTMX UI, scheduler, notifications — and
# the only role that talks to Postgres or runs migrations.
#
# Build from the repository root, which is the uv workspace root:
#   docker build -f deploy/docker/api.Dockerfile -t icebergsst/api .

FROM python:3.14-slim AS builder

# Pinned rather than :latest so an image rebuilt in six months resolves the same
# way the lock file was written.
COPY --from=ghcr.io/astral-sh/uv:0.8.17 /uv /usr/local/bin/uv

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never

# The builder works at the same path the runtime stage will use. A venv is not
# relocatable: uv writes `#!/app/.venv/bin/python` into every console script, so
# building at /src and copying to /app leaves `uvicorn` with a shebang pointing at
# a directory that does not exist — "exec: no such file or directory" at start.
WORKDIR /app

# Dependencies first, from the lock file and manifests alone: editing application
# code then costs a layer, not a resolve. --locked fails the build if uv.lock is
# out of date rather than silently resolving something else.
COPY pyproject.toml uv.lock ./
COPY apps/api/pyproject.toml apps/api/
COPY apps/engine/pyproject.toml apps/engine/
COPY packages/core/pyproject.toml packages/core/
COPY packages/detect/pyproject.toml packages/detect/
COPY packages/connectors/pyproject.toml packages/connectors/
RUN uv sync --locked --no-dev --no-editable --no-install-workspace --package iceberg-api

COPY apps/ apps/
COPY packages/ packages/
# --no-editable installs the workspace packages into the venv proper rather than
# linking back at /src, so the venv is self-contained and the runtime stage can
# take it alone. Templates, static assets, migrations and alembic.ini all live
# under src/iceberg_api/ and travel in the wheel with it.
RUN uv sync --locked --no-dev --no-editable --package iceberg-api


FROM python:3.14-slim AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/app/.venv/bin:$PATH"

# A fixed uid keeps file ownership predictable when a volume is mounted.
RUN useradd --create-home --uid 10001 iceberg

WORKDIR /app
# The venv and nothing else: no source tree, no uv, no build dependencies. What
# is not in the image cannot be imported by accident or read by an attacker.
COPY --from=builder --chown=iceberg:iceberg /app/.venv /app/.venv

USER iceberg
EXPOSE 8000

# Reports the same readiness the load balancer and compose depend on. Uses the
# stdlib rather than adding curl to the image for one request.
HEALTHCHECK --interval=10s --timeout=3s --start-period=20s --retries=5 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz').read()"]

# Migrations are a deliberate, separate step — `make migrate` in compose, a
# pre-upgrade Job in Helm. An image that migrates on start would race its own
# replicas and surprise an operator during a rollback.
CMD ["uvicorn", "iceberg_api.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
