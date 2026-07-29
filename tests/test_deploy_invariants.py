"""Deployment-level invariants (ADR 0002).

`make up` and `docker build` are not runnable in CI, so the properties the
containers must have are asserted against the files that define them. These are
cheap checks for expensive mistakes: an engine handed a database URL is a
credential-isolation failure that no unit test would notice.
"""

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DOCKER_DIR = REPO_ROOT / "deploy" / "docker"
API_DOCKERFILE = DOCKER_DIR / "api.Dockerfile"
ENGINE_DOCKERFILE = DOCKER_DIR / "engine.Dockerfile"

#: Variable names that would give a process a route to Postgres.
DB_VARIABLE_RE = re.compile(r"\b(?:\w*DATABASE\w*|POSTGRES\w*|PG(?:HOST|USER|PASSWORD|DATABASE))\b")

#: Directives that put configuration into an image.
CONFIG_DIRECTIVE_RE = re.compile(r"^\s*(?:ENV|ARG)\s+(.*)$", re.MULTILINE)


def _configured_variables(dockerfile: Path) -> list[str]:
    """Every ENV/ARG assignment in a Dockerfile, line continuations included."""
    text = dockerfile.read_text().replace("\\\n", " ")
    return [match.group(1) for match in CONFIG_DIRECTIVE_RE.finditer(text)]


def test_both_role_images_exist() -> None:
    assert API_DOCKERFILE.is_file()
    assert ENGINE_DOCKERFILE.is_file()


def test_the_engine_image_carries_no_database_configuration() -> None:
    """The engine holds no DB credentials — the first invariant (ADR 0002)."""
    offenders = [
        line for line in _configured_variables(ENGINE_DOCKERFILE) if DB_VARIABLE_RE.search(line)
    ]

    assert offenders == [], f"engine image configures database access: {offenders}"


def test_the_engine_image_installs_no_database_driver() -> None:
    """``uv sync --package iceberg-engine`` is what keeps psycopg out of the image."""
    contents = ENGINE_DOCKERFILE.read_text()

    assert "--package iceberg-engine" in contents
    assert "psycopg" not in contents
    assert "alembic" not in contents


def test_neither_image_runs_as_root() -> None:
    for dockerfile in (API_DOCKERFILE, ENGINE_DOCKERFILE):
        assert "USER iceberg" in dockerfile.read_text(), dockerfile.name


def test_both_images_declare_a_healthcheck() -> None:
    """Compose and Kubernetes both need a readiness signal to gate on."""
    for dockerfile in (API_DOCKERFILE, ENGINE_DOCKERFILE):
        assert "HEALTHCHECK" in dockerfile.read_text(), dockerfile.name


def test_images_install_from_the_lock_file() -> None:
    """``--locked`` fails the build on a stale lock instead of resolving something else."""
    for dockerfile in (API_DOCKERFILE, ENGINE_DOCKERFILE):
        assert "uv sync --locked" in dockerfile.read_text(), dockerfile.name


def test_the_build_context_excludes_secrets_and_history() -> None:
    ignored = {
        line.strip()
        for line in (REPO_ROOT / ".dockerignore").read_text().splitlines()
        if line.strip() and not line.startswith("#")
    }

    assert {".env", ".git"} <= ignored


def test_only_the_api_image_owns_migrations() -> None:
    """Schema ownership is the api role's alone (docs/deployment.md § Migrations)."""
    assert "alembic" not in ENGINE_DOCKERFILE.read_text()
    assert "--package iceberg-api" in API_DOCKERFILE.read_text()
