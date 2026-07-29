"""Deployment-level invariants (ADR 0002).

`make up` and `docker build` are not runnable in CI, so the properties the
containers must have are asserted against the files that define them. These are
cheap checks for expensive mistakes: an engine handed a database URL is a
credential-isolation failure that no unit test would notice.
"""

import importlib
import re
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
DOCKER_DIR = REPO_ROOT / "deploy" / "docker"
API_DOCKERFILE = DOCKER_DIR / "api.Dockerfile"
ENGINE_DOCKERFILE = DOCKER_DIR / "engine.Dockerfile"
COMPOSE_FILE = REPO_ROOT / "deploy" / "compose" / "docker-compose.yml"
ENV_EXAMPLE = REPO_ROOT / ".env.example"

#: ${VAR}, ${VAR:-default}, ${VAR:?message}
INTERPOLATION_RE = re.compile(r"\$\{([A-Z_][A-Z0-9_]*)")

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


@pytest.fixture(name="compose", scope="module")
def compose_fixture() -> dict[str, Any]:
    loaded: dict[str, Any] = yaml.safe_load(COMPOSE_FILE.read_text())
    return loaded


def _service(compose: dict[str, Any], name: str) -> dict[str, Any]:
    service: dict[str, Any] = compose["services"][name]
    return service


def _environment(service: dict[str, Any]) -> dict[str, str]:
    """Service environment as a mapping, with the shared anchor merged in.

    PyYAML expands ``<<`` merge keys for mappings, so an inherited variable is
    visible here exactly as Compose would see it.
    """
    environment = service.get("environment", {})
    if isinstance(environment, list):
        pairs = [item.split("=", 1) for item in environment]
        return {key: value for key, *rest in pairs for value in (rest or [""])}
    return {str(key): str(value) for key, value in environment.items()}


def test_the_stack_is_the_four_documented_services(compose: dict[str, Any]) -> None:
    assert set(compose["services"]) == {"api", "engine", "postgres", "redis"}


def test_only_the_api_service_is_given_a_database(compose: dict[str, Any]) -> None:
    """The invariant, at the deployment layer (ADR 0002)."""
    engine_env = _environment(_service(compose, "engine"))

    offenders = sorted(name for name in engine_env if DB_VARIABLE_RE.search(name))

    assert offenders == [], f"engine service is configured for the database: {offenders}"
    assert "ICEBERG_DATABASE_URL" in _environment(_service(compose, "api"))


def test_the_engine_service_is_not_wired_to_postgres_at_all(compose: dict[str, Any]) -> None:
    assert "postgres" not in _service(compose, "engine").get("depends_on", {})


def test_the_engine_never_receives_the_master_key(compose: dict[str, Any]) -> None:
    """The pepper arrives per task in the lease response, not as config (ADR 0007)."""
    engine_env = _environment(_service(compose, "engine"))

    assert "ICEBERG_MASTER_KEY" not in engine_env
    assert "ICEBERG_FINGERPRINT_PEPPER_REF" not in engine_env


def test_the_engine_service_can_be_scaled(compose: dict[str, Any]) -> None:
    """`--scale engine=N` needs no fixed name and no published host port."""
    engine = _service(compose, "engine")

    assert "container_name" not in engine
    assert "ports" not in engine


def test_infrastructure_services_report_health_and_the_apps_wait_for_it(
    compose: dict[str, Any],
) -> None:
    for name in ("postgres", "redis"):
        assert "healthcheck" in _service(compose, name), name

    api_dependencies = _service(compose, "api")["depends_on"]
    assert {"postgres", "redis"} == set(api_dependencies)
    assert all(
        dependency["condition"] == "service_healthy" for dependency in api_dependencies.values()
    )


def test_no_secret_is_committed_in_the_compose_file(compose: dict[str, Any]) -> None:
    """Every credential is a ${VARIABLE} reference resolved from .env."""
    secretish = re.compile(r"PASSWORD|MASTER_KEY|TOKEN|PEPPER", re.IGNORECASE)

    for name in compose["services"]:
        for variable, value in _environment(_service(compose, name)).items():
            if secretish.search(variable):
                assert "${" in value, f"{name}.{variable} looks like a committed secret"


def test_compose_and_dockerfiles_agree_on_the_build_context(compose: dict[str, Any]) -> None:
    """The build context is the workspace root, because uv.lock lives there."""
    for name, dockerfile in (("api", "api.Dockerfile"), ("engine", "engine.Dockerfile")):
        build = _service(compose, name)["build"]
        assert build["context"] == "../.."
        assert build["dockerfile"] == f"deploy/docker/{dockerfile}"


def _documented_variables() -> set[str]:
    return {
        line.split("=", 1)[0].strip()
        for line in ENV_EXAMPLE.read_text().splitlines()
        if "=" in line and not line.strip().startswith("#")
    }


def test_env_example_documents_every_variable_the_stack_interpolates() -> None:
    """A variable compose reads but .env.example omits is a stack that will not start."""
    directives = "\n".join(
        line for line in COMPOSE_FILE.read_text().splitlines() if not line.strip().startswith("#")
    )
    interpolated = set(INTERPOLATION_RE.findall(directives))
    documented = _documented_variables()

    assert interpolated <= documented, sorted(interpolated - documented)


def test_env_example_contains_no_real_values() -> None:
    """Placeholders only — this file is committed."""
    for line in ENV_EXAMPLE.read_text().splitlines():
        name, separator, value = line.partition("=")
        if separator and re.search(r"PASSWORD|MASTER_KEY|TOKEN|PEPPER", name):
            assert value.strip() == "CHANGE_ME", f"{name} has a committed value"


def test_init_env_fills_every_placeholder_with_a_working_value(tmp_path: Path) -> None:
    """The generated pepper ref must open with the generated master key.

    Generating them independently would produce a file that looks right and fails
    on the first fingerprint.
    """
    from iceberg_core.secrets import EnvKeyBackend
    from iceberg_core.secrets.env_key import decode_master_key

    sys.path.insert(0, str(REPO_ROOT / "deploy" / "compose"))
    init_env = importlib.import_module("init-env")

    rendered, filled = init_env.render(ENV_EXAMPLE.read_text())
    values = dict(
        line.split("=", 1) for line in rendered.splitlines() if "=" in line and line[0] != "#"
    )

    assert set(filled) == {
        "POSTGRES_PASSWORD",
        "REDIS_PASSWORD",
        "ICEBERG_ENGINE_TOKEN",
        "ICEBERG_MASTER_KEY",
        "ICEBERG_SESSION_SECRET",
        "ICEBERG_FINGERPRINT_PEPPER_REF",
    }
    # What is left is what only the operator can supply — the OIDC client secret
    # is issued by their identity provider, not generated here.
    outstanding = {name for name, value in values.items() if value == "CHANGE_ME"}
    assert outstanding == {"ICEBERG_OIDC_CLIENT_SECRET"}

    store = EnvKeyBackend(
        decode_master_key(values["ICEBERG_MASTER_KEY"]),
        pepper_ref=values["ICEBERG_FINGERPRINT_PEPPER_REF"],
    )
    assert len(store.get_pepper()) == 32


def test_init_env_refuses_to_overwrite_an_existing_env(tmp_path: Path) -> None:
    """Losing the master key makes every stored credential ref undecryptable."""
    sys.path.insert(0, str(REPO_ROOT / "deploy" / "compose"))
    init_env = importlib.import_module("init-env")
    existing = tmp_path / ".env"
    existing.write_text("ICEBERG_MASTER_KEY=precious\n")

    code = init_env.main(["--example", str(ENV_EXAMPLE), "--output", str(existing)])

    assert code == 1
    assert existing.read_text() == "ICEBERG_MASTER_KEY=precious\n"
