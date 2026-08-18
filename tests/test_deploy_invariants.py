"""Deployment-level invariants (ADR 0002).

These read the files that define the containers rather than the containers: cheap
checks for expensive mistakes, running in the ordinary unit-test suite where an
engine handed a database URL fails in seconds.

They are the fast half of the story. The slow half is two scripts that need tools
this suite does not have:

* ``deploy/docker/verify-images.sh`` (``make images-verify``) builds both images
  and probes the artefacts — no database package importable in the engine, both
  entrypoints serving, both running non-root (#81).
* ``deploy/helm/verify-chart.sh`` (``make helm-verify``) renders the chart and
  checks the manifests — the engine mounting only its own Secret, migrations as a
  pre-upgrade hook, every workload unprivileged (#61, #62).

Reading a Dockerfile cannot tell you an image builds, and a text check cannot
tell you sqlalchemy is genuinely absent rather than merely unmentioned. Keep
both halves: this file catches the mistake in the edit, those scripts catch it in
the result.
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
HELM_DIR = REPO_ROOT / "deploy" / "helm"
CHART_DIR = HELM_DIR / "icebergsst"

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


def _instructions(dockerfile: Path) -> str:
    """The Dockerfile with comments stripped.

    These files explain themselves at length, and several comments name the very
    packages the checks below forbid — "no Postgres driver, no alembic" is the
    engine Dockerfile stating the invariant, not breaking it. Substring checks
    over the raw text would read prose as instruction and fail on a comment that
    got the rule right.
    """
    return "\n".join(
        line for line in dockerfile.read_text().splitlines() if not line.lstrip().startswith("#")
    )


#: Helm's block comments, ``{{/* … */}}``.
HELM_COMMENT_RE = re.compile(r"\{\{-?/\*.*?\*/-?\}\}", re.DOTALL)


def _template_instructions(template: Path) -> str:
    """A chart template with both comment forms stripped.

    Same reasoning as :func:`_instructions` for Dockerfiles: the engine
    Deployment's header states "no database URL, no master key" as the rule it
    follows, and a substring check over the raw text would read that as a breach.
    """
    text = HELM_COMMENT_RE.sub("", template.read_text())
    return "\n".join(line for line in text.splitlines() if not line.strip().startswith("#"))


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
    """``uv sync --package iceberg-engine`` is what keeps psycopg out of the image.

    The stronger form of this — proving nothing database-shaped is importable in
    the built image — is in ``deploy/docker/verify-images.sh``.
    """
    contents = _instructions(ENGINE_DOCKERFILE)

    assert "--package iceberg-engine" in contents
    assert "psycopg" not in contents
    assert "alembic" not in contents


def test_the_engine_never_asks_for_the_orm_extra() -> None:
    """``iceberg-core[db]`` carries sqlmodel; only the api role may depend on it.

    This is what makes the image probe pass: the engine's dependency closure has
    no ORM in it, so none is installed, so none can be imported (ADR 0002).
    """
    engine_manifest = (REPO_ROOT / "apps" / "engine" / "pyproject.toml").read_text()
    api_manifest = (REPO_ROOT / "apps" / "api" / "pyproject.toml").read_text()

    assert "iceberg-core[db]" not in engine_manifest
    assert "iceberg-core[db]" in api_manifest

    core_manifest = (REPO_ROOT / "packages" / "core" / "pyproject.toml").read_text()
    base, _, extras = core_manifest.partition("[project.optional-dependencies]")
    assert "sqlmodel" not in base, "sqlmodel must stay in the db extra, not core's base deps"
    assert "sqlmodel" in extras


def test_the_engine_chart_template_carries_no_database_configuration() -> None:
    """ADR 0002 at the Kubernetes layer, checked in the template source.

    The rendered form of this — the engine Deployment referencing only its own
    Secret — is asserted by ``deploy/helm/verify-chart.sh``. This one runs in the
    ordinary suite, so mounting the api Secret from the engine fails in seconds
    rather than waiting for a job that needs Helm.
    """
    instructions = _template_instructions(CHART_DIR / "templates" / "engine-deployment.yaml")

    assert "apiSecretName" not in instructions, "engine Deployment references the api's Secret"
    assert "engineSecretName" in instructions
    offenders = sorted(set(DB_VARIABLE_RE.findall(instructions)))
    assert offenders == [], f"engine chart template mentions database config: {offenders}"


def test_only_the_api_chart_template_runs_migrations() -> None:
    job = (CHART_DIR / "templates" / "migration-job.yaml").read_text()

    assert "pre-install,pre-upgrade" in job
    assert '"python", "-m", "iceberg_api", "migrate"' in job
    # The api image, because it is the only one with alembic and a driver.
    assert '"role" "api"' in job

    engine = (CHART_DIR / "templates" / "engine-deployment.yaml").read_text()
    assert "migrate" not in engine


#: ``"helm.sh/hook-weight": "-10"`` and friends, as written in the templates.
HOOK_WEIGHT_RE = re.compile(r'"helm\.sh/hook-weight":\s*"(-?\d+)"')


def _hook_weight(template: Path) -> int:
    text = template.read_text()
    assert "pre-install,pre-upgrade" in text, f"{template.name} is not a pre-install hook"
    match = HOOK_WEIGHT_RE.search(text)
    assert match is not None, f"{template.name} declares no hook weight"
    return int(match.group(1))


def test_the_migration_jobs_configuration_is_created_before_it_runs() -> None:
    """Helm creates every hook before any ordinary manifest.

    So a hook Job whose ``envFrom`` names a plain ConfigMap or Secret has nothing
    to read on a fresh install and sits in ``CreateContainerConfigError`` until
    the deadline — and on an upgrade it migrates using the *previous* release's
    configuration. The ordering is the weights, so the weights are the assertion.
    The rendered form is in ``deploy/helm/verify-chart.sh``.
    """
    templates = CHART_DIR / "templates"
    job_weight = _hook_weight(templates / "migration-job.yaml")

    assert _hook_weight(templates / "configmap.yaml") < job_weight
    assert _hook_weight(templates / "secrets.yaml") < job_weight


def test_the_hook_configuration_outlives_the_job_that_needed_it() -> None:
    """Both Deployments read them for the life of the release.

    ``hook-succeeded`` on either would delete the ConfigMap or the api Secret the
    moment migrations finished, which is the same outage as never creating them.
    """
    for name in ("configmap.yaml", "secrets.yaml"):
        instructions = _template_instructions(CHART_DIR / "templates" / name)
        policy = re.search(r'"helm\.sh/hook-delete-policy":\s*(.+)', instructions)
        assert policy is not None, name
        assert policy.group(1).strip() == "before-hook-creation", name


def test_both_pod_templates_checksum_the_secret_they_read() -> None:
    """A Secret-only ``helm upgrade`` must roll pods, exactly as a ConfigMap one does.

    Rotating ``sessionSecret``, opening a pepper-rotation window or reissuing an
    engine token changes nothing but the Secret, and a replica keeps the
    environment it started with — so without this the release looks applied when
    it is not. Guarded on the existingSecret toggles: when the Secret is managed
    out of band the chart does not render it, and a checksum over the template
    would be a constant.
    """
    for role, toggle in (("api", "existingApiSecret"), ("engine", "existingEngineSecret")):
        template = _template_instructions(CHART_DIR / "templates" / f"{role}-deployment.yaml")

        assert "checksum/secret" in template, role
        assert f"if not .Values.secrets.{toggle}" in template, role
        # Scoped to the role's own values: a hash over the whole rendered
        # secrets.yaml made rotating one role's secret roll the *other* role's
        # fleet too (an engine-token reissue restarting every api pod, an api
        # session-secret rotation restarting engines mid-lease).
        assert f"toYaml .Values.secrets.{role} | sha256sum" in template, role


def test_the_chart_separates_the_two_roles_secrets() -> None:
    """One Secret per role is what makes "engines cannot read the api's" a rule a
    cluster can enforce, rather than only a property of these templates."""
    secrets = (CHART_DIR / "templates" / "secrets.yaml").read_text()

    assert "existingApiSecret" in secrets
    assert "existingEngineSecret" in secrets
    api_half, _, engine_half = secrets.partition("-engine")
    assert "ICEBERG_MASTER_KEY" in api_half
    assert "ICEBERG_MASTER_KEY" not in engine_half
    assert "ICEBERG_DATABASE_URL" not in engine_half


def test_the_chart_verification_runs_in_ci() -> None:
    script = HELM_DIR / "verify-chart.sh"
    assert script.is_file()
    assert script.stat().st_mode & 0o111, "verify-chart.sh must be executable"

    workflow = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text()
    assert "make helm-verify" in workflow
    assert "helm-verify:" in (REPO_ROOT / "Makefile").read_text()


def test_the_image_verification_runs_in_ci() -> None:
    """The artefact-level checks are only worth having if they actually run.

    ``verify-images.sh`` is the thing that proves the images build and that the
    engine cannot import an ORM. A green PR should mean both were re-checked, so
    the CI job that does it is asserted here rather than trusted (#81).
    """
    script = DOCKER_DIR / "verify-images.sh"
    assert script.is_file()
    assert script.stat().st_mode & 0o111, "verify-images.sh must be executable"

    workflow = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text()
    assert "make images-verify" in workflow

    makefile = (REPO_ROOT / "Makefile").read_text()
    assert "images-verify:" in makefile


def test_migrations_are_exercised_against_postgres_in_ci() -> None:
    """SQLite standing in for Postgres proves the ops execute, not that they are valid.

    ``apps/api/tests/test_migrations.py`` runs on SQLite, where alembic takes the
    batch-copy path for an ALTER, JSONB is ordinary JSON and a partial index is
    spelled differently. Without a leg that applies the same revisions to a real
    Postgres, the first machine to execute the Postgres DDL is the pre-upgrade
    Job in production (#126).
    """
    workflow = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text()

    assert "image: postgres:" in workflow, "no Postgres service container in CI"
    assert "python -m iceberg_api migrate" in workflow
    # Reversibility is what makes a rollback possible, so the leg goes both ways.
    assert "downgrade base" in workflow


def test_ci_actions_are_pinned_to_a_commit() -> None:
    """A tag is a pointer its owner can move; a SHA is the artefact.

    This repository pins everything else it consumes — the uv version in both
    Dockerfiles, the gitleaks image, ``uv sync --locked`` — and a step that runs
    in a secret scanner's CI is not the place to float on a mutable major tag.
    """
    workflow = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text()
    floating = re.findall(r"uses:\s*(\S+@(?!\w{40}\b)\S+)", workflow)

    assert floating == [], f"actions pinned to a tag rather than a commit: {floating}"


def test_the_chart_does_not_advertise_an_unimplemented_secret_backend() -> None:
    """``secretStoreBackend: vault`` CrashLoops every api pod after a clean upgrade.

    ``build_secret_store`` raises for it — a documented seam, not a backend. The
    values file is where an operator decides, so it has to say so; .env.example
    already does.
    """
    lines = (CHART_DIR / "values.yaml").read_text().splitlines()
    setting = next(
        i for i, line in enumerate(lines) if line.strip().startswith("secretStoreBackend")
    )
    comment: list[str] = []
    while setting and lines[setting - 1].strip().startswith("#"):
        setting -= 1
        comment.insert(0, lines[setting])
    block = " ".join(comment)

    assert "`vault`" in block, "the values file no longer mentions the vault backend"
    assert "not yet implemented" in block


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
    assert "alembic" not in _instructions(ENGINE_DOCKERFILE)
    assert "--package iceberg-api" in _instructions(API_DOCKERFILE)


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


def test_the_engine_service_is_given_time_to_finish_its_task(compose: dict[str, Any]) -> None:
    """worker.py catches SIGTERM and finishes the task it leased.

    Docker's default 10s would SIGKILL a fetch in progress, and the scan then
    waits out its 300s lease before anything reclaims it — so the shutdown the
    worker documents is only clean with this set. Matches
    ``terminationGracePeriodSeconds`` in the chart, deliberately.
    """
    chart_grace = re.search(
        r"terminationGracePeriodSeconds:\s*(\d+)",
        (CHART_DIR / "templates" / "engine-deployment.yaml").read_text(),
    )

    assert chart_grace is not None
    assert _service(compose, "engine")["stop_grace_period"] == f"{chart_grace.group(1)}s"


def test_the_engine_service_waits_for_a_token_that_only_the_api_can_mint(
    compose: dict[str, Any],
) -> None:
    """The dev stack's one unresolvable ordering, made explicit.

    An engine refuses to start without a token; only the api can mint one, and
    only against a schema that does not exist until ``make up`` has migrated. The
    profile is what lets that first ``up`` succeed — without it the stack waits on
    a container that cannot start, and the answer is never to hand the engine a
    token the API never issued.
    """
    assert _service(compose, "engine")["profiles"] == ["engine"]

    script = REPO_ROOT / "deploy" / "compose" / "engine-token.sh"
    assert script.is_file()
    assert script.stat().st_mode & 0o111, "engine-token.sh must be executable"
    assert "mint-engine-token" in script.read_text()


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
    secretish = re.compile(
        r"PASSWORD|MASTER_KEY|TOKEN|PEPPER|SESSION_SECRET|CLIENT_SECRET", re.IGNORECASE
    )

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


#: Variables Compose reads itself rather than interpolating into a service, so
#: they appear in .env with no ``${…}`` anywhere in the compose file to match.
#: COMPOSE_PROFILES is what keeps the engine out of the stack until it has a
#: token; engine-token.sh sets it.
COMPOSE_OWN_VARIABLES = {"COMPOSE_PROFILES"}


def test_env_example_and_the_compose_file_agree_on_the_variables() -> None:
    """A variable compose reads but .env.example omits is a stack that will not
    start; one .env.example documents but compose never delivers is a tunable an
    operator sets to no effect (the session TTL once fell in that second bucket).
    """
    directives = "\n".join(
        line for line in COMPOSE_FILE.read_text().splitlines() if not line.strip().startswith("#")
    )
    interpolated = set(INTERPOLATION_RE.findall(directives))
    documented = _documented_variables() - COMPOSE_OWN_VARIABLES

    assert interpolated <= documented, sorted(interpolated - documented)
    assert documented <= interpolated, sorted(documented - interpolated)


def test_env_example_contains_no_real_values() -> None:
    """Placeholders only — this file is committed."""
    for line in ENV_EXAMPLE.read_text().splitlines():
        name, separator, value = line.partition("=")
        if separator and re.search(
            r"PASSWORD|MASTER_KEY|TOKEN|PEPPER|SESSION_SECRET|CLIENT_SECRET", name
        ):
            # CHANGE_ME for values init-env generates; blank for the engine token,
            # which is minted by the API rather than generated (a placeholder there
            # would authenticate with a value the API never issued).
            assert value.strip() in ("CHANGE_ME", ""), f"{name} has a committed value"


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
        "ICEBERG_MASTER_KEY",
        "ICEBERG_SESSION_SECRET",
        "ICEBERG_FINGERPRINT_PEPPER_REF",
    }
    # What is left is what only the operator can supply — the OIDC client secret is
    # issued by their identity provider, and the engine token is minted by the API;
    # neither can be generated here.
    outstanding = {name for name, value in values.items() if value == "CHANGE_ME"}
    assert outstanding == {"ICEBERG_OIDC_CLIENT_SECRET"}
    assert values["ICEBERG_ENGINE_TOKEN"] == ""  # blank until an operator mints one

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


def test_the_api_image_ships_the_console_and_its_assets() -> None:
    """The console is served from inside the package, so the image must carry it.

    ``.dockerignore`` exists to keep secrets and build noise out of the layer, and
    a pattern broad enough to also drop the templates or the vendored fonts would
    produce an API that boots, answers `/healthz`, and renders an unstyled page
    with no JavaScript — a failure nobody would attribute to the Dockerfile.
    """
    web_root = REPO_ROOT / "apps" / "api" / "src" / "iceberg_api" / "web"
    ignored = {
        line.strip()
        for line in (REPO_ROOT / ".dockerignore").read_text().splitlines()
        if line.strip() and not line.startswith("#")
    }

    # The whole apps/ tree goes in, which is what carries templates and static.
    assert "COPY apps/ apps/" in API_DOCKERFILE.read_text()

    for required in ("templates/base.html", "static/assets.lock.json", "static/css/iceberg.css"):
        assert (web_root / required).is_file(), f"{required} is missing from the package"

    for pattern in ("**/static", "**/templates", "static", "templates", "**/*.css", "**/*.js"):
        assert pattern not in ignored, f".dockerignore would strip the console: {pattern}"
