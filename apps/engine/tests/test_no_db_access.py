"""The engine boundary, enforced (ADR 0002, invariant 1).

A static import scan would miss a transitive path — ``iceberg_engine`` importing
some helper that itself imports the session module. So this runs a real
interpreter, imports the engine, and inspects the resulting module graph.

The probe covers the *finished* worker (#52): the actor, the task runner, the API
client, and the suppression pre-filter — which is the whole of what an engine
process loads. The interesting risk is transitive: `runner` imports
`iceberg_connectors`, which imports `iceberg_core.fingerprint`, and one careless
`from iceberg_core.models import ...` anywhere down that chain would hand a worker
the ORM. A static grep would miss it; importing for real does not.
"""

import json
import subprocess
import sys

# Modules that exist to talk to Postgres. None of them may be reachable from an
# engine process, at any import depth.
DB_MODULES = ("iceberg_core.db", "iceberg_core.models", "sqlmodel", "sqlalchemy", "alembic")

PROBE = """
import importlib
import json
import sys

importlib.import_module("iceberg_engine")
importlib.import_module("iceberg_engine.worker")
importlib.import_module("iceberg_engine.runner")
importlib.import_module("iceberg_engine.api_client")
importlib.import_module("iceberg_engine.suppression")
print(json.dumps(sorted(sys.modules)))
"""


def _engine_module_graph() -> set[str]:
    result = subprocess.run(  # noqa: S603  # fixed argv, no shell, interpreter is sys.executable
        [sys.executable, "-c", PROBE],
        capture_output=True,
        text=True,
        check=True,
    )
    return set(json.loads(result.stdout))


def test_engine_never_imports_database_code() -> None:
    imported = _engine_module_graph()

    offenders = sorted(
        module
        for module in imported
        if any(module == blocked or module.startswith(f"{blocked}.") for blocked in DB_MODULES)
    )

    assert offenders == [], f"engine process reached database code: {offenders}"


def test_engine_settings_are_the_only_configuration_it_needs() -> None:
    """Sanity check that the engine's own settings class carries no DB fields."""
    from iceberg_core.config import EngineSettings

    assert "database_url" not in EngineSettings.model_fields


def test_the_engine_reaches_the_control_plane_only_through_its_client() -> None:
    """The other half of the boundary: an engine has one way to talk to the API,
    and it is authenticated with a token that works nowhere else (ADR 0002).

    Asserted against the module graph because the failure mode is a helper quietly
    importing `iceberg_api` for "just one schema" — which would give a worker the
    API's dependency tree, and with it the database.
    """
    imported = _engine_module_graph()

    api_modules = sorted(module for module in imported if module.startswith("iceberg_api"))
    assert api_modules == [], f"engine process reached the API package: {api_modules}"
