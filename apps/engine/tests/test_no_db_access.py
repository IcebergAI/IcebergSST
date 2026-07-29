"""The engine boundary, enforced (ADR 0002, invariant 1).

A static import scan would miss a transitive path — ``iceberg_engine`` importing
some helper that itself imports the session module. So this runs a real
interpreter, imports the engine, and inspects the resulting module graph.

Issue #52 extends this to the finished worker; the guard exists from M0 so the
boundary can never be crossed unnoticed in between.
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
