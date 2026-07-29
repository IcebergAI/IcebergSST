"""The engine must never reach the database (ADR 0002).

Seeds the invariant check that issue #52 completes. Three layers assert it:
this import-graph test, the ``iceberg-core[db]`` packaging split (the engine does
not install asyncpg/sqlmodel at all), and the compose/image env (#20, #21).
"""

import subprocess
import sys

FORBIDDEN_PREFIXES = ("iceberg_core.db", "sqlalchemy", "sqlmodel", "asyncpg")


def test_importing_the_engine_pulls_in_no_database_module() -> None:
    """A fresh interpreter importing the worker must load no DB module.

    Run out-of-process because pytest itself has already imported the DB modules
    for the core package's own tests — checking ``sys.modules`` in-process would
    always fail.
    """
    probe = (
        "import iceberg_engine.worker, sys;"
        f"bad=[m for m in sys.modules if m.startswith({FORBIDDEN_PREFIXES!r})];"
        "print(','.join(sorted(bad)))"
    )
    result = subprocess.run(  # noqa: S603  # fixed argv, no shell, no user input
        [sys.executable, "-c", probe],
        capture_output=True,
        text=True,
        check=True,
    )
    leaked = result.stdout.strip()
    assert not leaked, f"engine imported database modules: {leaked}"


def test_engine_settings_expose_no_database_fields() -> None:
    from iceberg_core.config import EngineSettings

    fields = set(EngineSettings.model_fields)
    assert not {f for f in fields if "database" in f or "db_" in f}
