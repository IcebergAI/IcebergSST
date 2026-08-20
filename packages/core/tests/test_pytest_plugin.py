"""The shared plugin loads where the ORM does not (#197, ADR 0002).

``iceberg-core`` publishes ``iceberg_core.testing`` under ``pytest11``, so pytest
imports it in **every** environment where this package is installed — including
one with the engine's dependency shape: plain ``iceberg-core``, no ``db`` extra,
no SQLAlchemy. An unguarded import of the ORM there fails at collection, before a
single test runs, in a package that deliberately does not depend on it.

Run in a subprocess with the ORM blocked, because the workspace this suite runs
in has the extra installed and so can never reproduce the condition in-process.
"""

import json
import subprocess
import sys
from typing import Any

#: Import of any of these raises, standing in for an environment that never
#: installed them. `sys.modules[name] = None` is the documented way to make
#: `import name` fail — the loader treats a None entry as "known missing".
PROBE = """
import json
import sys

for blocked in ("sqlalchemy", "sqlmodel", "iceberg_core.db", "iceberg_core.models"):
    sys.modules[blocked] = None

import iceberg_core.testing as plugin

print(json.dumps({
    "available": plugin.DB_FIXTURES_AVAILABLE,
    "fixtures": sorted(
        name for name in dir(plugin) if name.endswith("_fixture")
    ),
}))
"""


def _probe() -> dict[str, Any]:
    result = subprocess.run(  # noqa: S603  # fixed argv, no shell, interpreter is sys.executable
        [sys.executable, "-c", PROBE],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, f"the plugin failed to import without the ORM:\n{result.stderr}"
    parsed: dict[str, Any] = json.loads(result.stdout)
    return parsed


def test_the_plugin_imports_without_the_database_extra() -> None:
    """The whole point: a failure here is every pytest run in an engine-shaped
    environment failing at collection, whatever it was actually testing."""
    probed = _probe()

    assert probed["available"] is False


def test_the_fixtures_are_still_registered_when_they_cannot_run() -> None:
    """Degrade to "unavailable", not to "absent". A fixture that vanished would
    be an obscure `fixture 'session' not found`; one that skips says what to
    install, and a test that needed it is reported skipped rather than green.
    """
    probed = _probe()

    assert "db_engine_fixture" in probed["fixtures"]
    assert "session_fixture" in probed["fixtures"]
    assert "secret_store_fixture" in probed["fixtures"]
