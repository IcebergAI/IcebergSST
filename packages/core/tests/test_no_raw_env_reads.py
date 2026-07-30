"""One config layer, one place that reads the environment (ADR 0007).

The secret-store acceptance criterion is that *all* credential and pepper access
goes through the interface, with no raw env reads. That is only true if it stays
true, so this walks the shipped source and fails on any ``os.environ`` /
``os.getenv`` outside the settings module.

Keeping env access in one file is what makes the role split auditable: to see
everything an engine can be configured with, you read one class.
"""

import ast
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]

#: The single sanctioned reader of the process environment.
ALLOWED = {REPO_ROOT / "packages" / "core" / "src" / "iceberg_core" / "config.py"}

ENV_ACCESSORS = {"environ", "getenv", "environb"}


def _shipped_sources() -> list[Path]:
    roots = [*(REPO_ROOT / "apps").glob("*/src"), *(REPO_ROOT / "packages").glob("*/src")]
    return sorted(path for root in roots for path in root.rglob("*.py"))


def _reads_environment(path: Path) -> bool:
    """True if the module touches ``os.environ``/``os.getenv`` (or imports them).

    Aliased spellings count too — ``import os as _o; _o.environ`` and
    ``from os import environ as e`` are the same read wearing a disguise.
    """
    tree = ast.parse(path.read_text(), filename=str(path))
    os_aliases = {"os"} | {
        alias.asname or alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
        if alias.name == "os"
    }
    for node in ast.walk(tree):
        match node:
            case ast.Attribute(value=ast.Name(id=name), attr=attr) if (
                name in os_aliases and attr in ENV_ACCESSORS
            ):
                return True
            case ast.ImportFrom(module="os", names=names) if any(
                alias.name in ENV_ACCESSORS for alias in names
            ):
                return True
    return False


def test_the_config_module_is_the_only_reader_of_the_environment() -> None:
    sources = _shipped_sources()
    assert sources, "expected to find shipped Python sources to scan"

    offenders = sorted(
        str(path.relative_to(REPO_ROOT))
        for path in sources
        if path not in ALLOWED and _reads_environment(path)
    )

    assert offenders == [], (
        "these modules read the environment directly; add the value to "
        f"iceberg_core.config instead: {offenders}"
    )
