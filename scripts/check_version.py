"""Assert that everything IcebergSST ships carries the same version.

A release is one number applied to both role images, the chart's ``appVersion``,
and every workspace package (``docs/releases.md``). Nothing structural keeps those
five files in step — they are edited by hand, in a bump nobody enjoys doing — so
this is the check that a half-bumped version fails on the pull request that
introduced it rather than during a release.

The chart's own ``version`` is deliberately *not* checked: a template change is a
chart release even when the application did not change, and it is the one number
allowed to differ.

Run it as ``make version-check``; ``tests/test_release_invariants.py`` runs the
same function in the ordinary suite, so CI enforces it without a separate job.
"""

import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

#: Every ``pyproject.toml`` whose version is part of the release.
PACKAGES = (
    "pyproject.toml",
    "apps/api/pyproject.toml",
    "apps/engine/pyproject.toml",
    "packages/core/pyproject.toml",
    "packages/connectors/pyproject.toml",
    "packages/detect/pyproject.toml",
)

CHART = "deploy/helm/icebergsst/Chart.yaml"

#: Read with a regex rather than a YAML parser: the chart is the one file here
#: that is not TOML, and adding a YAML dependency to a script that runs in every
#: test session to read one scalar is not a trade worth making.
_APP_VERSION = re.compile(r"^appVersion:\s*\"?([^\"\s]+)\"?\s*$", re.MULTILINE)


def declared_versions(root: Path = ROOT) -> dict[str, str]:
    """Every declared version, by the file that declares it."""
    versions: dict[str, str] = {}
    for relative in PACKAGES:
        data = tomllib.loads((root / relative).read_text(encoding="utf-8"))
        versions[relative] = str(data["project"]["version"])

    chart = (root / CHART).read_text(encoding="utf-8")
    match = _APP_VERSION.search(chart)
    if match is None:
        raise ValueError(f"{CHART} declares no appVersion")
    versions[f"{CHART} (appVersion)"] = match.group(1)
    return versions


def disagreements(root: Path = ROOT) -> dict[str, str]:
    """The files that do not match the majority version. Empty when they agree."""
    versions = declared_versions(root)
    # The root package is the reference rather than the most common value: a bump
    # that changed four files out of six should name the two that were missed,
    # not silently redefine the release as whatever the stragglers say.
    expected = versions["pyproject.toml"]
    return {name: value for name, value in versions.items() if value != expected}


def main() -> int:
    versions = declared_versions()
    mismatched = disagreements()
    if not mismatched:
        print(f"version {versions['pyproject.toml']} is consistent across {len(versions)} files")
        return 0
    print(f"expected {versions['pyproject.toml']} (from pyproject.toml), but:", file=sys.stderr)
    for name, value in sorted(mismatched.items()):
        print(f"  {name}: {value}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
