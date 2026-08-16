"""What has to be true before a tag can be pushed (#147).

The release workflow re-checks all of this before it builds anything, because a
signed artifact is public the moment it exists and a bad release has to be
superseded rather than withdrawn. But a check that only runs on a tag is one
nobody sees until the release they were trying to cut fails — so the same
properties are asserted here, on every pull request, where the fix is cheap.

Lives in the root suite because it reads across the whole workspace: six
`pyproject.toml` files, the chart, the CHANGELOG, and the migrations directory.
"""

import importlib.util
import re
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]
CHANGELOG = ROOT / "CHANGELOG.md"
MIGRATIONS = ROOT / "apps/api/src/iceberg_api/migrations/versions"
WORKFLOW = ROOT / ".github/workflows/release.yml"

#: `## [1.2.3] — 2026-08-16`, or `## [Unreleased]`.
_ENTRY = re.compile(r"^## \[([^\]]+)\]", re.MULTILINE)


def _load(name: str) -> ModuleType:
    """Import a `scripts/` module by path.

    `scripts/` is not a package and should not become one: the files in it are
    commands `make` runs, not library code, and making it importable would invite
    application code to depend on them. Loading by path keeps that one-way.
    """
    path = ROOT / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


check_version = _load("check_version")


def _sections(version: str) -> str:
    """One version's CHANGELOG entry, from its heading to the next one."""
    text = CHANGELOG.read_text(encoding="utf-8")
    start = text.index(f"## [{version}]")
    remainder = text[start + 1 :]
    end = remainder.find("\n## [")
    return remainder if end == -1 else remainder[:end]


# ─── One version, everywhere ──────────────────────────────────────────────────


def test_every_shipped_component_declares_the_same_version() -> None:
    """A release is one number applied to both images, the chart, and every
    package. Nothing structural keeps six hand-edited files in step, so this is
    what fails on the pull request that half-bumps them rather than during the
    release."""
    assert check_version.disagreements() == {}


def test_the_version_check_would_notice_a_disagreement(tmp_path: Path) -> None:
    """A guard nobody has seen fail is a guard nobody should trust. Builds a
    scratch tree where one package lags, and asserts it is named."""
    for relative in check_version.PACKAGES:
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        version = "0.1.0" if relative != "packages/detect/pyproject.toml" else "0.0.9"
        target.write_text(f'[project]\nname = "x"\nversion = "{version}"\n')
    chart = tmp_path / "deploy/helm/icebergsst/Chart.yaml"
    chart.parent.mkdir(parents=True, exist_ok=True)
    chart.write_text('appVersion: "0.1.0"\n')

    assert list(check_version.disagreements(tmp_path)) == ["packages/detect/pyproject.toml"]


def test_the_chart_version_is_allowed_to_differ_from_the_app_version() -> None:
    """The one number that moves independently: a template change is a chart
    release even when the application did not change. Asserted so a future
    "tidy-up" does not fold it into the check above."""
    assert not any("(version)" in name for name in check_version.declared_versions())


# ─── The CHANGELOG is the release notes ───────────────────────────────────────


def test_the_changelog_has_an_unreleased_section() -> None:
    """Where the next release's notes accumulate. Without it, notes get written
    at tag time from commit subjects — which is how a migration goes
    undocumented."""
    assert "## [Unreleased]" in CHANGELOG.read_text(encoding="utf-8")


def test_every_changelog_version_is_a_semantic_version() -> None:
    text = CHANGELOG.read_text(encoding="utf-8")
    versions = [name for name in _ENTRY.findall(text) if name != "Unreleased"]

    assert versions, "the changelog documents no releases"
    for version in versions:
        assert re.fullmatch(r"\d+\.\d+\.\d+", version), version


def test_a_release_that_adds_a_migration_documents_it() -> None:
    """ "Does this upgrade touch my database?" is the first question an operator
    asks and the one a changelog most often fails to answer.

    Checked against the *current* version's entry, since that is the one whose
    scope this working tree can still change.
    """
    version = check_version.declared_versions()["pyproject.toml"]
    if f"## [{version}]" not in CHANGELOG.read_text(encoding="utf-8"):
        pytest.skip(f"{version} is not yet a changelog entry; nothing to check")
    migrations = sorted(path.name for path in MIGRATIONS.glob("0*.py"))

    assert migrations, "no migrations found; the glob is looking in the wrong place"
    assert "### Migrations" in _sections(version)


def test_the_release_workflow_verifies_before_it_publishes() -> None:
    """Ordering is the whole safety property: once an artifact is signed and
    pushed it is public. Both build jobs must depend on the verify job."""
    workflow = WORKFLOW.read_text(encoding="utf-8")

    assert "needs: verify" in workflow
    assert "needs: [verify, images]" in workflow


def test_every_release_action_is_pinned_to_a_commit() -> None:
    """A tag is a mutable pointer its owner can move — the same reason images are
    signed by digest. The trailing comment is the human-readable half; only the
    SHA decides what runs."""
    workflow = WORKFLOW.read_text(encoding="utf-8")
    used = re.findall(r"uses:\s*(\S+)", workflow)

    assert used, "no actions found; the pattern is looking at the wrong thing"
    unpinned = [ref for ref in used if not re.search(r"@[0-9a-f]{40}$", ref)]
    assert unpinned == [], f"not pinned to a commit: {unpinned}"


def test_the_release_workflow_signs_by_digest_never_by_tag() -> None:
    """Verifying a signature on a tag proves something about a name rather than
    about the bytes that run."""
    workflow = WORKFLOW.read_text(encoding="utf-8")

    assert "REFERENCE: ${{ steps.build.outputs.image }}@${{ steps.build.outputs.digest }}" in (
        workflow
    )
    assert 'cosign sign --yes "$REFERENCE"' in workflow


def test_the_version_check_script_runs_as_a_command() -> None:
    """`make version-check` is what a release engineer runs; this is the same
    entry point, so a refactor that breaks the CLI fails here."""
    result = subprocess.run(  # noqa: S603  # this interpreter, one repository path
        [sys.executable, str(ROOT / "scripts/check_version.py")],
        capture_output=True,
        text=True,
        check=False,
        cwd=ROOT,
    )

    assert result.returncode == 0, result.stderr
    assert "consistent" in result.stdout
