"""Invariants for the repository's own secret scan (`.gitleaks.toml`).

The CI job that scans this repository's history is the last line between a leaked
credential and a public git remote. Its config is the one file where weakening it
looks like a small convenience — "the tests are noisy, exempt the directory" — and
nothing else would notice. So the properties that make it worth running are
asserted here rather than left to review.
"""

import re
import tomllib
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
GITLEAKS_CONFIG = REPO_ROOT / ".gitleaks.toml"
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"


@pytest.fixture(name="config", scope="module")
def config_fixture() -> dict[str, Any]:
    with GITLEAKS_CONFIG.open("rb") as handle:
        loaded: dict[str, Any] = tomllib.load(handle)
    return loaded


def _allowlists(config: dict[str, Any]) -> list[dict[str, Any]]:
    """Every allowlist, global or attached to a rule."""
    entries = list(config.get("allowlists", []))
    if isinstance(config.get("allowlist"), dict):
        entries.append(config["allowlist"])
    for rule in config.get("rules", []):
        entries.extend(rule.get("allowlists", []))
        if isinstance(rule.get("allowlist"), dict):
            entries.append(rule["allowlist"])
    return entries


def test_the_default_rule_pack_is_extended_not_replaced(config: dict[str, Any]) -> None:
    """A config without `useDefault` silently scans for nothing but our own rules."""
    assert config.get("extend", {}).get("useDefault") is True


def test_no_allowlist_names_a_path(config: dict[str, Any]) -> None:
    """A path allowlist silences a whole file, including real credentials in it.

    Not a style preference — gitleaks applies `paths` as a file-level pre-filter,
    before and independently of `regexes`/`stopwords`, so pairing them with
    `condition = "AND"` does *not* narrow the exemption. Verified against v8.30: a
    real `ghp_…` token in a file under an allowlisted path goes unreported.

    Exempting `**/tests/**` is the tempting one, since this repository's fixtures
    are deliberately secret-shaped, and it would retract the reason
    `pyproject.toml` gives for exempting the test suite from ruff's S105/S106 —
    that real leaks are caught by the gitleaks job over the whole repo. Allowlist
    the literal instead, or mark the line with an inline `gitleaks:allow`.
    """
    for entry in _allowlists(config):
        assert not entry.get("paths"), (
            "allowlists must not name paths — a path exemption applies to the whole "
            f"file regardless of any other criterion: {entry.get('paths')}"
        )
        assert entry.get("regexes") or entry.get("stopwords") or entry.get("commits"), (
            f"allowlist constrains nothing: {entry}"
        )


def test_every_allowlist_says_why_it_exists(config: dict[str, Any]) -> None:
    """ "Who allowed this, and on what grounds" must be answerable from the file."""
    for entry in _allowlists(config):
        assert len(entry.get("description", "").strip()) > 40, (
            f"allowlist needs a real justification: {entry}"
        )


def test_ci_scans_the_whole_history() -> None:
    """A shallow checkout would miss a credential that was committed and removed.

    That is the case the scan most needs to catch: deleting the line does not delete
    it from the history a clone hands over.
    """
    workflow = CI_WORKFLOW.read_text()

    assert "gitleaks" in workflow
    assert re.search(r"fetch-depth:\s*0", workflow), "gitleaks needs the full history"
