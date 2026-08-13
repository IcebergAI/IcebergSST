"""The remediation-guidance catalog (#142, ADR 0012): valid, complete, honest."""

from pathlib import Path

import pytest
import yaml
from iceberg_api.remediation.guidance import (
    CATALOG_PATH,
    GuidanceCatalog,
    load_catalog,
)
from iceberg_detect import load_named_pack


def test_the_packaged_catalog_loads_and_validates() -> None:
    catalog = load_catalog()

    assert catalog.version
    assert "default" in catalog.entries


def test_every_entry_separates_the_four_actions() -> None:
    """The acceptance criterion: revoke / rotate / scope-reduce / remove-source
    are distinct sections, and every entry offers at least revoke or rotate —
    guidance that names no way to kill the credential is not guidance."""
    for rule_id, entry in load_catalog().entries.items():
        assert entry.revoke or entry.rotate, rule_id
        assert entry.remove_source, rule_id


def test_every_seed_rule_resolves_to_an_entry_or_the_default() -> None:
    """A rule id with no entry gets the default, and says so — no rule can hit
    a missing key at render time."""
    catalog = load_catalog()

    for rule in load_named_pack().rules:
        entry, matched = catalog.lookup(rule.id)
        assert entry.title, rule.id
        assert matched in {"rule", "default"}
        if matched == "rule":
            assert rule.id in catalog.entries


def test_specific_entries_name_rules_that_exist() -> None:
    """The reverse direction: an entry for a renamed or deleted rule is dead
    advice that would never render — the review should notice."""
    seeded = {rule.id for rule in load_named_pack().rules}

    orphans = set(load_catalog().entries) - seeded - {"default"}

    assert orphans == set(), f"guidance for unknown rules: {sorted(orphans)}"


def test_an_unknown_key_fails_validation() -> None:
    raw = yaml.safe_load(CATALOG_PATH.read_text())
    raw["entries"]["default"]["surprise"] = ["not a section"]

    with pytest.raises(ValueError, match="surprise"):
        GuidanceCatalog.model_validate(raw)


def test_lookup_reports_which_entry_was_served() -> None:
    catalog = load_catalog()

    _, matched_specific = catalog.lookup("aws-access-key-id")
    fallback, matched_default = catalog.lookup("some-rule-with-no-entry")

    assert matched_specific == "rule"
    assert matched_default == "default"
    assert fallback is catalog.entries["default"]


def test_a_malformed_catalog_stops_the_app_from_starting(monkeypatch: pytest.MonkeyPatch) -> None:
    """ADR 0012 says loud failure, and lazily loud is not loud: validating on
    the first request that happens to need guidance means a packaging mistake
    passes the deploy's health check and surfaces as a 500 on somebody's
    finding page. `create_app` loads the catalog itself."""
    from iceberg_api.app import create_app
    from iceberg_api.remediation import guidance

    guidance.load_catalog.cache_clear()
    monkeypatch.setattr(guidance, "CATALOG_PATH", Path("/nonexistent/guidance.yaml"))
    monkeypatch.setattr("iceberg_api.app.load_catalog", guidance.load_catalog)
    try:
        with pytest.raises(guidance.GuidanceError, match="unreadable"):
            create_app(background=False)
    finally:
        guidance.load_catalog.cache_clear()
