"""Content units and the locator split (#45).

The split between coarse identity and display metadata is the whole point of this
type, and getting it wrong fails quietly — findings stop matching across scans and
triage history is discarded with no error anywhere. So it is tested directly.
"""

import pytest
from iceberg_connectors import ContentOrigin, ContentUnit
from iceberg_core.fingerprint import CoarseLocator, fingerprint_for_secret

PEPPER = b"0123456789abcdef0123456789abcdef"


def _unit(**overrides: object) -> ContentUnit:
    defaults: dict[str, object] = {
        "locator": CoarseLocator(connector_type="fake", resource_id="page-1"),
        "text": "some text",
    }
    return ContentUnit(**(defaults | overrides))  # type: ignore[arg-type]


def test_a_unit_carries_both_halves_of_its_locator() -> None:
    unit = _unit(
        locator=CoarseLocator("confluence", "page-42", "notes.txt"),
        origin=ContentOrigin.ATTACHMENT,
        display={"url": "https://wiki.test/page/42", "space": "DOCS"},
    )

    blob = unit.resource_locator()

    assert blob["resource_id"] == "page-42"
    assert blob["sub_resource"] == "notes.txt"
    assert blob["origin"] == "attachment"
    assert blob["url"] == "https://wiki.test/page/42"


def test_display_metadata_cannot_shadow_the_coarse_identity() -> None:
    """A connector putting `resource_id` in display must not be able to rewrite
    what the fingerprint was computed from."""
    unit = _unit(
        locator=CoarseLocator("confluence", "the-real-id"),
        display={"resource_id": "an-impostor", "connector_type": "not-this"},
    )

    blob = unit.resource_locator()

    assert blob["resource_id"] == "the-real-id"
    assert blob["connector_type"] == "confluence"


def test_editing_the_display_half_does_not_change_the_fingerprint() -> None:
    """The property the whole split exists for: a page whose title or URL changed
    is still the same page, and its findings keep their triage state (ADR 0006)."""
    before = _unit(display={"title": "Runbook", "url": "https://wiki.test/1"})
    after = _unit(display={"title": "Runbook (2026 edition)", "url": "https://wiki.test/1?v=9"})

    assert fingerprint_for_secret(
        locator=before.locator, rule_id="aws-access-key-id", secret="s", pepper=PEPPER
    ) == fingerprint_for_secret(
        locator=after.locator, rule_id="aws-access-key-id", secret="s", pepper=PEPPER
    )


def test_a_different_sub_resource_is_a_different_identity() -> None:
    """Two attachments on one page are two resources, not one."""
    page = CoarseLocator("confluence", "page-1")
    attachment = CoarseLocator("confluence", "page-1", "creds.txt")

    assert fingerprint_for_secret(
        locator=page, rule_id="r", secret="s", pepper=PEPPER
    ) != fingerprint_for_secret(locator=attachment, rule_id="r", secret="s", pepper=PEPPER)


def test_the_origin_defaults_to_body() -> None:
    assert _unit().origin is ContentOrigin.BODY


def test_a_locator_needs_a_connector_type_and_resource_id() -> None:
    """Both feed identity; an empty one would collapse unrelated findings together."""
    with pytest.raises(ValueError, match="connector_type is required"):
        CoarseLocator(connector_type="  ", resource_id="page-1")
    with pytest.raises(ValueError, match="resource_id is required"):
        CoarseLocator(connector_type="fake", resource_id="")


def test_glob_friendly_keys_are_what_suppressions_match_against() -> None:
    """A connector populating none of these leaves analysts unable to write a
    `path_glob` suppression for that source."""
    from iceberg_connectors import GLOB_FRIENDLY_KEYS
    from iceberg_core.suppression import LOCATOR_PATH_KEYS

    assert set(GLOB_FRIENDLY_KEYS) <= set(LOCATOR_PATH_KEYS)
