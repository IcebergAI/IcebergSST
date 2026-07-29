"""Fingerprint identity: determinism, pepper dependence, and what must not change it."""

import dataclasses
import inspect
import subprocess
import sys

import pytest
from iceberg_core.fingerprint import (
    MIN_PEPPER_BYTES,
    CoarseLocator,
    fingerprint,
    fingerprint_for_secret,
    secret_hash,
)
from iceberg_core.secrets import EnvKeyBackend

PEPPER = bytes(range(32))
OTHER_PEPPER = bytes(range(1, 33))
SECRET = "AKIAsampleSAMPLEkey1"  # AWS-shaped, deliberately not a real id
RULE = "aws-access-key-id"
PAGE = CoarseLocator(connector_type="confluence", resource_id="page-12345")
ATTACHMENT = CoarseLocator(
    connector_type="confluence", resource_id="page-12345", sub_resource="creds.txt"
)


def _fp(locator: CoarseLocator = PAGE, rule: str = RULE, secret: str = SECRET) -> str:
    return fingerprint_for_secret(locator=locator, rule_id=rule, secret=secret, pepper=PEPPER)


def test_fingerprint_is_a_stable_hex_digest() -> None:
    value = _fp()

    assert len(value) == 64
    assert int(value, 16) >= 0
    assert value == _fp()


def test_fingerprint_is_identical_in_a_fresh_process() -> None:
    """Determinism across runs — no per-process salt sneaking in via hash()."""
    probe = (
        "from iceberg_core.fingerprint import CoarseLocator, fingerprint_for_secret;"
        f"print(fingerprint_for_secret(locator=CoarseLocator('confluence', 'page-12345'),"
        f" rule_id={RULE!r}, secret={SECRET!r}, pepper=bytes(range(32))))"
    )
    result = subprocess.run(  # noqa: S603  # fixed argv, no shell
        [sys.executable, "-c", probe], capture_output=True, text=True, check=True
    )

    assert result.stdout.strip() == _fp()


def test_offsets_cannot_change_the_fingerprint() -> None:
    """A match at line 4 and the same match at line 400 are one finding (ADR 0006).

    Position is not an input to this API at all: adding one would mean adding a
    field to CoarseLocator, which is exactly the reviewable change ADR 0006 wants
    it to be. The check is structural for that reason.
    """
    positional = {"line", "offset", "column", "start", "end", "position", "index"}

    inputs = {
        *inspect.signature(fingerprint).parameters,
        *inspect.signature(fingerprint_for_secret).parameters,
        *(field.name for field in dataclasses.fields(CoarseLocator)),
    }

    assert positional.isdisjoint(inputs)


def test_repeated_matches_in_one_resource_collapse_to_one_finding() -> None:
    text = f"prod={SECRET} staging={SECRET} backup={SECRET}"
    fingerprints = {_fp() for _ in range(text.count(SECRET))}

    assert len(fingerprints) == 1


def test_a_sub_resource_is_a_distinct_finding() -> None:
    assert _fp(PAGE) != _fp(ATTACHMENT)


def test_a_different_page_is_a_distinct_finding() -> None:
    other_page = CoarseLocator(connector_type="confluence", resource_id="page-99999")

    assert _fp(PAGE) != _fp(other_page)


def test_a_different_connector_is_a_distinct_finding() -> None:
    jira = CoarseLocator(connector_type="jira", resource_id="page-12345")

    assert _fp(PAGE) != _fp(jira)


def test_a_different_rule_is_a_distinct_finding() -> None:
    assert _fp(rule="generic-high-entropy") != _fp(rule=RULE)


def test_a_different_secret_is_a_distinct_finding() -> None:
    assert _fp(secret="AKIAsampleSAMPLEkey2") != _fp(secret=SECRET)


def test_separators_in_locator_fields_cannot_forge_a_collision() -> None:
    """Length-prefixed encoding: field boundaries survive a colon in the data."""
    left = CoarseLocator(connector_type="confluence", resource_id="space:page", sub_resource="file")
    right = CoarseLocator(
        connector_type="confluence", resource_id="space", sub_resource="page:file"
    )

    assert _fp(left) != _fp(right)


def test_rule_id_boundary_cannot_be_forged_either() -> None:
    left = fingerprint(locator=PAGE, rule_id="aws", secret_hash="key123", pepper=PEPPER)
    right = fingerprint(locator=PAGE, rule_id="aws-key", secret_hash="123", pepper=PEPPER)

    assert left != right


def test_unicode_normalisation_keeps_one_finding_one_finding() -> None:
    """The same page title can arrive composed or decomposed."""
    decomposed = CoarseLocator(connector_type="confluence", resource_id="Café-notes")
    composed = CoarseLocator(connector_type="confluence", resource_id="Café-notes")

    assert composed.resource_id != decomposed.resource_id
    assert _fp(composed) == _fp(decomposed)


def test_the_pepper_participates_in_identity() -> None:
    with_pepper = fingerprint_for_secret(locator=PAGE, rule_id=RULE, secret=SECRET, pepper=PEPPER)
    with_other = fingerprint_for_secret(
        locator=PAGE, rule_id=RULE, secret=SECRET, pepper=OTHER_PEPPER
    )

    assert with_pepper != with_other


def test_secret_hash_is_peppered_and_reveals_nothing() -> None:
    digest = secret_hash(SECRET, pepper=PEPPER)

    assert len(digest) == 64
    assert SECRET not in digest
    assert digest == secret_hash(SECRET, pepper=PEPPER)
    assert digest != secret_hash(SECRET, pepper=OTHER_PEPPER)
    assert digest != secret_hash(SECRET.lower(), pepper=PEPPER)


def test_secret_hash_accepts_bytes_for_binary_matches() -> None:
    assert secret_hash(b"\x00\x01binary-key", pepper=PEPPER)


def test_a_weak_pepper_is_refused() -> None:
    with pytest.raises(ValueError, match=f"at least {MIN_PEPPER_BYTES} bytes"):
        secret_hash(SECRET, pepper=b"short")

    with pytest.raises(ValueError, match="get_pepper"):
        fingerprint(locator=PAGE, rule_id=RULE, secret_hash="abc", pepper=b"")


@pytest.mark.parametrize(
    ("connector_type", "resource_id"),
    [("", "page-1"), ("confluence", ""), ("  ", "page-1")],
)
def test_a_locator_needs_its_stable_fields(connector_type: str, resource_id: str) -> None:
    with pytest.raises(ValueError, match="required"):
        CoarseLocator(connector_type=connector_type, resource_id=resource_id)


def test_empty_inputs_are_programming_errors() -> None:
    with pytest.raises(ValueError, match="empty secret"):
        secret_hash("", pepper=PEPPER)

    with pytest.raises(ValueError, match="rule_id is required"):
        fingerprint(locator=PAGE, rule_id=" ", secret_hash="abc", pepper=PEPPER)

    with pytest.raises(ValueError, match="secret_hash is required"):
        fingerprint(locator=PAGE, rule_id=RULE, secret_hash="", pepper=PEPPER)


def test_pepper_from_the_secret_store_works_end_to_end(secret_store: EnvKeyBackend) -> None:
    """The pepper reaches fingerprinting through the interface, not the environment."""
    pepper = secret_store.get_pepper()

    value = fingerprint_for_secret(locator=PAGE, rule_id=RULE, secret=SECRET, pepper=pepper)

    assert len(value) == 64
    assert value != _fp()  # a different pepper, so a different identity
