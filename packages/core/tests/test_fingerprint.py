"""Issue #26 acceptance: deterministic, peppered, coarse-locator fingerprints."""

import pytest
from iceberg_core.fingerprint import CoarseLocator, fingerprint, fingerprint_from_hash, hash_secret

PEPPER = b"test-pepper-not-real"
OTHER_PEPPER = b"different-pepper"
# Obviously fake, low-entropy: keeps the repo's own gitleaks scan quiet.
FAKE_SECRET = "fake-not-a-real-secret-value"  # noqa: S105  # placeholder, not a credential
PAGE = CoarseLocator(resource_id="page-1001")
GOLDEN_FINGERPRINT = "13a43a4c9d1dfe6a05b86437e913eb521242cbf4b2bdf417c67f1c95e4b84ca5"


def fp(**overrides: object) -> str:
    kwargs: dict[str, object] = {
        "connector_type": "confluence",
        "locator": PAGE,
        "rule_id": "aws-access-key-id",
        "secret": FAKE_SECRET,
        "pepper": PEPPER,
    }
    kwargs.update(overrides)
    return fingerprint(**kwargs)  # type: ignore[arg-type]  # kwargs are checked by the callee


def test_deterministic_across_runs() -> None:
    """Same inputs must always give the same identity, in any process.

    The pinned digest is the real guarantee: a change to the hash construction
    would silently orphan every triage decision in an existing deployment, so it
    must break this test loudly. Changing it requires a fingerprint migration
    (ADR 0006).
    """
    assert fp() == fp()
    assert fp() == GOLDEN_FINGERPRINT
    assert len(fp()) == 64


def test_pepper_changes_the_fingerprint() -> None:
    """Without the pepper a DB dump cannot be brute-forced offline."""
    assert fp() != fp(pepper=OTHER_PEPPER)


def test_empty_pepper_is_refused() -> None:
    with pytest.raises(ValueError, match="pepper must not be empty"):
        hash_secret(FAKE_SECRET, b"")


def test_line_offset_is_not_part_of_identity() -> None:
    """ADR 0006: editing text above a secret must not orphan its triage state.

    CoarseLocator has no offset field at all, so the only way to express "same
    page, different position" is the identical locator — and it fingerprints the
    same.
    """
    moved = CoarseLocator(resource_id="page-1001")
    assert fp(locator=moved) == fp()


def test_same_secret_twice_in_one_locator_collapses() -> None:
    """Two occurrences in one page are one finding, not two."""
    first = fp()
    second = fp()
    assert first == second
    assert len({first, second}) == 1


def test_distinct_locators_are_distinct_findings() -> None:
    """The same key in two pages is two independently triageable findings."""
    assert fp(locator=CoarseLocator(resource_id="page-2002")) != fp()


def test_attachment_participates_in_identity() -> None:
    attached = CoarseLocator(resource_id="page-1001", attachment_name="creds.txt")
    assert fp(locator=attached) != fp()


def test_rule_id_and_connector_participate_in_identity() -> None:
    assert fp(rule_id="generic-high-entropy") != fp()
    assert fp(connector_type="jira") != fp()


def test_different_secrets_collide_not() -> None:
    other = "fake-other-placeholder-value"
    assert fp(secret=other) != fp()


def test_locator_fields_cannot_be_confused() -> None:
    """A separator must stop ('ab', None) and ('a', 'b') hashing alike."""
    ab_none = CoarseLocator(resource_id="ab")
    a_b = CoarseLocator(resource_id="a", attachment_name="b")
    assert fp(locator=ab_none) != fp(locator=a_b)


def test_api_can_reconcile_without_plaintext() -> None:
    """The API never sees the secret, so it must fingerprint from the hash."""
    digest = hash_secret(FAKE_SECRET, PEPPER)
    assert (
        fingerprint_from_hash(
            connector_type="confluence",
            locator=PAGE,
            rule_id="aws-access-key-id",
            secret_hash=digest,
        )
        == fp()
    )


def test_hash_does_not_contain_the_secret() -> None:
    assert FAKE_SECRET not in hash_secret(FAKE_SECRET, PEPPER)
