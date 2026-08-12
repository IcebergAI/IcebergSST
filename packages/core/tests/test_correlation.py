"""Correlation-id derivation (ADR 0010, #140): equality and nothing else."""

import secrets

import pytest
from iceberg_core.correlation import (
    MIN_CORRELATION_KEY_BYTES,
    correlation_id,
)
from iceberg_core.fingerprint import CoarseLocator, fingerprint, secret_hash

KEY = secrets.token_bytes(MIN_CORRELATION_KEY_BYTES)
PEPPER = secrets.token_bytes(32)

HASH_A = secret_hash("AKIAIOSFODNN7EXAMPLE", pepper=PEPPER)
HASH_B = secret_hash("ghp_another_secret_value", pepper=PEPPER)


def test_the_same_hash_correlates_deterministically() -> None:
    assert correlation_id(HASH_A, key=KEY) == correlation_id(HASH_A, key=KEY)


def test_different_hashes_do_not_correlate() -> None:
    assert correlation_id(HASH_A, key=KEY) != correlation_id(HASH_B, key=KEY)


def test_a_different_key_yields_a_different_id() -> None:
    """Two deployments with different keys can never correlate values."""
    other_key = secrets.token_bytes(MIN_CORRELATION_KEY_BYTES)

    assert correlation_id(HASH_A, key=KEY) != correlation_id(HASH_A, key=other_key)


def test_the_id_is_not_the_input_hash() -> None:
    """Exposing the id must not re-expose the peppered hash."""
    derived = correlation_id(HASH_A, key=KEY)

    assert derived != HASH_A
    assert len(derived) == 64
    assert all(c in "0123456789abcdef" for c in derived)


def test_domain_separation_from_the_fingerprint_family() -> None:
    """The same key bytes must never make a correlation id collide with the
    secret hash or fingerprint of the same material — a cross-domain equality
    would let one identifier stand in for another."""
    derived = correlation_id(HASH_A, key=KEY)

    assert derived != secret_hash(HASH_A, pepper=KEY)
    assert derived != fingerprint(
        locator=CoarseLocator(connector_type="confluence", resource_id="page-1"),
        rule_id="aws-access-key-id",
        secret_hash=HASH_A,
        pepper=KEY,
    )


def test_a_short_key_is_refused() -> None:
    with pytest.raises(ValueError, match="at least"):
        correlation_id(HASH_A, key=secrets.token_bytes(MIN_CORRELATION_KEY_BYTES - 1))


@pytest.mark.parametrize(
    "bad_hash",
    [
        "",
        "not-hex",
        HASH_A[:-1],  # 63 chars
        HASH_A + "0",  # 65 chars
        HASH_A.upper(),  # stored hashes are lowercase hex; refuse lookalikes
    ],
)
def test_malformed_secret_hashes_are_refused(bad_hash: str) -> None:
    with pytest.raises(ValueError, match="64 lowercase hex"):
        correlation_id(bad_hash, key=KEY)
