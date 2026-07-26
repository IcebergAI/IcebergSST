"""Issue #24 acceptance: round-trip encryption, opaque refs, pepper via the interface."""

import base64

import pytest
from iceberg_core.secrets.store import (
    KEY_BYTES,
    EnvKeyBackend,
    SecretRef,
    SecretStore,
    SecretStoreError,
)

# Obviously fake, low-entropy: keeps the repo's own gitleaks scan quiet.
FAKE_CREDENTIAL = "fake-not-a-real-confluence-token"


def test_backend_satisfies_the_protocol(secret_store: EnvKeyBackend) -> None:
    """Call sites depend on SecretStore, never on the concrete backend."""
    assert isinstance(secret_store, SecretStore)


def test_round_trip(secret_store: EnvKeyBackend) -> None:
    ref = secret_store.put(FAKE_CREDENTIAL)
    assert secret_store.get(ref) == FAKE_CREDENTIAL


def test_ref_is_opaque_and_hides_the_plaintext(secret_store: EnvKeyBackend) -> None:
    """A Source row stores this ref (#32); it must disclose nothing."""
    ref = secret_store.put(FAKE_CREDENTIAL)
    assert FAKE_CREDENTIAL not in ref
    assert ref.startswith("icbg.v1.")


def test_same_plaintext_yields_different_refs(secret_store: EnvKeyBackend) -> None:
    """Fresh nonce per put: equal credentials must not be correlatable by ref."""
    assert secret_store.put(FAKE_CREDENTIAL) != secret_store.put(FAKE_CREDENTIAL)


def test_tampered_ref_is_rejected(secret_store: EnvKeyBackend) -> None:
    """AES-GCM authenticates: a flipped byte must fail, not decrypt to garbage."""
    ref = secret_store.put(FAKE_CREDENTIAL)
    tampered = SecretRef(ref[:-2] + ("AA" if not ref.endswith("AA") else "BB"))
    with pytest.raises(SecretStoreError):
        secret_store.get(tampered)


@pytest.mark.parametrize("bad", ["", "nonsense", "icbg.v2.abc", "vault:v1:secret/x", "icbg.v1."])
def test_foreign_or_malformed_refs_are_rejected(secret_store: EnvKeyBackend, bad: str) -> None:
    with pytest.raises(SecretStoreError):
        secret_store.get(SecretRef(bad))


def test_error_does_not_disclose_why(secret_store: EnvKeyBackend) -> None:
    """Decryption failures must not become an oracle."""
    ref = secret_store.put(FAKE_CREDENTIAL)
    with pytest.raises(SecretStoreError) as exc:
        secret_store.get(SecretRef(ref[:-4] + "AAAA"))
    assert str(exc.value) == "could not decrypt secret reference"


def test_another_key_cannot_open_the_ref(secret_store: EnvKeyBackend) -> None:
    """Key compromise is bounded to that key."""
    ref = secret_store.put(FAKE_CREDENTIAL)
    other = EnvKeyBackend(master_key=b"z" * KEY_BYTES, pepper=b"other-pepper")
    with pytest.raises(SecretStoreError):
        other.get(ref)


def test_pepper_comes_from_the_interface(secret_store: EnvKeyBackend) -> None:
    """ADR 0006/0007: no call site reads the pepper from the environment."""
    assert secret_store.pepper() == b"iceberg-test-pepper"


def test_wrong_length_key_is_refused() -> None:
    with pytest.raises(SecretStoreError, match="master key must be 32 bytes"):
        EnvKeyBackend(master_key=b"too-short", pepper=b"p")


def test_empty_pepper_is_refused() -> None:
    with pytest.raises(SecretStoreError, match="pepper must not be empty"):
        EnvKeyBackend(master_key=b"k" * KEY_BYTES, pepper=b"")


def test_non_base64_material_is_refused() -> None:
    with pytest.raises(SecretStoreError, match="valid base64"):
        EnvKeyBackend.from_values(master_key_b64="not!base64", pepper_b64="also!bad")


def test_generated_key_is_usable() -> None:
    """`generate_key` is the bootstrap path documented in .env.example."""
    key = EnvKeyBackend.generate_key()
    assert len(base64.b64decode(key)) == KEY_BYTES
    store = EnvKeyBackend.from_values(
        master_key_b64=key,
        pepper_b64=base64.b64encode(b"pepper").decode(),
    )
    assert store.get(store.put(FAKE_CREDENTIAL)) == FAKE_CREDENTIAL


def test_unicode_and_empty_values_round_trip(secret_store: EnvKeyBackend) -> None:
    for value in ("", "pässwörd-ünïcode-🔑", "x" * 4096):
        assert secret_store.get(secret_store.put(value)) == value
