"""Secret-store behaviour: round trips, purpose binding, and failure modes."""

import base64
import secrets
from collections.abc import Iterator

import pytest
from iceberg_core.config import SecretStoreSettings, reset_settings_cache
from iceberg_core.secrets import (
    EnvKeyBackend,
    SealedRefError,
    SecretPurpose,
    SecretStoreConfigError,
    build_secret_store,
    generate_master_key,
)
from iceberg_core.secrets.cli import main as cli_main
from iceberg_core.secrets.env_key import MASTER_KEY_BYTES, decode_master_key
from pydantic import SecretStr

CREDENTIAL = "confluence-api-token-value"  # test fixture, not a real credential


@pytest.fixture(autouse=True)
def _clear_settings_cache() -> Iterator[None]:
    """Settings are process-cached; the CLI tests below change the environment."""
    reset_settings_cache()
    yield
    reset_settings_cache()


@pytest.fixture(name="store")
def store_fixture() -> EnvKeyBackend:
    return EnvKeyBackend(secrets.token_bytes(MASTER_KEY_BYTES))


def test_credential_round_trips(store: EnvKeyBackend) -> None:
    ref = store.seal(CREDENTIAL)

    assert store.open(ref).get_secret_value() == CREDENTIAL


def test_sealed_ref_does_not_contain_the_plaintext(store: EnvKeyBackend) -> None:
    ref = store.seal(CREDENTIAL)

    assert CREDENTIAL not in ref
    assert ref.startswith("envkey:1:credential:")


def test_sealing_the_same_secret_twice_gives_different_refs(store: EnvKeyBackend) -> None:
    """A deterministic ref would leak "these two sources share a credential"."""
    assert store.seal(CREDENTIAL) != store.seal(CREDENTIAL)


def test_bytes_round_trip(store: EnvKeyBackend) -> None:
    payload = secrets.token_bytes(48)

    ref = store.seal_bytes(payload, purpose=SecretPurpose.GENERIC)

    assert store.open_bytes(ref, purpose=SecretPurpose.GENERIC) == payload


def test_a_credential_ref_cannot_be_opened_as_a_pepper(store: EnvKeyBackend) -> None:
    ref = store.seal(CREDENTIAL, purpose=SecretPurpose.CREDENTIAL)

    with pytest.raises(SealedRefError):
        store.open_bytes(ref, purpose=SecretPurpose.PEPPER)


def test_another_key_cannot_open_the_ref(store: EnvKeyBackend) -> None:
    ref = store.seal(CREDENTIAL)
    stranger = EnvKeyBackend(secrets.token_bytes(MASTER_KEY_BYTES))

    with pytest.raises(SealedRefError):
        stranger.open(ref)


def test_tampered_ciphertext_is_rejected(store: EnvKeyBackend) -> None:
    scheme, version, purpose, payload = store.seal(CREDENTIAL).split(":", 3)
    raw = bytearray(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    raw[-1] ^= 0x01
    flipped = base64.urlsafe_b64encode(bytes(raw)).decode().rstrip("=")

    with pytest.raises(SealedRefError):
        store.open(f"{scheme}:{version}:{purpose}:{flipped}")


def test_tampered_purpose_is_rejected(store: EnvKeyBackend) -> None:
    """The purpose is authenticated, so rewriting it in the DB cannot repurpose a ref."""
    _, _, _, payload = store.seal_bytes(b"x", purpose=SecretPurpose.PEPPER).split(":", 3)

    with pytest.raises(SealedRefError):
        store.open_bytes(f"envkey:1:generic:{payload}", purpose=SecretPurpose.GENERIC)


@pytest.mark.parametrize(
    "ref",
    [
        "",
        "envkey:1:credential",
        "vault:1:credential:abcd",
        "envkey:2:credential:abcd",
        "envkey:1:credential:!!!",
    ],
)
def test_malformed_refs_are_rejected(store: EnvKeyBackend, ref: str) -> None:
    with pytest.raises(SealedRefError):
        store.open(ref)


def test_pepper_comes_back_through_the_interface() -> None:
    master_key = secrets.token_bytes(MASTER_KEY_BYTES)
    pepper_ref = EnvKeyBackend(master_key).generate_pepper_ref()

    store = EnvKeyBackend(master_key, pepper_ref=pepper_ref)
    pepper = store.get_pepper()

    assert len(pepper) == 32
    assert store.get_pepper() == pepper  # stable across calls


def test_missing_pepper_ref_fails_loudly(store: EnvKeyBackend) -> None:
    with pytest.raises(SecretStoreConfigError, match="ICEBERG_FINGERPRINT_PEPPER_REF"):
        store.get_pepper()


def test_master_key_must_be_32_bytes() -> None:
    with pytest.raises(SecretStoreConfigError):
        EnvKeyBackend(secrets.token_bytes(16))

    with pytest.raises(SecretStoreConfigError, match="32 bytes"):
        decode_master_key(base64.b64encode(secrets.token_bytes(16)).decode())


def test_master_key_must_be_base64() -> None:
    with pytest.raises(SecretStoreConfigError, match="base64"):
        decode_master_key("not base64 at all !!")


def test_generated_master_key_is_accepted() -> None:
    assert len(decode_master_key(generate_master_key())) == MASTER_KEY_BYTES


def test_key_material_never_appears_in_repr() -> None:
    master_key = secrets.token_bytes(MASTER_KEY_BYTES)
    encoded = base64.b64encode(master_key).decode()

    rendered = repr(EnvKeyBackend(master_key))

    assert encoded not in rendered
    assert "<redacted>" in rendered


def test_factory_builds_the_env_key_backend() -> None:
    settings = SecretStoreSettings(master_key=SecretStr(generate_master_key()))

    assert isinstance(build_secret_store(settings), EnvKeyBackend)


def test_factory_requires_a_master_key() -> None:
    with pytest.raises(SecretStoreConfigError, match="ICEBERG_MASTER_KEY"):
        build_secret_store(SecretStoreSettings())


def test_vault_backend_is_a_documented_seam() -> None:
    settings = SecretStoreSettings(secret_store_backend="vault")  # noqa: S106  # a backend name

    with pytest.raises(SecretStoreConfigError, match="ADR 0007"):
        build_secret_store(settings)


def test_cli_generates_a_usable_master_key(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli_main(["generate-master-key"]) == 0

    printed = capsys.readouterr().out.strip()
    assert len(decode_master_key(printed)) == MASTER_KEY_BYTES


def test_cli_generate_pepper_prints_only_a_ref(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("ICEBERG_MASTER_KEY", generate_master_key())

    assert cli_main(["generate-pepper"]) == 0

    printed = capsys.readouterr().out.strip()
    assert printed.startswith("envkey:1:pepper:")


def test_cli_seal_reads_the_secret_from_stdin(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    master_key = generate_master_key()
    monkeypatch.setenv("ICEBERG_MASTER_KEY", master_key)
    monkeypatch.setattr("sys.stdin", _FakeStdin(f"{CREDENTIAL}\n"))

    assert cli_main(["seal"]) == 0

    ref = capsys.readouterr().out.strip()
    store = EnvKeyBackend(decode_master_key(master_key))
    assert store.open(ref).get_secret_value() == CREDENTIAL


def test_cli_reports_configuration_errors_without_a_traceback(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("ICEBERG_MASTER_KEY", raising=False)

    assert cli_main(["generate-pepper"]) == 2
    assert "ICEBERG_MASTER_KEY" in capsys.readouterr().err


class _FakeStdin:
    def __init__(self, text: str) -> None:
        self._text = text

    def read(self) -> str:
        return self._text
