"""`EnvKeyBackend` — app-layer AES-GCM with an env-injected master key.

The default backend (ADR 0007): the ".env now, Vault later" path. Sealed refs are
**self-contained** — the ciphertext travels inside the ref — so there is no
separate blob store to operate, and a `credential_ref` column holds everything
needed to open the secret *given the key*.

Ref format::

    envkey:1:<purpose>:<base64url(nonce || ciphertext || tag)>

The version and purpose are plaintext (they select how to open the envelope) and
also authenticated: they go into the AEAD's associated data, so editing either
one in a database row makes the ref fail to open instead of opening as something
else.
"""

import base64
import secrets as _secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from iceberg_core.config import SecretStoreSettings
from iceberg_core.secrets.base import (
    SealedRefError,
    SecretPurpose,
    SecretStore,
    SecretStoreConfigError,
)

SCHEME = "envkey"
VERSION = "1"
MASTER_KEY_BYTES = 32  # AES-256
NONCE_BYTES = 12  # GCM standard nonce
PEPPER_BYTES = 32
CORRELATION_KEY_BYTES = 32

_GENERATE_HINT = "generate one with: python -m iceberg_core.secrets generate-master-key"


def generate_master_key() -> str:
    """Return a fresh base64 master key, ready to paste into ``ICEBERG_MASTER_KEY``."""
    return base64.b64encode(_secrets.token_bytes(MASTER_KEY_BYTES)).decode()


def decode_master_key(encoded: str) -> bytes:
    """Decode and validate a configured master key.

    Accepts standard and URL-safe base64 (operators paste from both) and insists
    on exactly 32 bytes — a short key is a silently weaker deployment, which is
    worse than a startup failure.
    """
    padded = encoded.strip()
    padded += "=" * (-len(padded) % 4)
    try:
        # binascii.Error (what b64decode raises) is a ValueError subclass.
        key = base64.b64decode(padded.replace("-", "+").replace("_", "/"), validate=True)
    except ValueError as exc:
        raise SecretStoreConfigError(
            f"ICEBERG_MASTER_KEY is not valid base64; {_GENERATE_HINT}"
        ) from exc
    if len(key) != MASTER_KEY_BYTES:
        raise SecretStoreConfigError(
            f"ICEBERG_MASTER_KEY must decode to {MASTER_KEY_BYTES} bytes, "
            f"got {len(key)}; {_GENERATE_HINT}"
        )
    return key


class EnvKeyBackend(SecretStore):
    """AES-256-GCM secret store keyed by a master key from the environment."""

    def __init__(
        self,
        master_key: bytes,
        *,
        pepper_ref: str | None = None,
        previous_pepper_ref: str | None = None,
        correlation_key_ref: str | None = None,
    ) -> None:
        if len(master_key) != MASTER_KEY_BYTES:
            raise SecretStoreConfigError(
                f"master key must be {MASTER_KEY_BYTES} bytes, got {len(master_key)}"
            )
        self._aead = AESGCM(master_key)
        self._pepper_ref = pepper_ref
        self._previous_pepper_ref = previous_pepper_ref
        self._correlation_key_ref = correlation_key_ref

    @classmethod
    def from_settings(cls, settings: SecretStoreSettings) -> EnvKeyBackend:
        if settings.master_key is None:
            raise SecretStoreConfigError(f"ICEBERG_MASTER_KEY is not set; {_GENERATE_HINT}")
        return cls(
            decode_master_key(settings.master_key.get_secret_value()),
            pepper_ref=settings.fingerprint_pepper_ref,
            previous_pepper_ref=settings.previous_fingerprint_pepper_ref,
            correlation_key_ref=settings.correlation_key_ref,
        )

    def __repr__(self) -> str:
        # Never render key material, not even truncated: this object ends up in
        # tracebacks and debug logs.
        return f"{type(self).__name__}(master_key=<redacted>)"

    def seal_bytes(self, plaintext: bytes, *, purpose: SecretPurpose) -> str:
        nonce = _secrets.token_bytes(NONCE_BYTES)
        envelope = self._aead.encrypt(nonce, plaintext, _associated_data(purpose))
        payload = base64.urlsafe_b64encode(nonce + envelope).decode().rstrip("=")
        return f"{SCHEME}:{VERSION}:{purpose.value}:{payload}"

    def open_bytes(self, ref: str, *, purpose: SecretPurpose) -> bytes:
        scheme, version, ref_purpose, payload = _split_ref(ref)
        if scheme != SCHEME:
            raise SealedRefError(f"ref is not an {SCHEME} ref")
        if version != VERSION:
            raise SealedRefError(f"unsupported {SCHEME} ref version {version!r}")
        if ref_purpose != purpose.value:
            raise SealedRefError(f"ref was sealed for {ref_purpose!r}, opened as {purpose.value!r}")
        raw = _decode_payload(payload)
        if len(raw) <= NONCE_BYTES:
            raise SealedRefError("ref payload is truncated")
        try:
            return self._aead.decrypt(
                raw[:NONCE_BYTES], raw[NONCE_BYTES:], _associated_data(purpose)
            )
        except InvalidTag as exc:
            raise SealedRefError("ref failed authentication (wrong key or tampered)") from exc

    def generate_pepper_ref(self) -> str:
        """Seal a freshly generated pepper and return its ref.

        Rotating the pepper invalidates every finding fingerprint (ADR 0006/0007),
        so this is a bootstrap operation, not routine maintenance.
        """
        return self.seal_bytes(_secrets.token_bytes(PEPPER_BYTES), purpose=SecretPurpose.PEPPER)

    def get_pepper(self) -> bytes:
        if self._pepper_ref is None:
            raise SecretStoreConfigError(
                "ICEBERG_FINGERPRINT_PEPPER_REF is not set; "
                "generate one with: python -m iceberg_core.secrets generate-pepper"
            )
        return self.open_bytes(self._pepper_ref, purpose=SecretPurpose.PEPPER)

    def get_previous_pepper(self) -> bytes | None:
        """The outgoing pepper during a rotation window (#64).

        Sealed with the same master key, so rotating the pepper and rotating the
        master key are independent operations — which they need to be, because
        one is a re-scan and the other is a re-seal.
        """
        if self._previous_pepper_ref is None:
            return None
        return self.open_bytes(self._previous_pepper_ref, purpose=SecretPurpose.PEPPER)

    def generate_correlation_key_ref(self) -> str:
        """Seal a freshly generated correlation key and return its ref.

        Rotating this key only invalidates correlation ids, which can be
        re-derived from stored hashes (`reindex-correlation`) — far cheaper than
        a pepper rotation, and the reason the two are separate keys (ADR 0010).
        """
        return self.seal_bytes(
            _secrets.token_bytes(CORRELATION_KEY_BYTES), purpose=SecretPurpose.CORRELATION
        )

    def get_correlation_key(self) -> bytes | None:
        if self._correlation_key_ref is None:
            return None
        return self.open_bytes(self._correlation_key_ref, purpose=SecretPurpose.CORRELATION)


def _associated_data(purpose: SecretPurpose) -> bytes:
    return f"{SCHEME}:{VERSION}:{purpose.value}".encode()


def _split_ref(ref: str) -> tuple[str, str, str, str]:
    parts = ref.split(":", 3)
    if len(parts) != 4:
        raise SealedRefError("ref is malformed")
    return parts[0], parts[1], parts[2], parts[3]


def _decode_payload(payload: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
    except ValueError as exc:
        raise SealedRefError("ref payload is not valid base64") from exc
