"""SecretStore interface + EnvKeyBackend (issue #24, ADR 0007).

What this protects: connector credentials (Confluence/Jira tokens, SMB creds), the
OIDC client secret, and the fingerprint pepper. Every access goes through this
interface — no call site reads a credential out of the environment directly.

Reference semantics
-------------------
:meth:`SecretStore.put` returns an opaque :class:`SecretRef`. Callers persist the
*ref* and nothing else: ``Source.credential_ref`` holds one (issue #32), and the
plaintext is recovered only by handing the ref back to :meth:`SecretStore.get`.
The ref's internal structure is backend-specific and must not be parsed by
callers — ``EnvKeyBackend`` packs the ciphertext into the ref itself, whereas a
Vault backend would return a pointer like ``vault:v1:secret/data/sources/42#token``.

Vault seam
----------
:class:`VaultBackend` is not implemented here. Adding it means implementing this
protocol against Vault's KV v2 API and selecting it by config — no call site
changes, because nothing outside this module knows how a ref is built.
"""

import base64
import os
from typing import NewType, Protocol, runtime_checkable

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SecretRef = NewType("SecretRef", str)
"""Opaque handle to stored secret material. Persist this; never the plaintext."""

_SCHEME = "icbg"
_VERSION = "v1"
_NONCE_BYTES = 12
KEY_BYTES = 32


class SecretStoreError(Exception):
    """Raised when a secret cannot be stored, retrieved, or decrypted."""


@runtime_checkable
class SecretStore(Protocol):
    """Backend-agnostic secret storage."""

    def put(self, plaintext: str) -> SecretRef:
        """Store ``plaintext`` and return an opaque reference to it."""
        ...

    def get(self, ref: SecretRef) -> str:
        """Recover the plaintext behind ``ref``.

        Raises :class:`SecretStoreError` if the ref is malformed, was produced by
        a different backend, or fails authentication.
        """
        ...

    def pepper(self) -> bytes:
        """Return the fingerprint pepper (ADR 0006).

        Read through the store rather than from the environment so that rotation
        and backend swaps have exactly one code path. The API reads this and
        hands it to engines in the lease response (ADR 0009); engines never call
        a secret store themselves.
        """
        ...


class EnvKeyBackend:
    """App-layer AES-GCM encryption with a master key injected via env/k8s secret.

    This is the ".env now, Vault later" default from ADR 0007. The returned ref is
    self-contained — ``icbg.v1.<base64url(nonce || ciphertext)>`` — so no side
    table is needed and the store has no database dependency.

    Operator responsibilities (protecting and rotating the master key, protecting
    the pepper) are documented in ``docs/security.md``.
    """

    def __init__(self, *, master_key: bytes, pepper: bytes) -> None:
        if len(master_key) != KEY_BYTES:
            raise SecretStoreError(f"master key must be {KEY_BYTES} bytes, got {len(master_key)}")
        if not pepper:
            raise SecretStoreError("fingerprint pepper must not be empty")
        self._aesgcm = AESGCM(master_key)
        self._pepper = pepper

    @classmethod
    def from_values(cls, *, master_key_b64: str, pepper_b64: str) -> "EnvKeyBackend":
        """Build from the base64 forms carried in settings.

        Takes decoded values from :class:`~iceberg_core.config.ApiSettings`, not
        from ``os.environ`` — the settings object is the only env reader.
        """
        try:
            master_key = base64.b64decode(master_key_b64, validate=True)
            pepper = base64.b64decode(pepper_b64, validate=True)
        except (ValueError, TypeError) as exc:
            raise SecretStoreError("master key and pepper must be valid base64") from exc
        return cls(master_key=master_key, pepper=pepper)

    @staticmethod
    def generate_key() -> str:
        """Mint a fresh base64 master key, for bootstrap and `.env.example` docs."""
        return base64.b64encode(os.urandom(KEY_BYTES)).decode()

    def put(self, plaintext: str) -> SecretRef:
        nonce = os.urandom(_NONCE_BYTES)
        ciphertext = self._aesgcm.encrypt(nonce, plaintext.encode(), None)
        payload = base64.urlsafe_b64encode(nonce + ciphertext).decode()
        return SecretRef(f"{_SCHEME}.{_VERSION}.{payload}")

    def get(self, ref: SecretRef) -> str:
        scheme, _, rest = ref.partition(".")
        version, _, payload = rest.partition(".")
        if scheme != _SCHEME or version != _VERSION or not payload:
            raise SecretStoreError("not an EnvKeyBackend secret reference")
        try:
            raw = base64.urlsafe_b64decode(payload)
            nonce, ciphertext = raw[:_NONCE_BYTES], raw[_NONCE_BYTES:]
            return self._aesgcm.decrypt(nonce, ciphertext, None).decode()
        except Exception as exc:
            # Deliberately opaque: the caller learns the ref did not open, not why.
            raise SecretStoreError("could not decrypt secret reference") from exc

    def pepper(self) -> bytes:
        return self._pepper
