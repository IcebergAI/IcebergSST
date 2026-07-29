"""The `SecretStore` interface (ADR 0007).

Every secret IcebergSST holds — connector credentials, the OIDC client secret,
the fingerprint pepper — is reached through this interface. Nothing in the
codebase outside :mod:`iceberg_core.config` reads a credential out of the
environment; ``packages/core/tests/test_no_raw_env_reads.py`` enforces that.

A **sealed ref** is the only form a secret takes at rest: an opaque string safe
to store in a database column (``Source.credential_ref``), to log, and to return
from the API. Turning one back into a secret requires the backend, which
requires the master key — so a database dump on its own yields nothing.

Refs are bound to a **purpose**. A ref sealed as a connector credential cannot be
opened as the fingerprint pepper: the purpose is authenticated data in the
envelope, so swapping one for the other fails to decrypt rather than quietly
succeeding.
"""

from abc import ABC, abstractmethod
from enum import StrEnum

from pydantic import SecretStr


class SecretPurpose(StrEnum):
    """What a sealed ref is for. Cryptographically bound to the ciphertext."""

    CREDENTIAL = "credential"
    PEPPER = "pepper"
    GENERIC = "generic"


class SecretStoreError(Exception):
    """Base class for secret-store failures."""


class SecretStoreConfigError(SecretStoreError):
    """The store is misconfigured (missing/invalid master key, unknown backend)."""


class SealedRefError(SecretStoreError):
    """A ref is malformed, was sealed for another purpose, or failed to open.

    Deliberately undifferentiated: distinguishing "wrong key" from "tampered
    ciphertext" from "wrong purpose" would hand an attacker an oracle.
    """


class SecretStore(ABC):
    """Seal secrets into opaque refs and open them again."""

    @abstractmethod
    def seal_bytes(self, plaintext: bytes, *, purpose: SecretPurpose) -> str:
        """Return an opaque ref for ``plaintext``, bound to ``purpose``."""

    @abstractmethod
    def open_bytes(self, ref: str, *, purpose: SecretPurpose) -> bytes:
        """Return the bytes behind ``ref``, or raise :class:`SealedRefError`."""

    def seal(self, plaintext: str, *, purpose: SecretPurpose = SecretPurpose.CREDENTIAL) -> str:
        """Seal text (UTF-8). Defaults to the credential purpose."""
        return self.seal_bytes(plaintext.encode(), purpose=purpose)

    def open(self, ref: str, *, purpose: SecretPurpose = SecretPurpose.CREDENTIAL) -> SecretStr:
        """Open a text secret, wrapped so it cannot be logged by accident."""
        try:
            return SecretStr(self.open_bytes(ref, purpose=purpose).decode())
        except UnicodeDecodeError as exc:  # sealed as bytes, opened as text
            raise SealedRefError("sealed value is not UTF-8 text") from exc

    @abstractmethod
    def get_pepper(self) -> bytes:
        """Return the fingerprint pepper (ADR 0006).

        The API is the only role that calls this: engines receive the pepper for
        the lifetime of a task in the lease response (ADR 0009), never from
        their own configuration.
        """
