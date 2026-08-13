"""Backend selection — the seam that keeps call sites backend-agnostic (ADR 0007).

Call sites ask for a :class:`~iceberg_core.secrets.base.SecretStore` and get
whichever backend the deployment configured. Swapping ``env_key`` for a Vault
backend is a configuration change plus one class here, not a sweep through the
codebase.

**The Vault seam.** ``ICEBERG_SECRET_STORE_BACKEND=vault`` is a recognised,
validated value that raises a deliberate error until the backend lands (M4
hardening) — it is a documented seam, not a supported backend, so no deployment
can be running on a half-built one. A ``VaultBackend`` implements the same two
primitives — seal to an opaque ref, open a ref — with the ref pointing at a
Vault path (``vault:1:<mount>/<path>#<version>``) instead of carrying
ciphertext, and with Vault's transit/KV engine holding the key material the
operator would otherwise manage by hand. Nothing above this module changes.

It must also answer all three key accessors — ``get_pepper``,
``get_previous_pepper``, ``get_correlation_key``. The first and last are
abstract precisely so that cannot be forgotten: a backend that inherited a
``None`` correlation key would disable exposure clustering in silence, because
ingest fails open on that call (ADR 0011).
"""

from iceberg_core.config import SecretStoreSettings, get_secret_store_settings
from iceberg_core.secrets.base import SecretStore, SecretStoreConfigError
from iceberg_core.secrets.env_key import EnvKeyBackend


def build_secret_store(settings: SecretStoreSettings | None = None) -> SecretStore:
    """Return the configured secret store."""
    resolved = settings or get_secret_store_settings()
    match resolved.secret_store_backend:
        case "env_key":
            return EnvKeyBackend.from_settings(resolved)
        case "vault":
            raise SecretStoreConfigError(
                "the vault backend is a documented seam, not yet implemented "
                "(ADR 0007); use ICEBERG_SECRET_STORE_BACKEND=env_key"
            )
