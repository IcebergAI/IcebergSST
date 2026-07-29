"""Secret storage for the secrets IcebergSST itself holds (ADR 0007).

Start at :mod:`iceberg_core.secrets.base` for the interface and the sealed-ref
model; :mod:`iceberg_core.secrets.env_key` is the default backend.
"""

from iceberg_core.secrets.base import (
    SealedRefError,
    SecretPurpose,
    SecretStore,
    SecretStoreConfigError,
    SecretStoreError,
)
from iceberg_core.secrets.env_key import EnvKeyBackend, generate_master_key
from iceberg_core.secrets.factory import build_secret_store

__all__ = [
    "EnvKeyBackend",
    "SealedRefError",
    "SecretPurpose",
    "SecretStore",
    "SecretStoreConfigError",
    "SecretStoreError",
    "build_secret_store",
    "generate_master_key",
]
