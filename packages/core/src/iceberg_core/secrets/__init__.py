"""Pluggable secret storage for the material IcebergSST itself holds (ADR 0007).

Import submodules directly (``from iceberg_core.secrets.store import EnvKeyBackend``);
this package deliberately has no re-export surface, matching the rest of
``iceberg_core``.
"""
