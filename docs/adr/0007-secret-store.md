# ADR 0007 — Secret store: pluggable, env-key default, Vault later

**Status:** Accepted

## Context
IcebergSST must protect secrets *it* holds: connector credentials (Confluence/Jira tokens, SMB
creds), the OIDC client secret, and the fingerprint pepper. Options ranged from full KMS/Vault
envelope encryption to app-level encryption with an env-injected key.

## Decision
Define a **pluggable `SecretStore` interface** in `packages/core`. Ship two backends:
- **`EnvKeyBackend` (default):** app-level AES-GCM/Fernet encryption with a master key injected
  via environment / k8s secret. This is the ".env now" path.
- **`VaultBackend` (documented seam):** HashiCorp Vault / cloud KMS for production, added later.

All credential access in the codebase goes through the interface, never raw env reads.

## Consequences
- Fast to start; no external KMS dependency for dev or small installs.
- Clear upgrade path to Vault without touching call sites.
- With the env-key backend, key management (rotation, protection) is the operator's
  responsibility — documented in `docs/security.md`.
