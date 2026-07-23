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

## Pepper distribution & rotation
The fingerprint pepper is read through the secret store by the **API only** and delivered to
engines per-task in the lease response (ADR 0009) — never baked into images or engine env.
Because the pepper participates in every fingerprint (ADR 0006), **rotating it invalidates all
finding identities**. Rotation therefore requires either a migration that re-keys stored
fingerprints or a dual-hash transition window; the procedure belongs in the key-rotation
runbook (M4 hardening).

## Consequences
- Fast to start; no external KMS dependency for dev or small installs.
- Clear upgrade path to Vault without touching call sites.
- With the env-key backend, key management (rotation, protection) is the operator's
  responsibility — documented in `docs/security.md`.
- Pepper rotation is deliberately expensive; treat the pepper as long-lived and protect it
  accordingly.
