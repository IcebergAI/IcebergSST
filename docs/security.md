# Security model & threat model

IcebergSST handles live secret material and its database maps *where* secrets live. That makes the
system itself a high-value target. This document states the trust boundaries and mitigations.

## Assets
- **The findings database** — reveals which systems contain secrets (even without plaintext).
- **Connector credentials** — tokens/passwords used to read Confluence/Jira/file shares.
- **The fingerprint pepper** and app encryption key.
- **In-flight content** being scanned inside an engine.

## Trust boundaries
1. **Browser ↔ API** — OIDC-authenticated sessions, RBAC on every route (ADR 0005).
2. **Engine ↔ API** — per-engine token; engines may submit results and lease tasks, nothing else.
   Engines **cannot** read findings or credentials (ADR 0002).
3. **API ↔ Postgres** — only the API holds DB credentials.
4. **API ↔ secret store** — credentials and pepper accessed only through the `SecretStore`
   interface (ADR 0007).

## Key mitigations
- **No plaintext at rest.** Redaction happens in the engine; only masked snippet + salted hash
  are stored (ADR 0004). A DB compromise does not leak secrets.
- **Engine credential isolation.** A compromised engine's blast radius is limited to the content
  of its current task — it has no DB access and no other source's credentials.
- **Peppered hashes.** Secret hashes use a pepper from the secret store, so they aren't
  brute-forceable offline from a DB dump.
- **Encrypted connector credentials.** Stored via the secret store (AES-GCM/Fernet by default;
  Vault in prod). Never logged; never returned by the API in plaintext.
- **Full audit trail.** Every finding state/assignee/comment change writes a `FindingEvent`.
- **RBAC.** admin/analyst/viewer enforced server-side; the UI is not the enforcement point.
- **Transport.** TLS everywhere; engine↔API mutual auth (mTLS) available as hardening.

## Operator responsibilities (env-key backend)
With the default `EnvKeyBackend`, the operator owns:
- Protecting and rotating the master encryption key (via env/k8s secret).
- Restricting network access to Postgres and Redis to the API/engine roles.
- Moving to the Vault backend for production-grade key separation (ADR 0007).

## Out of scope (MVP)
Multi-tenancy isolation, image OCR, external ticket creation. Adding any of these must revisit
this threat model.
