# Security model & threat model

IcebergSST handles live secret material and its database maps *where* secrets live. That makes the
system itself a high-value target. This document states the trust boundaries and mitigations.

## Assets
- **The findings database** — reveals which systems contain secrets (even without plaintext).
- **Connector credentials** — tokens/passwords used to read Confluence/Jira/file shares.
- **The fingerprint pepper** and app encryption key.
- **In-flight content** being scanned inside an engine.

## Trust boundaries
1. **Browser ↔ API** — OIDC-authenticated sessions, RBAC on every route (ADR 0005). Session
   cookies + HTMX form posts require **CSRF protection** (token per session, enforced on every
   mutating route).
2. **Engine ↔ API** — per-engine token over mandatory TLS; engines may lease tasks and submit
   results, nothing else. The **lease response carries the source credential (task-scoped) and
   the fingerprint pepper** — the only moment either transits to an engine (ADR 0002, 0009).
3. **Engine ↔ Redis** — a shared trust surface: any engine can read/enqueue broker messages.
   Mitigations: payloads are task-id hints only (no secrets, no specs), everything is validated
   at lease time, and Redis runs with auth + TLS.
4. **Engine ↔ scanned content** — attachments and pages are **attacker-editable input**
   attacking the extraction parsers. Mitigations: size caps, extraction timeouts,
   decompression-ratio limits, per-unit failure isolation; consider sandboxing extraction.
5. **API ↔ Postgres** — only the API holds DB credentials.
6. **API ↔ secret store** — credentials and pepper accessed only through the `SecretStore`
   interface (ADR 0007).

## Key mitigations
- **No plaintext at rest.** Redaction happens in the engine; only masked snippet + salted hash
  are stored (ADR 0004). A DB compromise does not leak secrets.
- **Engine credential isolation (honest statement).** A compromised engine can read the content
  it is given, the credential of sources whose tasks it leases, and the shared pepper — but not
  the findings DB, credentials at rest, or other engines' results. Narrower than direct-DB
  workers; not zero.
- **Peppered hashes.** Secret hashes use a pepper from the secret store, so they aren't
  brute-forceable offline from a DB dump.
- **Encrypted connector credentials.** Stored via the secret store (AES-GCM/Fernet by default;
  Vault in prod). Never logged; never returned by the API in plaintext.
- **Full audit trail.** Every finding state/assignee/comment change writes a `FindingEvent`.
- **RBAC.** admin/analyst/viewer enforced server-side; the UI is not the enforcement point.
- **Transport.** TLS everywhere; engine↔API mutual auth (mTLS) available as hardening.

## Notification egress
Webhook channels send redacted snippets + resource locations to arbitrary URLs — a deliberate
egress channel. Channel configuration is **admin-only**, the payload is documented, and adding
a channel is audit-logged.

## Bootstrap
- **First admin:** OIDC-only auth needs a seed — an env-configured OIDC subject (or email) is
  granted `admin` on first login. All later role changes happen in-app and are audited.
- **First engine token:** minted at deploy time via a CLI/management command (compose) or a
  provisioning Job (Helm) — never a default credential baked into an image.

## Secret store in practice (`EnvKeyBackend`)
The default backend (ADR 0007) is AES-256-GCM with a master key injected as
`ICEBERG_MASTER_KEY`. Secrets are stored as **sealed refs** — self-contained, opaque strings safe
to keep in a database column (`Source.credential_ref`), to log, and to return from the API:

```
envkey:1:<purpose>:<base64url(nonce || ciphertext || tag)>
```

- **Purpose binding.** `credential`, `pepper`, and `generic` refs are cryptographically distinct:
  the purpose is authenticated data, so a credential ref cannot be opened as the pepper, and
  editing the purpose in a database row makes the ref fail to open rather than open as something
  else.
- **Single reader of the environment.** Only `iceberg_core.config` reads env vars; everything else
  goes through the `SecretStore` interface. `packages/core/tests/test_no_raw_env_reads.py` walks the
  shipped source and fails on any `os.environ`/`os.getenv` elsewhere.
- **Bootstrap commands** (see `.env.example`):

  ```
  python -m iceberg_core.secrets generate-master-key   # → ICEBERG_MASTER_KEY
  python -m iceberg_core.secrets generate-pepper       # → ICEBERG_FINGERPRINT_PEPPER_REF
  python -m iceberg_core.secrets seal < credential     # → an opaque credential ref
  ```

  `generate-pepper` prints only the sealed ref — the pepper itself is never displayed. `seal` reads
  from stdin, never from arguments, because arguments are visible in `ps`.
- **Vault seam.** `ICEBERG_SECRET_STORE_BACKEND=vault` is recognised and fails with a pointer to
  ADR 0007 until the backend lands. A Vault backend implements the same two primitives, with the
  ref naming a Vault path instead of carrying ciphertext; no call site changes.

## Operator responsibilities (env-key backend)
With the default `EnvKeyBackend`, the operator owns:
- Protecting and rotating the master encryption key (via env/k8s secret).
- Protecting the fingerprint pepper — rotating it invalidates all finding identities and
  requires the documented re-key procedure (ADR 0007).
- Restricting network access to Postgres and Redis to the API/engine roles; Redis auth + TLS.
- Moving to the Vault backend for production-grade key separation (ADR 0007).

## Out of scope (MVP)
Multi-tenancy isolation, image OCR, external ticket creation. Adding any of these must revisit
this threat model.
