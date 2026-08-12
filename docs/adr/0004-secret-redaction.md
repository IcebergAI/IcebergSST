# ADR 0004 — Finding storage: redacted snippet + salted hash, no plaintext

**Status:** Accepted

## Context
A secrets scanner necessarily handles live secret material. Storing the plaintext (even
encrypted) makes the findings database a high-value secret store in its own right. Storing only a
hash with no context makes triage hard.

## Decision
A finding stores a **redacted snippet** (masked context, e.g. `AKIA…4 chars` with surrounding
non-secret text) **plus a salted hash** of the secret value for dedup/fingerprinting. The
**plaintext is never persisted** and never leaves the engine by default — redaction happens inside
the worker before results are transmitted. ADR 0010 defines the sole exception: an explicitly
authorized, fixed provider request for live credential validation. Plaintext still never crosses
the engine-to-API, Redis, database, log, metric, audit, notification, or browser boundaries.

## Consequences
- The findings DB cannot be used to recover secrets; a DB compromise leaks *where* secrets are,
  not the secrets themselves.
- Analysts still get enough context (masked snippet, resource locator) to triage.
- Trade-off: validation can happen only while plaintext is transient in the engine, under the
  dual opt-in and provider contract in ADR 0010; it can never be reconstructed from stored data.
- The hash uses a pepper from the secret store (ADR 0007) so hashes aren't brute-forceable
  offline.
