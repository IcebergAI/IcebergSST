# ADR 0004 — Finding storage: redacted snippet + salted hash, no plaintext

**Status:** Accepted

## Context
A secrets scanner necessarily handles live secret material. Storing the plaintext (even
encrypted) makes the findings database a high-value secret store in its own right. Storing only a
hash with no context makes triage hard.

## Decision
A finding stores a **redacted snippet** (masked context, e.g. `AKIA…4 chars` with surrounding
non-secret text) **plus a salted hash** of the secret value for dedup/fingerprinting. The
**plaintext is never persisted** and never leaves the engine — redaction happens inside the
worker before results are transmitted.

## Consequences
- The findings DB cannot be used to recover secrets; a DB compromise leaks *where* secrets are,
  not the secrets themselves.
- Analysts still get enough context (masked snippet, resource locator) to triage.
- Trade-off: no after-the-fact verification of a stored secret's validity. Acceptable for MVP;
  verification, if added, would happen live in the engine, never from stored data.
- The hash uses a pepper from the secret store (ADR 0007) so hashes aren't brute-forceable
  offline.
