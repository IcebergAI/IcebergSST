# ADR 0003 — Detection engine: custom regex + entropy + proximity

**Status:** Accepted

## Context
Detection could wrap existing scanners (detect-secrets, gitleaks, TruffleHog), be fully custom,
or a hybrid. Wrapping is fast to a working product but ties us to external binaries and their
output formats; our sources (Confluence pages, attachments, file shares) are not git repos and
don't fit those tools' assumptions cleanly.

## Decision
Build a **custom Python detection engine** combining:
- **Regex rules** for structured secrets (AWS keys, private-key blocks, tokens, etc.).
- **Shannon entropy** scoring to catch high-entropy strings not covered by a specific rule.
- **Keyword proximity** (e.g. `password`, `secret`, `token` near a candidate) to raise
  confidence and reduce false positives.

Each match carries a confidence score derived from the combination.

## Consequences
- Full control over rule behavior, output shape, and the content model (text units from arbitrary
  connectors, not just files).
- No external binaries in the engine image.
- We own rule maintenance and false-positive tuning from the start; mitigated by seeding the
  initial rule pack with well-known secret patterns and by DB-side suppressions (ADR 0008).
