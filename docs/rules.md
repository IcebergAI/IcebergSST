# Detection rules

Detection is a **custom engine** (ADR 0003) combining regex, entropy, and keyword proximity.
Rules are **code-defined** and versioned (ADR 0008); false-positive tuning is **DB data**.

## Rule packs
A rule pack is a versioned set of rules shipped inside the engine image. Findings record the
`rule_id` and `rulepack_version` that produced them, so results are reproducible.

### Rule shape (YAML)
```yaml
- id: aws-access-key-id
  description: AWS Access Key ID
  severity: high
  regex: 'AKIA[0-9A-Z]{16}'
  entropy_min: null            # regex alone is sufficient
  keywords: [aws, access, key] # proximity boosts confidence
  redaction: keep_prefix       # how to mask in the snippet
```

## Detection signals
1. **Regex** — matches structured secrets (cloud keys, private-key blocks, JWT-like tokens,
   connection strings, etc.).
2. **Shannon entropy** — flags high-entropy candidate strings not covered by a specific regex;
   `entropy_min` gates a rule or a generic high-entropy detector.
3. **Keyword proximity** — presence of terms like `password`, `secret`, `token`, `api_key` near a
   candidate raises confidence and helps suppress benign high-entropy noise (hashes, UUIDs).

**Confidence** is computed from the combination of signals; **severity** comes from the rule.

## Seed rule pack (MVP scope)
Common, high-signal secret types: AWS keys, GCP/Azure keys, generic API tokens, private-key PEM
blocks, Slack/GitHub tokens, JWTs, and password-in-connection-string patterns — plus a generic
high-entropy detector gated by proximity.

## Suppressions (DB, analyst-editable)
Independent of rules. Scopes: `path_glob`, `fingerprint`, `rule`, optionally scoped to a source
and with an expiry. Applied server-side at result ingest and surfaced in the UI. This is how
analysts silence known-benign matches without a code change.

## Redaction
Each rule declares how its matches are masked for the stored snippet. The engine redacts **before**
transmitting results — plaintext never leaves the worker (ADR 0004). Implemented in
`iceberg_core.redaction`:

| Strategy | Example output |
|---|---|
| `full` (default) | `[20 chars redacted]` |
| `keep_prefix` | `AKIA…[16 chars redacted]` |
| `keep_suffix` | `[16 chars redacted]…MPLE` |

`keep` is a ceiling, not a promise. Nothing is revealed from a secret shorter than
`min_length_to_reveal` (16 by default), and never more than a third of a secret — four characters
of an AWS key id are a vendor tag, four characters of a short password are a head start. An unknown
strategy name raises at load time rather than falling back to something more revealing.

The stored snippet is bounded context (48 chars either side by default, 300 chars hard ceiling)
collapsed to a single line, with **every** secret in the window masked — the matched one, its
neighbours, and any unmatched literal repeat of the same value elsewhere in the window. As a last
defence the snippet is re-checked for the plaintext before it is returned; if it is still there the
engine raises rather than transmits.
