# Detection rules

Detection is a **custom engine** (ADR 0003) combining regex, entropy, and keyword proximity.
Rules are **code-defined** and versioned (ADR 0008); false-positive tuning is **DB data**.

## Rule packs
A rule pack is a versioned set of rules shipped inside the engine image (`packages/detect`,
`iceberg_detect/rulepacks/*.yaml`). Findings record the `rule_id` and `rulepack_version` that
produced them, so results are reproducible. Bump `version` whenever a rule changes.

```python
from iceberg_detect import detect, load_named_pack

pack = load_named_pack()            # the packaged "seed" pack
result = detect(text, pack)         # redacted, scored matches
```

### Rule shape (YAML)
```yaml
version: "2026.07.1"
rules:
  - id: aws-access-key-id          # lowercase-hyphenated; reaches URLs and metric labels
    description: AWS Access Key ID
    severity: high                 # low | medium | high | critical
    regex: 'AKIA[0-9A-Z]{16}'
    flags: []                      # ignorecase | multiline | dotall
    entropy_min: null              # null = regex alone is sufficient
    keywords: [aws, access, key]   # proximity boosts confidence
    keyword_window: 64             # how far either side to look, in characters
    requires_keyword: false        # true = no keyword, no match (not just a lower score)
    redaction: keep_prefix         # full | keep_prefix | keep_suffix
    redaction_keep: 4              # ceiling on revealed characters
    base_confidence: 0.8           # before the entropy and proximity signals adjust it
```

A rule that needs surrounding context to match should capture the secret in a group named
`secret` — `client_secret\s*=\s*(?P<secret>\S+)`. Only that group is reported, hashed, and masked;
without it the fingerprint would change whenever the spacing did, and the snippet would mask the
word `client_secret` rather than what follows it.

### Loading fails loudly
A pack that half-loads is worse than one that refuses to: a rule dropped for a typo is a secret
type nobody is looking for, and nothing downstream reports its absence. `load_pack` raises
`RulePackError`, naming the rule, for an uncompilable regex, an unknown severity/flag/redaction
strategy, an unknown or missing key, a duplicate id, a malformed id, an out-of-range
`base_confidence`, `requires_keyword` without keywords, or a missing version.

It also rejects **catastrophic backtracking**: an unbounded quantifier applied to a group that
already contains one (`(\w+)+`) has exponentially many ways to fail a match, and `re` has no
timeout while rules run over attacker-supplied attachment text. The check is static and
conservative — it catches the shape that causes the blow-up in practice, and content units stay
size-capped as well.

## Detection signals
1. **Regex** — matches structured secrets (cloud keys, private-key blocks, JWT-like tokens,
   connection strings, etc.).
2. **Shannon entropy** — flags high-entropy candidate strings not covered by a specific regex;
   `entropy_min` gates a rule or a generic high-entropy detector.
3. **Keyword proximity** — presence of terms like `password`, `secret`, `token`, `api_key` near a
   candidate raises confidence and helps suppress benign high-entropy noise (hashes, UUIDs).
   Matched on word boundaries, so `key` fires on `api_key` and not on `monkey`.

### Confidence
**Severity** comes from the rule; **confidence** is computed per match:

```
confidence = clip(base_confidence + entropy_bonus + proximity_adjustment, 0, 1)

entropy_bonus        = 0.2 × min(1, (entropy − entropy_min) / 1.5)   # 0 if the rule has no gate
proximity_adjustment = +0.15 with a keyword nearby, −0.10 without    # 0 if the rule has no keywords
```

Additive and shallow on purpose. A learned model would score better and explain worse, and "why is
this 0.85?" has to have an answer an analyst can act on — it is what tells them whether to tune the
rule or rotate the secret. The absence penalty is gentler than the presence bonus because prose
near a secret is strong evidence while its absence is weak: plenty of real credentials sit in
config blocks with no prose anywhere near them.

Matches scoring below the **confidence threshold** are dropped. The threshold is applied in the
engine and again at ingest, so neither role can silently disagree with the other (#70).

**Overlapping matches collapse to the strongest.** Two rules matching overlapping text have found
the same secret — distinct secrets cannot occupy the same characters — so reporting both would put
one credential in the queue twice under two rule ids. Highest confidence wins, then the longer
span. Every match found is still masked in every snippet, including the ones that lost.

## Seed rule pack (MVP scope)
16 rules covering the common, high-signal types: AWS access keys and secret keys, GCP service
accounts and API keys, Azure storage and client secrets, GitHub/Slack/Stripe tokens, Slack webhook
URLs, PEM private-key blocks, JWTs, connection-string passwords, Basic-auth headers, password
assignments — plus a generic high-entropy detector gated by mandatory proximity.

### Measured behaviour
`packages/detect/tests/test_seed_rulepack.py` asserts these rather than reporting them:

| Measure | Value |
|---|---|
| Rules with a positive fixture | 16 / 16 (a rule without one fails the suite) |
| False positives on the benign corpus | 0 / 20 |
| Throughput, ~30 KB page, one core | ~4 MB/s (test asserts a 100 KB/s floor) |

The benign corpus is the shapes that get mistaken for secrets in real documentation: git shas,
UUIDs, sha256 checksums, base64 of ordinary strings, Docker digests, ETags, and prose containing
the word "password". The throughput floor is deliberately far below what a laptop manages — it
catches a rule that turned quadratic, not a CI runner having a slow minute.

### Writing fixtures for a secret scanner
A new rule needs a positive fixture, and a fixture realistic enough to match the rule is realistic
enough to trip everything else that scans this repository. Two mechanisms, for two different
scanners:

- **gitleaks** (the CI job over the whole history) — mark the line `# gitleaks:allow`. Never add a
  `paths` entry to `.gitleaks.toml`; see the comments in that file for why it does not do what it
  appears to.
- **GitHub push protection** (server-side, cannot be configured from the repo) — it blocks the push
  outright for shapes like Slack and Stripe tokens. Build those fixtures from fragments with the
  `_fake(...)` helper in `test_seed_rulepack.py`, so the whole literal never appears in the file.

Neither is a reason to weaken the fixture: the value has to keep matching the rule, or the test
stops proving anything.

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
