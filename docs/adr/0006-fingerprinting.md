# ADR 0006 — Finding fingerprint & re-scan reconciliation

**Status:** Accepted

## Context
Findings must have a stable identity so that triage decisions persist across repeated scans and
so the system can tell new leaks from already-seen ones. Identity could ignore location (secret
+ rule only) or include it.

## Decision
The fingerprint is:

```
fingerprint = hash(connector_type, resource_locator, rule_id, salted_secret_hash)
```

Including the **resource locator** means the same secret in two places is two findings, each
independently triageable — important for remediation ("this key is in page X *and* page Y").

**Locator granularity:** the locator used in the fingerprint is **coarse and stable** — e.g.
`(page id, attachment name)` — and explicitly **excludes line/offset**. Offsets are stored on
the finding for display only. Otherwise any edit above a secret would re-fingerprint it and
orphan its triage state. Corollary: the same secret value matched by the same rule multiple
times within one locator collapses to one finding.

**Rule-id stability:** `rule_id` is part of finding identity and therefore a stable contract.
Renaming or splitting a rule requires a migration mapping old ids to new; rule packs must not
rename ids casually.

**Re-scan reconciliation** (run by the API, per source, **only when a scan reaches
`completed`** — a `partial` or `failed` scan never auto-resolves findings; see ADR 0009):
- new fingerprint → `open`
- matching fingerprint → keep triage state, bump `last_seen_scan`
- previously-open, now-missing → `resolved (auto)`
- suppressed fingerprint → recorded, not surfaced as active

## Consequences
- Analyst decisions (false-positive, accepted-risk) survive re-scans.
- A resolved secret that reappears re-opens automatically.
- Moving a secret to a new location produces a new finding (loses the old triage state); accepted
  as the cost of per-location precision.
