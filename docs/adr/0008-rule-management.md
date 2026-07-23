# ADR 0008 — Rule management: code-defined rules + DB suppressions

**Status:** Accepted

## Context
Detection rules and false-positive handling could be code-defined, fully UI/DB-editable, or a
split. Fully UI-editable rules turn regexes into untrusted runtime data engines must fetch and
validate (a bad or catastrophic-backtracking regex becomes an availability risk).

## Decision
Split by concern:
- **Rules** (regex + entropy/proximity config) are **code-defined** in versioned rule packs
  (YAML + Python) shipped inside the engine image. Findings record `rule_id` +
  `rulepack_version`.
- **Suppressions / allowlists** are **DB data**, editable by analysts through the UI. Scopes:
  per-path glob, per-fingerprint, per-rule; optional expiry.

Suppressions are applied server-side at result ingest and surfaced in the UI.

## Consequences
- Detection logic is reviewed, versioned, and reproducible; no runtime regex injection risk.
- Analysts still get fast, self-service tuning where they need it (allowlisting noise).
- Adding a new rule requires a release of the engine image — acceptable given the safety benefit.
  A future UI for *proposing* rules (still merged via code) can be layered on if needed.
