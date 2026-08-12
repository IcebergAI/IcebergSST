# ADR 0012 — Rotation guidance & remediation evidence

**Status:** Accepted

## Context
Closing a finding records a state change and, optionally, a comment. Nothing distinguishes "the
key was revoked, here is the ticket" from an administrative click, which makes closure reporting
untrustworthy and gives responders no provider-aware advice at the moment they need it (#142).

Three constraints shape the design: the platform must never execute rotation itself (non-goal),
must never store replacement credentials (non-goal), and has no file/blob storage anywhere — a
deliberate absence this feature should not quietly reverse.

## Decision

**Guidance is a versioned catalog shipped with the API**, not with rule packs.
`apps/api/src/iceberg_api/remediation/guidance.yaml` maps rule ids to advice split into the four
actions the issue names — **revoke, rotate, scope-reduce, remove-source** — with a required
`default` entry for rules without specific advice (`GET /remediation/guidance/{rule_id}` says
which entry answered). Rule packs live in engine images and report over a closed wire schema;
guidance riding them would couple advice releases to engine rollouts for content only the API
renders. The catalog is data in the invariant-3 sense — versioned and reviewed in git like a
rule pack — and its `version` is stamped onto every action recorded while it is live, so "what
were they told to do" survives catalog changes. A DB-backed, admin-editable catalog is named
future work, not built.

**A remediation action is a structured record with evidence links, not uploads.**
`remediation_action` rows carry: kind (the four verbs plus `other`), actor, when it was
performed vs when recorded, a note, up to ten evidence links (`{url, label}` — http(s) only, no
embedded userinfo, because a credential-bearing URL submitted as evidence would be this
product's own finding), the guidance version, a one-way verification (who/when), and a set-once
retraction (who/when/why). **Content is write-once**: a wrong record is retracted and a new one
recorded, and every mutation writes a `FindingEvent` (the finding's history) plus an
`AuditEvent` (`remediation.recorded|verified|retracted`) — the append-only trail is the
"immutable audit events" the acceptance criteria require, so the row itself can stay simple.

**The required-evidence policy is enforced in the one triage choke point.**
`ICEBERG_REMEDIATION_EVIDENCE_MIN_SEVERITY` (unset = off, the shipped default) makes
`triage.apply` refuse `open → resolved` on findings at or above the bar unless a non-retracted
action with at least one evidence link exists — before anything is written, all-or-nothing like
`IllegalTransition`, surfaced as a 409. A recorded action with a link qualifies; verification is
a stronger signal, deliberately not required, so solo-analyst deployments are not forced into
four-eyes flows. Exempt by design: `false_positive` and `accepted_risk` (judgements that no
secret needed rotating) and reconciliation's auto-resolve (an inference from absence — and a
reappearing credential reopens the finding with its remediation history intact, which ingest
already guarantees).

**Redaction is role-shaped.** Viewers see that an action happened — kind, actor, times,
verification, link *labels* — but not the note or URLs, which responders write about internal
systems. Analysts see everything. One route serves both shapes.

**Retention scrubs, never deletes.** `ICEBERG_RETENTION_REMEDIATION_EVIDENCE_DAYS` (off by
default) reduces links to labels and drops the note once a finding has stayed resolved past the
window, marking `scrubbed_at`. The record of who did what survives; only where-the-proof-lives
ages out. Rows are deleted solely by the cascade when retention purges their finding under its
own rules.

**"Reappearing or live credentials reopen" needs no separate liveness path.** Credential
validation landed alongside this work (ADR 0010), and a validation result only ever reaches the
API *attached to a sighting* — the engine validates what it just detected, so `_record_validation`
is only reached from the ingest path that already reopens a resolved finding. A live credential is
therefore a re-sighted one, and the existing reopen covers both halves of the criterion with the
remediation history intact. A validator that could report on a credential nobody re-detected would
change that, and should reopen through the same branch rather than growing a second one.

## Alternatives considered
- **Guidance in rule packs.** Couples advice to engine rollouts; forces the `extra="forbid"`
  wire schema to grow; puts operator-facing prose in every engine image. Rejected.
- **File uploads for evidence.** The first blob store in the system: a new deployment surface,
  a redaction problem (screenshots of consoles full of other secrets), and its own retention
  regime. Rejected in favour of links; revisit only as an explicit decision.
- **Fully event-sourced actions.** The append-only trail already exists (`FindingEvent`,
  `AuditEvent`); a second temporal model for the same facts buys nothing.

## Consequences
- Closure reporting can distinguish evidenced remediation from administrative closure, and
  reviewers can follow the links while they live.
- The evidence bar is opt-in; enabling it changes analyst workflow for high-severity findings
  (record first, then resolve) and is refused with an actionable 409 until then.
- Guidance quality is a documentation concern with a review process (PRs against the YAML),
  not a code path.
