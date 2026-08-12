# Data retention

Findings, their append-only event trail, and the administrative audit log all grow forever. This
is how a deployment bounds that — and, more importantly, what it will never delete.

**Every window is off by default.** This database is evidence: it records where an organisation's
secrets were found, and who did what about each one. Deleting some of it has to be a decision
somebody made, not something that starts happening because they upgraded. With nothing configured,
the purge runs and deletes nothing.

## What can be deleted

| Setting | Default | What ages out |
|---|---|---|
| `ICEBERG_RETENTION_RESOLVED_FINDINGS_DAYS` | `0` (keep forever) | Findings **auto-resolved** longer ago than this. |
| `ICEBERG_RETENTION_FINDING_EVENTS_DAYS` | `0` (keep forever) | `FindingEvent` rows older than this, on findings that are not open. |
| `ICEBERG_RETENTION_AUDIT_EVENTS_DAYS` | `0` (keep forever) | `AuditEvent` rows older than this. |
| `ICEBERG_RETENTION_REMEDIATION_EVIDENCE_DAYS` | `0` (keep forever) | **Scrubbed, not deleted** (ADR 0011): evidence-link URLs and notes on remediation actions whose finding has stayed resolved this long are reduced to labels. The action rows — who did what, verified or not — survive. |
| `ICEBERG_RETENTION_BATCH_SIZE` | `1000` | Rows per table (or scrub round) per beat. |

The finding clock runs from the **decision**, not the first sighting: `updated_at` moves when the
finding is resolved, so a secret found two years ago and auto-resolved yesterday is one day old
for retention purposes.

## What is never deleted

These are not configurable, because each one exists to prevent a specific bad outcome:

- **Open findings.** An unresolved secret is not old news — it is a secret nobody has dealt with.
- **Findings an analyst decided about**: `false_positive`, `accepted_risk`, or a *manual*
  resolution. Those are judgements. Letting one expire silently means the same finding returns on
  the next scan as new, with nobody remembering it was already considered. Only `auto`
  resolutions — an inference from absence, made by a scan — are eligible.
- **Suppressed findings.** The suppression is the reason the finding is not in anyone's list;
  deleting the row would resurrect it as new on the next scan (ADR 0008).
- **An open finding's event trail**, however old. It is what an analyst reads to understand the
  state in front of them, and an old open finding is exactly the one needing explanation.

Deleting a finding does take its own `FindingEvent` rows with it — the trail describes that
finding, and orphaning it would leave rows nothing can interpret.

## How it runs

In the API's maintenance loop, under the same Postgres advisory lock as the scheduler, so one
replica purges however many are running. It is last in the round: it is the only job that can be
slow on a database that has never been purged, and nothing else waits on it.

Deletion is batched. A round that hits `ICEBERG_RETENTION_BATCH_SIZE` simply continues on the next
beat, so the first purge after configuring a window cannot hold locks for minutes.

To run one now — useful immediately after configuring a window, when you want to see the number
rather than discover it in the audit log:

```bash
python -m iceberg_api retention-purge   # in the api container
```

It prints the counts per table and, like the scheduled round, audits itself if it removed
anything.

## Purges are audited

Deleting evidence is an administrative action, so a round that removed anything writes an
`audit_event` with `action = retention.purged`, recording the counts **and the windows that
justified them** — the row still explains itself a year later when the settings have changed.

A round that deleted nothing writes nothing: an audit log full of "deleted 0 rows" every minute is
one nobody reads.

That audit row is itself subject to `ICEBERG_RETENTION_AUDIT_EVENTS_DAYS`, like every other. That
is deliberate rather than an oversight — a purge record exempt from retention would be a special
case hiding from the policy it enforces. If you need purge records to outlive the audit window,
ship them off-box: they are in the structured logs as `retention_purged`.

## Choosing windows

There is no default that is right for everyone, which is why there is no default. Some anchors:

- **Do you need to prove a secret was remediated?** Then auto-resolved findings are the evidence
  that it was, and the window should be at least as long as the period you might be asked about.
- **Regulatory audit-log windows** (SOX, PCI DSS, ISO 27001 and friends) typically land between
  one and seven years. `ICEBERG_RETENTION_AUDIT_EVENTS_DAYS` should match whichever applies to
  you; if you are unsure, leave it at `0` and ask, because you cannot get the rows back.
- **Storage pressure is rarely the real constraint.** A finding row is small. If the database is
  growing uncomfortably it is usually `finding_event` on a noisy source, which
  `ICEBERG_RETENTION_FINDING_EVENTS_DAYS` addresses without touching any finding.
- **Data-minimisation obligations** (GDPR Art. 5(1)(e) and similar) point the other way: keep
  personal data no longer than necessary. Findings do not intentionally contain personal data —
  the snippet is redacted (ADR 0004) — but a resource locator is a path in someone's wiki and can
  name a person. If that matters for you, the findings window is the control.

Whatever you choose, write it down somewhere other than the environment variable. The audit rows
record the window in force at the time of each purge, but only for purges that have already
happened.
