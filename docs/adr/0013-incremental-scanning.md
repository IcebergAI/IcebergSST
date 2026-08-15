# ADR 0013 — Incremental and resumable scanning

**Status:** Accepted

## Context

Every scan was a full scan, and every interrupted task restarted its spec from the top. On a large
source that is slow and expensive, and it makes throttling corrosive: a rate-limited task fails, the
scan goes `partial`, ADR 0009 §4 suppresses reconciliation, and a chronically throttled source never
auto-resolves anything.

Two capabilities were wanted, and they turn out to be one mechanism and one hazard.

## Decision

### 1. A checkpoint is only sound if its findings are already stored

A resume position that commits ahead of the findings it covers tells the next attempt to start
beyond content nobody stored — losing secrets with no sign it happened. So checkpoints require
**partial result submission**: `POST /scan-tasks/{id}/progress` ingests a batch of findings and
advances `scan_task.checkpoint` in one transaction. They are not two features that happen to pair
well; a checkpoint without durable batches is unsound.

Idempotency is one conditional UPDATE, in the idiom of `claim_task`/`claim_result`: a batch is
accepted only when its `sequence` is exactly one ahead of the stored counter. A duplicate batch, an
out-of-order batch, and a batch from an engine whose lease was reclaimed all fail identically. The
counter is per **task**, not per attempt, so a reclaimed attempt continues the sequence rather than
colliding with its predecessor's numbers.

### 2. The engine cuts a batch where position and work describe the same prefix

`fetch` is a generator, so its two ledgers move at different moments: coverage for a unit is recorded
before the unit is yielded, while the `checkpoint_at` covering it does not run until the consumer
asks for the next one. Pairing whatever is visible at a single instant ships a batch covering one
unit more than its position admits, and every reclaimed attempt re-reports that unit and inflates the
merged coverage.

The runner therefore records a boundary at the **end** of each unit and cuts the batch at the **top**
of the next iteration, once the checkpoint has caught up to exactly that boundary.

### 3. The task's outcome is judged from what the API accumulated

`_effective_outcome` reads the **merged** coverage, not the final submission. A unit that failed in
batch one is absent from the terminal body; trusting that body would mark the task completed and let
reconciliation auto-resolve against content nobody read.

### 4. An incremental scan never auto-resolves

This is the load-bearing constraint. `reconcile_scan` resolves every open finding a scan did not see.
An incremental scan deliberately never looked at unchanged content, so a finding it did not see is
not evidence of anything — reconciling on it would mass-resolve the whole source on the first run.
The gate in `finalize_and_reconcile` grows `and scan.mode is ScanMode.FULL`.

**Notifications stay outside that check.** Finding new secrets sooner is the entire point of an
incremental scan; silencing its announcements would gut the feature.

### 5. Periodic full reconciliation is a promotion rule, not a convention

A schedule's mode is a *request*. `launch_scan` promotes it to full whenever the watermark cannot be
trusted: no cursor, a rule-pack change, a fleet that disagrees about its rule pack, a source edit, a
pepper rotation, or `Source.full_scan_interval_days` having elapsed. Unknown always counts as
changed — an unverifiable fleet version is not the same as an equal one.

That rule is what makes §4 livable: a schedule left on incremental forever still produces full scans,
so remediated findings still close. Every promotion records its reason on the scan and in the
manifest.

### 6. Cursors are per scope, and advance only on complete evidence

A watermark is stored per `(source, scope)` — a space, a project — because scopes complete
independently: one whose tasks failed simply does not advance and is re-read in full next time. That
is fail-closed with no extra machinery.

Proposals are held on the task and committed inside the same gate that authorises reconciliation. A
scan that cannot be trusted to have read everything cannot be trusted to say where the next one
should start.

Invalidation sets a column rather than deleting the row, so "why did this become a full scan?" stays
answerable after the cursor that caused it is gone.

### 7. Positions are opaque to the control plane, and bearer-ish

Connectors run only in engines (ADR 0002), so the API stores a position, compares the metadata
*around* it for staleness, and hands it back verbatim. A position may hold a provider change token,
which is bearer-ish for a place in a result set: it is never logged, never exported, and never
returned by the cursor API — which reports whether a scope has a watermark and how old it is.

### 8. SDK 1.1, not 2.0

Neither `discover` nor `fetch` changes signature; a signature change is a major release and an engine
image must not mix connector majors. Both behaviours ride on `FetchOutcome`, and cursors reach
`discover` through an optional keyword the engine passes only when the connector declares
`INCREMENTAL` — gated on the declared capability, never on `isinstance`, which for a runtime-checkable
Protocol checks that a method exists rather than what it accepts.

## Consequences

- The engine gains a second write channel. It is not a second source of truth: a batch is never
  terminal, and `finalize_and_reconcile` is unreachable from it.
- Coverage manifests move to `manifest_version: "2"`. A `complete` **incremental** manifest means
  "everything that changed since the baseline", so an exporter reading v1 must not read v2 as full
  coverage.
- Resume quality differs by connector and the docs say so. Jira resumes exactly, on an immutable
  ordering. Confluence re-enumerates a space to find its position, because a v2 cursor is opaque and
  may not outlive a reclaim.
- Deletion detection remains full-scan-only. That is the issue's own non-goal: change tokens are not
  trusted without reconciliation.
- Nothing purges `scan`/`scan_task` today, so checkpoints accumulate with scan history
  (`docs/retention.md`).
