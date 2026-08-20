# Changelog

Every release has an entry here, and the entry **is** the release notes — GitHub's release body is
generated from it rather than written twice. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the version policy, support window, and
what counts as a breaking change are in [`docs/releases.md`](./docs/releases.md).

Sections appear in this order when they apply, because that is the order an operator needs them:
**Breaking**, **Migrations**, **Operator actions**, then Added / Changed / Fixed / Security.

## [Unreleased]

### Migrations

`0016` reconciles three columns the models and the migrations disagreed about — two VARCHAR
lengths and three unique constraints that had been created as unique indexes. No behaviour
changes; the fix keeps `--autogenerate` from folding them into an unrelated migration later.
Reversible, and the downgrade restores the previous shape exactly.

`0017` adds the external hand-over tables (`handoff_target`, `finding_handoff`), unique on
`(target_id, finding_id)` and on a never-regenerated idempotency key so repeated delivery creates
one external work item (#141). `0018` adds the inbound state-sync columns — what the receiver
says is recorded beside the finding, never written onto it. Both are reversible.

### Added

- File-share sources are configurable from the console (#196). The create/edit form gained the
  share's own fields — protocol, mount path, roots, include/exclude globs, symlink policy and the
  per-file ceiling — and `fileshare` joins the type select, so the connector the API has supported
  since #145 is no longer API-only to set up. It is deliberately not the Confluence form with
  different labels: there is no base URL, no deployment choice, and **no credential box**, because
  a share is authenticated by the mount an operator configures on the engine. The details card
  describes the share rather than a site, and the connectivity-test button is not offered — a probe
  from the API would reach the wrong machine, which is worse than no answer.

- External hand-over (#141, #179–#186): admin-configured targets receive a signed POST with a
  finding's context, delivered through the same outbox pattern as notifications; the receiver can
  report its own state back through a signed callback, and an analyst resolves any divergence from
  the console. See [`docs/handoff.md`](./docs/handoff.md).
- Release policy, a signed release pipeline, and a version-consistency invariant (#147). Every
  published artifact — both role images, the Helm chart, and the source archive — is signed with
  cosign's keyless flow and carries an SBOM and GitHub build provenance, so an operator can verify
  what they are running without this project holding a signing key.
- An upgrade, rollback and recovery rehearsal (`make rehearse`) that CI runs on every pull
  request against real Postgres: every revision applied and reversed one at a time, the previous
  release's schema upgraded onto the current tree, and a backup destroyed and restored.

### Changed

- The threat model knows about external hand-over (#194). `docs/security.md` § Outbound requests
  listed two features that send traffic out of the deployment; hand-over targets were a third, and
  the signed `POST /handoff/callback` — sessionless, CSRF-exempt, authenticated only by the
  target's own secret — was a trust boundary the numbered list did not contain. Both are written
  up now, including what a verified receiver may and may not drive, and "external ticket creation"
  is off the out-of-scope list it was still sitting on.
- [ADR 0014](./docs/adr/0014-external-handover.md) records the hand-over decisions that until now
  lived only as prose in `docs/handoff.md` and migration docstrings: one target type, the
  notification wire format reused deliberately, dedup by both a unique constraint and a
  never-regenerated idempotency key, admin-decides-where/analyst-decides-which, and the reply
  recorded beside the finding rather than written onto it.

- `make docs-check` now also verifies that every documented `make` target and every `ICEBERG_*`
  setting the docs name still exists, and reads only the files git tracks — so it no longer fails
  on a contributor's unrelated local directory (#150).

### Fixed

- Four follow-ups from the codebase review (#197), all on the API:

  - **A duplicate name raced to a 500.** Sources, notification channels, hand-over targets, owner
    groups and routing rules all check "is this name free?" with a SELECT and then INSERT, which
    only ever guarded the sequential case — two concurrent creates both find nothing, both insert,
    and the loser got an unhandled `IntegrityError`. `commit_or_conflict` turns that into the 409
    the route already had a message for, at ten call sites. Only a unique violation is converted;
    a foreign key or a check constraint is still a bug and still raises.
  - **A lock-order inversion between `submit_progress` and `submit_results`.** Both take the scan
    row `FOR UPDATE` and write the task row; progress took them scan-then-task and results
    task-then-scan, which is the AB/BA deadlock if a retried progress races the same task's final
    results. Results now takes the scan first. Postgres would have aborted one side and the retry
    ladder recovered, so nothing was lost — it was just free to make impossible.
  - **Cancelling a scan threw away coverage the tasks had reported.** A running task's accumulated
    per-batch report was replaced with a synthetic zero-count failure, so a cancelled scan's
    manifest said a task that had demonstrably ingested findings scanned nothing. The cancellation
    gap is merged onto the stored report instead.
  - **Ingest was an N+1 on the API's busiest transaction.** One or two point selects per finding
    payload, inside the transaction holding the scan row locked. The batch's findings — under both
    identities during a pepper rotation — are now loaded in one pass.

- A draining engine never finished shutting down (#192). `Worker.stop()` waits ten minutes by
  default and both grace periods this project ships are two, so an engine with a long fetch in
  flight was still waiting when SIGKILL arrived: the heartbeat, the API connection pool and the
  metrics server were never stopped, and `engine_stopped` never appeared in the log. The wait is
  now bounded by `ICEBERG_DRAIN_SECONDS` (default 90), which a deploy invariant holds below both
  graces, and a task still running when the budget expires is named in an
  `engine_drain_incomplete` warning before the engine goes. The drain policy — wait, then let the
  lease hand the work to another engine rather than reporting a terminal failure — is written down
  in [`docs/deployment.md`](./docs/deployment.md) § Draining an engine, along with why the
  alternative was rejected.

- A scan could report clean coverage for a task that died halfway through a resumable source
  (#193). When a connector checkpoints, the engine's last submission carries only the *remainder*
  the progress batches did not — but the task-wide gap that says "this task never finished reading
  its scope" was written onto the whole-task tally, which that submission no longer sent. So a
  timed-out or rate-limited fetch against Confluence, Jira or a file share left no blind spot on
  the manifest, and a scope the scan had only partly read counted as fully enumerated. The same
  failure against a connector without checkpoints reported the gap correctly, which is the
  inconsistency that gave it away. The remainder is now derived at submission, after the gap is
  recorded, so both kinds of connector tell the same story. No operator action; manifests already
  written are not recomputed, so re-run any scan whose partial fetch you need accounted for.

- Overdue escalation could stall behind findings that had nobody to escalate to (#190). A team
  configured with no channel is silent by choice, and an unowned finding no channel's filter selects
  has nowhere to go either — but neither writes an outbox row, so the "already escalated?" exclusion
  kept selecting them. The beat takes the oldest deadlines first and is bounded at 200, so once that
  many silent findings accumulated they held the front of every page and nothing behind them was
  ever escalated. Findings with no target are now excluded by the selecting query rather than
  skipped after it, so silence costs only the silent. No operator action: the next beat picks up
  whatever had been starved.

- A reclaimed file-share task could skip files and report the scope clean (#189). The walk handed
  a directory's own files over before descending into subdirectories that sort before them, while
  the resume comparison read the stored position as a plain string — two orders that disagree, so
  an attempt resuming from a checkpoint silently passed over whatever fell between them, and the
  coverage manifest counted the root as fully scanned. Files and subdirectories now take one
  order, and a position is compared segment by segment (`/` sorts after `.`, so `"a/b" > "a.txt"`
  as strings while the walk yields `a/b` first). The file-share checkpoint version moves to `2`;
  a `1` position names a place in the old order, so it is discarded and the root re-read. The
  conformance kit's `assert_checkpoint_resume` — which this connector declared `CHECKPOINTS`
  without ever running — now covers it, as it already did for Confluence and Jira.

### Security

- A redacted snippet could carry a fragment of the secret it was masking (#188). An unmatched copy
  of a matched secret that ran into the *side of a mask* — a neighbouring match's, or the match's
  own where a periodic secret overlaps itself — was cut in two: the context scrub only ever
  replaces whole copies, so the part sticking out was stored verbatim, shown in the console, and
  sent to notification and hand-over targets. Ten contiguous characters of a matched token in the
  reproducing case. Any such copy is now masked in full, and the bisection check that previously
  guarded only the two window edges guards every edge that emits context.

  **Operator action:** snippets already in the database were written by the old engine and are not
  rewritten in place. Ingest refreshes a finding's snippet every time the secret is seen again, so
  a full scan on engines carrying this fix replaces the stored snippet of every finding that still
  exists; a finding whose secret has since been removed keeps the snippet it was stored with, and
  is only cleared by retention or by deleting it.

## [0.1.0] — unreleased

The first tagged release. Everything below is the state of the project at the point a version
number started meaning something; earlier changes are in the git history, where they were never
claimed to be supported.

### Migrations

`0001` through `0015`. On a fresh database they apply in seconds. `0014` seeds the four response
targets, and `0015` backfills `notification_delivery.kind`; both are reversible, and no downgrade
in this range drops data an operator has entered.

### Operator actions

- Set `ICEBERG_MASTER_KEY` and `ICEBERG_FINGERPRINT_PEPPER_REF` before first start. Losing the
  master key makes every stored credential ref undecryptable — see
  [`runbooks/key-rotation.md`](./docs/runbooks/key-rotation.md).
- Mount SMB/NFS shares read-only into the **engine** only, if using the file-share connector
  (#145).

### Added

- Confluence, Jira, and SMB/NFS file-share connectors, on a versioned connector SDK with a
  conformance kit.
- Two-phase scans with API-authoritative leases, durable checkpoints, and incremental scanning
  with per-scope cursors (ADR 0009, ADR 0013).
- Detection with versioned rule packs, analyst-editable suppressions, and confidence thresholds.
- Findings with fingerprint-stable identity, triage, exposure clusters, remediation evidence, and
  ownership with routing rules and response targets (ADR 0006, 0011, 0012; #146).
- Opt-in credential liveness validation that never persists plaintext (ADR 0010).
- Notification channels with a transactional outbox, and escalation for findings that miss their
  response target.
- OIDC authentication with RBAC, a server-rendered console under a strict CSP, and an
  administrative audit trail.
- Coverage manifests: what a scan actually read, and where it could not.
- docker-compose for development and a Helm chart for production.

[Unreleased]: https://github.com/IcebergAI/IcebergSST/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/IcebergAI/IcebergSST/releases/tag/v0.1.0
