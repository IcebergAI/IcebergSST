# ADR 0011 — Credential correlation & exposure clusters

**Status:** Accepted

## Context
The same credential is routinely copied to many places — a wiki page, a runbook, a config
attachment. ADR 0006 deliberately makes each location its own finding ("this key is in page X
*and* page Y"), which is right for triage but leaves responders without the other half of the
picture: *how far has this one secret spread, and is the whole set remediated?* (#140).

The raw material already exists. `secret_hash` (ADR 0004) is a pepper-keyed HMAC of the value,
identical for the same secret across every source in a deployment. But the API has an explicit
rule against exposing it (`findings/schemas.py`): it is a stable comparison oracle, it is the
value pepper re-keying trusts (`previous_secret_hash`), and anyone who ever obtains the pepper
can use it to *test candidate secrets* against a database dump. Exposing it would spend a
guarantee to buy a feature.

## Decision
Introduce a second identifier that names exactly one relation — "these findings hold the same
secret value" — and nothing else:

```
correlation_id = HMAC-SHA256(correlation_key, "iceberg.correlation.v1" ‖ secret_hash)
```

- **Derived API-side, at ingest,** from the hash the engine already reports. The wire protocol
  (`FindingPayload`, the lease) is unchanged.
- **A dedicated key, held only by the API.** `ICEBERG_CORRELATION_KEY_REF` is sealed by the
  secret store under its own AEAD purpose (`correlation`, ADR 0007) and — unlike the pepper —
  is never placed in a lease. An engine, or anyone holding a plaintext secret plus a captured
  pepper, can compute `secret_hash` but **cannot** compute a correlation id or verify a guess.
  Nothing in the API accepts a correlation id as a credential, and no endpoint turns one back
  into secret material: the id is an opaque equality label, unusable as authentication.
- **Stored, indexed, nullable** (`finding.correlation_id`). Clusters are *derived on read* by
  grouping — no cluster table to keep consistent through ingest, re-key, and rotation. A NULL
  (key unset, or a transient secret-store failure at ingest, which fails open) is repaired by a
  bounded backfill in the maintenance round; nothing is lost, because the input is stored.
- **Exposure is role-scoped.** Cluster routes (`/correlation/clusters…`) and the per-finding
  cluster summary are analyst+; viewers keep the findings queue exactly as it was. The export
  is allowlisted (locations and states — no snippet, no notes) and each download is audited.
  `secret_hash` itself remains unexposed to every role, and a structural test pins that no
  engine-facing schema or engine setting ever grows a correlation field.
- **The export is complete or refused, never short.** Its summary numbers are computed from the
  members it lists, so the file cannot describe a membership it does not carry, and a cluster
  past the export bound answers 409 pointing at `GET /findings?correlation_id=…`, which pages.
  The detail screen's cap is a different thing — a rendering budget that says so on the page.
  Somebody works down an export to decide an exposure is closed; a truncated one is a wrong
  answer wearing the shape of a right one.

**Scope.** This deployment is single-org by design (`CLAUDE.md` invariant 5), so "correlate
within one organization only" reduces to: correlation is scoped to *this deployment's
correlation key*. Two deployments hold different keys, so their ids can never be compared.
Likewise "cluster access follows the strictest member permission" holds by construction under
global ranked roles — there is no per-source grant a member could be stricter by; if per-source
permissions ever arrive, cluster visibility must become the intersection of member visibility.

**Key rotation is a recompute, not a rescan.** Because the derivation input is stored, rotating
the correlation key is: generate a new sealed ref (`generate-correlation-key`), swap
`ICEBERG_CORRELATION_KEY_REF`, restart the API, run `python -m iceberg_api reindex-correlation`.
The command is idempotent and restartable; a second run reporting `updated=0` is the completion
signal. There is deliberately **no previous-key window** — unlike fingerprints, nothing must
*match across* the swap; clusters are simply recomputed. The reindex is audited
(`correlation.reindexed`).

Both maintenance paths — the backfill and the rotation walk — write **conditioned on the hash
they derived from**. An id is only correct with respect to one `secret_hash`, and ingest's pepper
re-key rewrites hash and id together in another session; an unconditional write could land after
that commit and leave a *populated* id derived from a hash that no longer exists, which the
backfill (it selects NULLs) and ordinary re-sighting (it leaves populated ids alone) would both
skip forever. Conditioned, the loser of that race simply updates nothing and the re-key stands.

**Interaction with pepper rotation (#64).** `correlation_id` is a function of `secret_hash`,
so the ingest re-key branch recomputes it in the same statement that rewrites the hash. While a
pepper rotation window is open, rows keyed under the old pepper carry different ids than rows
already re-keyed — clusters split and re-merge as the rotation completes, and the existing
`rekeyed` counter reaching zero marks the end. The runbook documents this.

## Alternatives considered
- **Expose `secret_hash` directly.** No new column, but hands every client the oracle and
  couples cluster identity to the pepper's (expensive) rotation story. Rejected.
- **Derive from the pepper (engine-side).** Inherits the pepper's rotation cost — a key swap
  would require re-scanning every source — and puts the correlation capability inside every
  engine. Rejected.
- **A materialized cluster table.** Consistency work at ingest/re-key/reindex for a grouping
  the index answers cheaply. Rejected until scale demands it.

## Consequences
- The "never expose anything derived from the secret" rule is *qualified*, not dropped: never
  the secret, the peppered hash, or anything an engine can recompute. The correlation id is
  API-minted and reveals only equality — the relation the feature exists to reveal — to
  analysts and admins.
- Findings gain one nullable indexed column; every list/detail behaviour is otherwise
  unchanged for viewers.
- Correlation ids are only as complete as ingest since the key was configured plus one
  backfill pass; operators can watch NULLs drain via the maintenance log.
