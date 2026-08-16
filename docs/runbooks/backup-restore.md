# Runbook: backup and restore

IcebergSST's database contains finding locations, triage, audit history, task state, and sealed
credential references. A database backup without the matching master key and fingerprint pepper is
not a recoverable backup. Never put either value in a command argument, log, ticket, or repository.

> **This procedure is rehearsed, not merely written.** `make rehearse` — which CI runs on every
> pull request against a real Postgres — takes a backup, destroys the database, restores it, and
> asserts both that a row written before the dump came back and that the restored schema still
> matches the models. A backup nobody has restored is a plan; see
> [`release.md`](./release.md) for where it sits in an upgrade.

## Before the drill

- Record the exact application/chart/image versions and database migration revision.
- Pause new scans and notification dispatch; wait for in-flight tasks to reach a terminal state.
- Take an operator-approved PostgreSQL backup using the managed database's native encrypted backup
  mechanism. Store it separately from the deployment and test its checksum.
- Verify that the external secret system can restore the API master key, session secret, OIDC
  secret, and fingerprint-pepper reference without exposing their values.
- Record the Redis backup policy. Redis is a queue/cache, not the system of record; rebuilding it
  is expected to lose only re-creatable task hints and transient rate-limit state.

## Restore in isolation

1. Create an isolated PostgreSQL and Redis instance with network access limited to the recovery API.
2. Restore the database backup and inject the **same** API secret references through the approved
   secret mechanism. Do not generate a new master key or pepper for this test.
3. Deploy the matching chart/image version with external ingress disabled and a temporary OIDC
   callback. Run the migration command in its normal API-only role and confirm the revision.
4. Rebuild Redis, start one engine with a newly minted recovery token, and run a synthetic scan.
5. Verify that pre-existing finding fingerprints, triage decisions, audit events, sealed source
   references, and notification outbox rows are readable. Verify that no plaintext appears in
   responses or logs.
6. Exercise one engine lease timeout and one notification retry. Confirm the API reconciles them
   without duplicate findings or lost audit history.
7. Record elapsed time, operator interventions, data differences, and every undocumented step.
   Destroy the isolated resources only after the evidence is exported to the approved evidence
   store.

## Recovery and rotation notes

Changing the master key makes existing sealed credential references unreadable; use the documented
key-rotation procedure and verify every reference before retiring the old key. Changing the
fingerprint pepper changes finding identity; follow the pepper-rotation procedure and verify that
triage state is preserved. Redis loss should be handled as queue recovery, not as a database
restore. If a backup cannot be restored with the matching secrets, treat the deployment as
unrecoverable and stop the rollout.
