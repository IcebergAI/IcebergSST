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

### Added

- Release policy, a signed release pipeline, and a version-consistency invariant (#147). Every
  published artifact — both role images, the Helm chart, and the source archive — is signed with
  cosign's keyless flow and carries an SBOM and GitHub build provenance, so an operator can verify
  what they are running without this project holding a signing key.
- An upgrade, rollback and recovery rehearsal (`make rehearse`) that CI runs on every pull
  request against real Postgres: every revision applied and reversed one at a time, the previous
  release's schema upgraded onto the current tree, and a backup destroyed and restored.

### Changed

- `make docs-check` now also verifies that every documented `make` target and every `ICEBERG_*`
  setting the docs name still exists, and reads only the files git tracks — so it no longer fails
  on a contributor's unrelated local directory (#150).

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
