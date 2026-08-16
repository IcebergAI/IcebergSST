# Releases, versions, and supported upgrades

What a version number promises, how long a release is supported, and which upgrades are
rehearsed. The mechanics of *producing* a release — signing, SBOMs, provenance — are in
[`runbooks/release.md`](./runbooks/release.md); this page is the policy those mechanics serve.

## One version, everywhere

A release is a single number applied to everything the project ships: both role images, the
Helm chart's `appVersion`, and every workspace package. There is deliberately no per-component
versioning, because every component in a deployment comes from the same build and an operator
answering "what am I running?" should not have to answer it five times.

`make version-check` asserts that agreement, and `tests/test_release_invariants.py` runs it in
the ordinary suite — so a half-bumped version fails on the pull request that introduced it rather
than during a release.

The chart's own `version` is separate and moves independently: a change to a template is a chart
release even when the application did not change. It is the one number that is allowed to differ.

## What a version number means

Semantic versioning, applied to the things an operator actually depends on:

| Change | Bump |
|---|---|
| A REST or engine-protocol field is removed or changes meaning | **major** |
| A connector SDK major (`CONNECTOR_SDK_VERSION`) | **major** |
| A configuration variable is removed, or its default changes behaviour | **major** |
| A migration cannot be reversed | **major** (see below) |
| A new endpoint, field, connector, rule pack, or setting | **minor** |
| A fix that changes no documented behaviour | **patch** |

Two things are explicitly *not* breaking changes, because treating them as such would make every
release a major one: adding a field to an API response or a notification payload (documented as
"ignore keys you do not recognise" in [`api.md`](./api.md) and
[`notifications.md`](./notifications.md)), and adding a rule to a rule pack. A new rule finds more
secrets; that is the product working, not a compatibility break.

## Support window

| Line | Supported until |
|---|---|
| Current minor | — |
| Previous minor | 90 days after the next minor is released |
| Anything older | Not supported |

"Supported" means: security fixes are backported, and an upgrade from it to current is rehearsed
in CI (below). It does not mean an uptime commitment — [`SUPPORT.md`](../SUPPORT.md) is the
authority on that, and this is self-hosted software.

Only tagged releases are supported. An arbitrary commit on `main` may be perfectly good, but
nothing rehearses an upgrade from it and no artifact is signed for it.

## Compatibility

**Database.** The API owns the schema and is the only role that migrates (ADR 0002). A migration
runs before the new API starts — the Helm chart does it in a pre-upgrade Job
([`deployment.md`](./deployment.md)) — so during a rolling upgrade the *old* API may briefly run
against the *new* schema. Every migration must therefore be additive with respect to the previous
release: add a column, backfill, and only drop it a release later. A migration that removes or
narrows something the previous release reads is a major-version change, and the release notes say
so.

**Engines.** An engine speaks the versioned engine protocol and carries a connector SDK major.
A fleet may run one version behind the API — that is what makes a rolling engine upgrade possible
— and the API refuses a lease to an engine whose connector SDK major it does not support
([`connector-sdk.md`](./connector-sdk.md)). Two engine minors apart is not tested and not
supported.

**Configuration.** Every variable the deployment interpolates is documented in `.env.example`, and
`tests/test_deploy_invariants.py` fails if one is missing. A removed variable is a major change; a
new one always has a default that preserves current behaviour, or the release is a major.

## Upgrades and rollback

**Supported path:** previous minor → current, or any patch within a minor. Skipping a minor is not
rehearsed; upgrade through it.

"Rehearsed" is literal. `make rehearse` — which CI runs on every pull request against real
Postgres — applies every revision one at a time rather than in one `head` jump, reverses them one
at a time, upgrades the previous release's schema onto the current tree, and takes a backup,
destroys the database, and restores it with a row whose survival is the assertion. It then
compares the restored schema against the models, which is what makes the claim on this page
something a reader can check rather than something the project asserts about itself.

**Rollback is bounded by migrations, not by images.** Rolling an image back is trivial and rolling
a schema back is not, so every migration ships with a `downgrade()` and
`apps/api/tests/test_migrations.py` proves it reverses. That makes rollback *mechanically*
possible; it does not make it lossless. A downgrade that drops a column drops the data in it, and
a release whose downgrade is destructive says so in its notes under **Rollback**. Where the data
matters, restore from a backup taken before the upgrade
([`runbooks/backup-restore.md`](./runbooks/backup-restore.md)) rather than downgrading.

The order that makes rollback survivable:

1. Back up the database. Verify the backup restores, in a scratch database, before continuing.
2. Upgrade the API (which migrates), then the engines.
3. Roll back in the reverse order: engines first, then the API, then — only if the release notes
   say the schema change is not backward-compatible — the migration.

## Release notes

Every release has an entry in [`CHANGELOG.md`](../CHANGELOG.md), and the entry is the release
notes: GitHub's release body is generated from it rather than written twice. Each entry carries,
in this order, whichever of these apply:

- **Breaking** — what changed, and what an operator must do about it.
- **Migrations** — which run, roughly how long they take on a large table, and whether the
  downgrade is lossless.
- **Operator actions** — new configuration, a required engine upgrade, a rule-pack change that
  will move finding counts.
- **Added / Changed / Fixed / Security** — the ordinary sections.

An entry that lists no migrations is a claim, not an omission: `test_release_invariants.py`
checks that a release adding a migration file also documents one.

## Security releases

A confirmed vulnerability is fixed on the current minor and backported to the supported previous
minor. The release is cut immediately rather than waiting for a planned one — a fix sitting on
`main` behind other work is a fix nobody is running.

Notification is by GitHub Security Advisory on this repository, which is also what populates the
ecosystem's vulnerability databases; the CHANGELOG entry carries the advisory identifier. The
private reporting path and the handling expectations are in [`SECURITY.md`](../SECURITY.md).

## Verifying what you are running

Every published artifact is signed, and the signature is verifiable without trusting this project
with a key: images and charts are signed with cosign's keyless flow, and the build provenance is a
GitHub attestation. The exact commands are in [`runbooks/release.md`](./runbooks/release.md) —
including the SBOM, which is the practical way to answer "does this release contain the library in
that advisory?" without rebuilding it.
