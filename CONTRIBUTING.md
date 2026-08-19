# Contributing to IcebergSST

IcebergSST is a security-sensitive, API-first scanner for non-git enterprise sources. Changes
must preserve the engine boundary and the no-plaintext-at-rest invariant.

## Local setup

Use Python 3.14, [uv](https://docs.astral.sh/uv/), and Docker. From a fresh checkout:

```console
make sync
make init-env
make check
```

`make check` is `make lint`, `make type`, `make docs-check` and `make test` — the same gate CI
runs, in the same order. The rest of CI is reachable the same way, so nothing in the pipeline is a
command you can only run by pushing:

| Command | What it proves | When you need it |
|---|---|---|
| `make check` | lint, types, doc integrity, and the whole test suite | always |
| `make docs-check` | links, `make` targets, and settings the docs name still exist | in `check`; also standalone |
| `make version-check` | every shipped component declares the same version | before tagging |
| `make images-verify` | both images build, serve, and hold the ADR 0002 boundary | container or dependency changes |
| `make helm-verify` | the rendered chart carries no engine database credentials | chart changes |
| `make rehearse` | migrations apply and reverse one at a time, and a backup restores | schema changes |

`make rehearse` needs a scratch Postgres and the libpq client tools; CI runs the identical script
against its own service container, so what you can rehearse locally is what every pull request
already rehearses. `make sync` also installs the pre-commit hooks, one of which is the gitleaks
scan — CI runs it over the full history either way, but by then the secret is committed.

## Design boundaries

- The API is the only database writer. Engines receive task-scoped material and post redacted
  results back to the API; they never import the database package.
- Plaintext secrets may exist only ephemerally inside the engine while a unit is being scanned.
  Findings contain a masked snippet and a peppered hash, never the matched value.
- New connectors implement [Connector SDK v1](docs/connector-sdk.md), declare only implemented
  capabilities, run the shared conformance kit, document source permissions, and add source-specific
  tests for partial reads, redirects, rate limits, malformed responses, and redaction.
- Browser routes call the API contract and remain CSRF-protected; do not add inline scripts or
  styles to templates.
- Schema changes require an Alembic revision, SQLite migration coverage, and PostgreSQL upgrade,
  downgrade, and re-apply coverage — `make rehearse` is that coverage, and it also compares the
  restored schema against the models, which is how three drifts SQLite cannot express were found.
- Every migration must be additive with respect to the **previous release**: a rolling upgrade
  briefly runs the old API against the new schema ([`docs/releases.md`](docs/releases.md)).

## Pull requests

Describe the user outcome, threat-model impact, migration/rollback behavior, and tests. A change
that alters operator-visible behaviour needs a `CHANGELOG.md` entry under **Unreleased**; a change
that adds a migration needs a **Migrations** line in it, which
[`tests/test_release_invariants.py`](tests/test_release_invariants.py) enforces at release time. Keep
changes focused. Do not include credentials, live source content, or unmasked canaries in commits,
fixtures, screenshots, logs, or issue comments. Reviewers may request a clean-room walkthrough for
deployment or recovery claims; document what was actually exercised rather than implying that a
runbook alone is evidence.

The repository's CI and CODEOWNERS rules are authoritative. A green check is necessary but does
not replace review of security boundaries or operator-facing behavior.
