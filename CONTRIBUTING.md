# Contributing to IcebergSST

IcebergSST is a security-sensitive, API-first scanner for non-git enterprise sources. Changes
must preserve the engine boundary and the no-plaintext-at-rest invariant.

## Local setup

Use Python 3.14, [uv](https://docs.astral.sh/uv/), and Docker. From a fresh checkout:

```console
make sync
make init-env
make check
make docs-check
```

`make check` is the same lint, type, and test gate used by CI. `make images-verify` and
`make helm-verify` are required when changing deployment or container files.

## Design boundaries

- The API is the only database writer. Engines receive task-scoped material and post redacted
  results back to the API; they never import the database package.
- Plaintext secrets may exist only ephemerally inside the engine while a unit is being scanned.
  Findings contain a masked snippet and a peppered hash, never the matched value.
- New connectors implement the protocol and sandbox limits, document their source permissions,
  and add conformance tests for partial reads, redirects, rate limits, and redaction.
- Browser routes call the API contract and remain CSRF-protected; do not add inline scripts or
  styles to templates.
- Schema changes require an Alembic revision, SQLite migration coverage, and PostgreSQL upgrade,
  downgrade, and re-apply coverage.

## Pull requests

Describe the user outcome, threat-model impact, migration/rollback behavior, and tests. Keep
changes focused. Do not include credentials, live source content, or unmasked canaries in commits,
fixtures, screenshots, logs, or issue comments. Reviewers may request a clean-room walkthrough for
deployment or recovery claims; document what was actually exercised rather than implying that a
runbook alone is evidence.

The repository's CI and CODEOWNERS rules are authoritative. A green check is necessary but does
not replace review of security boundaries or operator-facing behavior.
