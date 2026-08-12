# Security policy

IcebergSST handles source credentials and maps where secrets are stored. Report suspected
vulnerabilities privately through GitHub's **Report a vulnerability** action for this repository.
Do not open a public issue containing credentials, source content, exploit details, or a plaintext
secret.

## Scope

Reports are especially valuable for:

- plaintext crossing the engine/API boundary or being written to logs, events, fixtures, or the
  database;
- authentication, authorization, CSRF, session, engine-token, or secret-store bypasses;
- connector redirects, SSRF, unsafe egress, or credential disclosure;
- missing tenant/source isolation, unsafe migrations, or data loss during recovery;
- container/Helm controls that grant an engine database or master-key capability.

## What to include

Provide the affected version or commit, deployment mode, a minimal reproduction without live
credentials, impact, and any proposed mitigation. Use synthetic canaries and redact all source
identifiers that are not needed to reproduce the issue.

## Handling expectations

The maintainers will acknowledge a private report when they can, reproduce it in an isolated
environment, and coordinate a fix or mitigation before public disclosure. Timelines depend on
severity, reproducibility, and whether a supported release is affected. Security fixes must include
regression coverage and an update to the relevant ADR or runbook when the boundary changes.

The supported security model is documented in [`docs/security.md`](docs/security.md), and the
implemented controls are mapped in [`docs/security-review.md`](docs/security-review.md).
