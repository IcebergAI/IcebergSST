# Runbook: controlled Confluence Cloud pilot

## Decision

IcebergSST is suitable for a **small, operator-controlled, self-hosted pilot**, not a production
rollout. The pilot tests a narrow promise: scan current Confluence Cloud content without persisting
secret plaintext, preserve analyst triage across rescans, and fail partial when requested content
cannot be read. It is not evidence that generic Confluence scanning is unique or that the current
deployment is production-ready.

## Pilot boundary

- Run for 1–2 weeks against one dedicated non-production Cloud space.
- Use a dedicated read-only Confluence identity with access only to that space.
- Configure the Cloud `base_url` as the site root, without `/wiki`, and use the default
  `/wiki/api/v2` prefix.
- Use a private IcebergSST deployment, an authorized HTTPS OIDC callback, named operators, and one
  operator-controlled webhook receiver. Keep the first-login `viewer` default; grant admin or
  analyst roles deliberately.
- Seed only revoked or synthetic secret-shaped canaries. Never introduce a live credential to test
  detection.

In scope is current page storage content, footer and inline comments (including nested replies),
and supported text-extractable attachments. Findings from readable content are retained during a
partial scan; reconciliation and notification enqueueing require a complete scan.

Explicitly out of scope:

- page history, historical versions, and incremental/change-feed scanning;
- blogs;
- OCR, images, and archive traversal;
- Jira and SMB/NFS sources;
- Confluence Server/Data Center validation;
- checking whether a discovered credential is valid or revoked;
- automatic revocation, deletion, or remediation.

## Before starting

1. Run `make check` and the controlled acceptance test:
   `uv run pytest apps/api/tests/test_controlled_pilot.py -v`.
2. Record the source space, Confluence identity, IcebergSST operators, OIDC application, webhook
   owner, start date, and end date.
3. Verify the Confluence identity cannot write and cannot read any space outside the pilot.
4. Verify the webhook rejects an invalid HMAC and stores no sensitive triage notes or assignee data.
5. Back up the pilot database and the exact master-key/fingerprint-pepper material separately, then
   prove restoration in an isolated pilot instance before relying on retained triage.

## Operate and measure

Run an initial scan, triage its canaries, then run unchanged and edited rescans. Review every
partial/failed task before treating an absent finding as fixed. Track:

- completed, partial, and failed scans, including `units_failed`, `units_truncated`, and skips;
- scan duration, queue depth, lease reclaims, engine API retries/heartbeat failures, and connector
  failures from the `iceberg_*` Prometheus series;
- expected canaries found, analyst-confirmed false positives, and findings retained across rescans;
- notification rows and webhook delivery attempts/errors;
- Confluence 401/403/404/429 responses and unexpected scope access;
- API, engine, database, and webhook evidence for any plaintext canary or source-token leakage.

Stop the pilot immediately for plaintext persistence/logging, access outside the dedicated space,
incorrect reconciliation after a partial scan, unsigned/unexpected notification content, or a live
credential finding. Rotate any possibly exposed credential before investigation.

Pilot success means all expected current-content canaries are found, unchanged rescans preserve
fingerprints and triage without duplicate notifications, incomplete reads always produce a partial
scan with no reconciliation/notification, and no plaintext appears in human responses, engine
result submissions, persistence, logs, or webhooks. Here “plaintext” means a source credential,
notification secret, or detected canary; authorized analyst notes intentionally persist. The
task-scoped source credential is expected only in an authenticated engine lease (ADR 0009).

## Production GO blockers

An external or production rollout remains **NO-GO** until the operator supplies and proves all of
the following:

- **End-to-end transport security.** The chart supports TLS at Ingress, but currently renders the
  engine-to-API URL as plain `http://` (`templates/configmap.yaml`). Prove authenticated encryption
  for that internal lease channel. Provision and verify TLS for external Postgres and Redis too;
  the chart passes their URLs through and does not operate their TLS.
- **Default-deny egress.** The optional chart policies are ingress-only and disabled by default
  (`templates/networkpolicy.yaml`, `values.yaml`). Add tested egress allowlists for each role,
  including DNS and only the required API, database, Redis, OIDC, webhook, and Confluence targets.
- **Release provenance.** CI builds/tests images and renders Helm, but there is no image publish by
  immutable digest, signing/verification, release workflow, or SBOM production. Add and exercise
  that chain before consuming an image as a release artifact.
- **External secret delivery.** The chart can reference pre-created Kubernetes Secrets, but it does
  not prove a Vault/ExternalSecret flow. Deploy and test the chosen controller/injector, rotation,
  least-privilege access, and recovery without putting secret values in Helm release data.
- **Identity and authorization.** Register the exact HTTPS OIDC callback, verify issuer/client and
  PKCE behavior, retain viewer-by-default onboarding, and test admin/analyst/viewer assignments and
  break-glass recovery in the real provider.
- **Recovery.** Document, execute, and time a restore of Postgres plus the matching master key and
  fingerprint pepper. Losing the key loses stored credentials; changing the pepper changes finding
  identity. Test Redis loss/rebuild and the notification outbox recovery path as well.

The deployment evidence behind these blockers is in `docs/deployment.md`, `docs/security.md`,
`.github/workflows/ci.yml`, and `deploy/helm/icebergsst/`.
