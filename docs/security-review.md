# Security review

The review #64 asked for: every mitigation in [`security.md`](./security.md) mapped to the test or
documented control that makes it true, plus an audit-coverage review and the honest list of what is
*not* covered.

Reviewed against the implemented system on **2026-07-31**, at M4 (M0–M3 complete, notifications and
Helm landed).

The point of the table is falsifiability. "We validate input" is not a control; a named test that
fails when the validation is removed is. Where a mitigation has no test, it says so and says what
stands in its place.

---

## Trust boundaries

### 1. Browser ↔ API

| Mitigation | Evidence |
|---|---|
| OIDC authorization code + PKCE; `state` in a signed cookie, `nonce` checked inside the ID token | `apps/api/tests/test_oidc.py`, `test_auth_routes.py` |
| ID token verified against JWKS — signature, issuer, audience, expiry — never merely decoded | `test_oidc.py` |
| Sessions signed, `HttpOnly`, `SameSite=Lax`, `Secure` unless explicitly disabled | `test_session_cookies.py` |
| Session carries no role, so demotion takes effect on the next request | `test_rbac.py`, `test_users_api.py` |
| RBAC enforced server-side on every route | `test_rbac.py` |
| CSRF on every mutating browser route — asserted across the whole router, not route by route | `test_web_invariants.py` |
| First login lands as `viewer`; roles come from the database, not from a token claim | `test_auth_routes.py` |
| Nobody may change their own role or disable their own account | `test_users_api.py` |
| Rate limits on `/auth/login` and `/auth/callback` | `test_rate_limiting.py` |

### 2. Engine ↔ API

| Mitigation | Evidence |
|---|---|
| Per-engine bearer token; only its SHA-256 hash is stored | `test_engine_protocol.py` |
| An engine token cannot read findings; a browser session cannot lease or post results | `test_rbac.py`, `test_engine_protocol.py` |
| Credential and pepper transit **only** in the lease response, per task | `test_engine_protocol.py`, `apps/engine/tests/test_runner.py` |
| Lease is a conditional UPDATE — two engines cannot both hold one task | `test_scan_orchestration.py` |
| Results ingest is idempotent on `<task id>:<attempt>` | `test_results_ingest.py` |
| Rejected token presentations are rate-limited per address; accepted traffic per engine | `test_rate_limiting.py` |
| A missing pepper fails the task rather than leasing without one | `test_engine_protocol.py` |

### 3. Engine ↔ Redis

| Mitigation | Evidence |
|---|---|
| Broker messages are task-id hints only — no secrets, no specs | `apps/api/tests/test_scans_api.py`, `apps/engine/tests/test_worker.py` |
| Everything is re-validated at lease time against the database | `test_scan_orchestration.py` |
| Redis requires a password even in development | `deploy/compose/docker-compose.yml`; `tests/test_deploy_invariants.py` |
| Redis password is not interpolated into the container's `Cmd` (it would show in `docker inspect`) | compose file comment; `tests/test_deploy_invariants.py` |

### 4. Engine ↔ scanned content

Attacker-editable input attacking the extraction parsers — the boundary with the least margin,
because the content is by definition hostile and the parsers are third-party.

| Mitigation | Evidence |
|---|---|
| Size caps, extraction timeouts, decompression-ratio limits | `packages/connectors/tests/test_sandbox.py`, `test_extraction.py` |
| Per-unit failure isolation: one bad attachment does not fail a scan | `test_extraction.py`, `apps/engine/tests/test_runner.py` |
| Redaction happens in the engine, before results leave it | `packages/core/tests/test_redaction.py` |
| Dropped and clipped matches do not leak plaintext | `test_redaction.py` (ADR 0004) |

**Residual risk, stated:** a memory-safety bug in `pypdf` or the standard library's parsers is not
mitigated by any of the above. The controls bound the blast radius (non-root, read-only rootfs, no
database credentials, no master key) rather than prevent it. Out-of-process sandboxing of extraction
remains the honest next step.

### 5. Engine ↔ source API

| Mitigation | Evidence |
|---|---|
| Redirects are followed **without** the credential | `packages/connectors/tests/test_confluence_client.py` |
| `POST /sources/{id}/test` refuses redirects outright | `apps/api/tests/test_source_probe.py` |
| Credentials never reach a log line (`Credential.__repr__` overridden) | `test_confluence_client.py` |
| Response bodies are not echoed back; exception text reduced to its type | `test_source_probe.py` |

### 6–7. API ↔ Postgres, API ↔ secret store

| Mitigation | Evidence |
|---|---|
| Only the api holds database credentials | `apps/engine/tests/test_no_db_access.py`, `tests/test_deploy_invariants.py`, `deploy/docker/verify-images.sh`, `deploy/helm/verify-chart.sh` |
| The engine image has no importable database package at all | `verify-images.sh` (probe on the built image) |
| The engine's Helm Secret contains no database URL or master key | `verify-chart.sh` (probe on rendered manifests) |
| Secrets are reached only through the `SecretStore` interface | `packages/core/tests/test_no_raw_env_reads.py` |
| Sealed refs are bound to a purpose — a credential ref cannot be opened as the pepper | `packages/core/tests/test_secrets.py` |
| Failure modes are undifferentiated, so the store is not an oracle | `test_secrets.py` |

---

## Key mitigations

| Mitigation | Evidence |
|---|---|
| **No plaintext at rest** — masked snippet + salted hash only | `test_redaction.py`, `test_results_ingest.py`; `FindingPayload` has no field for a secret |
| **Peppered hashes**, not brute-forceable offline from a dump | `packages/core/tests/test_fingerprint.py` |
| **Encrypted connector credentials**, never returned in plaintext | `test_sources_api.py`, `test_secrets.py` |
| **Full audit trail** on finding state, assignee and comments | `test_triage.py` |
| **RBAC** enforced server-side | `test_rbac.py` |
| **Notification payloads carry no secret and no analyst notes** | `test_notification_dispatch.py` |
| **Webhook requests are signed; redirects are not followed** | `test_notification_dispatch.py` |
| **Retention never deletes open findings or analyst decisions** | `test_retention.py` |
| **Pepper rotation preserves triage state** | `test_pepper_rotation.py` (the dry-run for the runbook) |

### Transport

TLS is a deployment control, not a code one. The chart's Ingress enables TLS by default and the
session cookie is `Secure` by default, so a deployment served over plain HTTP fails to log anyone in
rather than silently downgrading. mTLS between engines and the api is available as hardening and is
not implemented in the chart.

---

## Audit-log coverage

`audit_event` covers **administrative** actions — the ones where "who did this?" must have an
answer. Coverage is asserted by `apps/api/tests/test_audit_coverage.py`, which fails both when a
declared action has no call site and when the reviewed list drifts from the declared vocabulary.

| Action | Written by |
|---|---|
| `user.role_changed`, `user.disabled`, `user.enabled` | `users/routes.py` |
| `source.created`, `source.updated`, `source.deleted` | `sources/routes.py` |
| `source.credential_set`, `source.credential_rotated` | `sources/routes.py` |
| `schedule.created`, `schedule.updated`, `schedule.deleted` | `sources/schedule_routes.py` |
| `suppression.created`, `suppression.deleted` | `findings/suppression_routes.py` |
| `engine.registered`, `engine.token_rotated` | `engines/routes.py`, `cli.py` |
| `channel.created`, `channel.updated`, `channel.deleted`, `channel.secret_set` | `notifications/routes.py` |
| `retention.purged` | `retention.py` |

Each row records the actor (null for system actions), the target, and before/after values where
they exist — never a credential value, which `test_audit_coverage.py` also asserts.

### Deliberately not in `audit_event`

- **Finding triage.** It has a richer, purpose-built trail in `finding_event`, including comments
  and reopenings. Duplicating it here would double the write volume and split the history across two
  tables.
- **Reads.** Nothing records who looked at a finding. Read auditing at this granularity is a
  meaningful cost, and the deployment's value is in *where secrets are* rather than in who browsed
  the list. A regime that requires read auditing should put it in front of the API.
- **Engine lease and heartbeat traffic.** Operational volume, not administrative action. It is in
  the structured logs and the Prometheus series.
- **Failed logins.** The provider owns the authentication event; the API only sees the result. IdP
  logs are the system of record for this, and `rate_limited` covers the abuse case.

---

## Rotation

Documented and dry-run verified in [`runbooks/key-rotation.md`](./runbooks/key-rotation.md).

- **Master key** — a re-seal of every stored ref. Mechanical, offline, minutes; finding identities
  are untouched.
- **Fingerprint pepper** — a re-scan, because identity is an HMAC of a plaintext that was never
  stored. Handled by a dual-pepper window where engines report both identities and ingest re-keys in
  place. `test_pepper_rotation.py` is the dry-run: it asserts that state, resolution, assignee, notes
  and the whole event trail survive, and demonstrates the duplicate-and-auto-resolve failure that
  happens without the window.

---

## Open items

Not blockers, and stated rather than left to be discovered:

1. **Extraction is not out-of-process sandboxed.** Boundary 4's residual risk, above.
2. **The Vault backend is a seam, not an implementation.** `ICEBERG_SECRET_STORE_BACKEND=vault`
   raises a deliberate error. The `env_key` backend puts the master key in the environment, which is
   as good as the platform's secret handling.
3. **No mTLS between engines and the api.** Bearer tokens over TLS; mutual auth is available as
   hardening and is not wired into the chart.
4. **Read access is not audited.** See above.
5. **Rate limiting fails open.** Deliberate — a limiter that locks operators out when its counter
   store hiccups is worse than the traffic it defends against — but it does mean the limits are not
   a control you can rely on while Redis is down.
