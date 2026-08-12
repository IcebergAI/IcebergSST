# Security model & threat model

IcebergSST handles live secret material and its database maps *where* secrets live. That makes the
system itself a high-value target. This document states the trust boundaries and mitigations.

## Assets
- **The findings database** — reveals which systems contain secrets (even without plaintext).
- **Connector credentials** — tokens/passwords used to read Confluence/Jira/file shares.
- **The fingerprint pepper** and app encryption key.
- **In-flight content** being scanned inside an engine.

## Trust boundaries
1. **Browser ↔ API** — OIDC-authenticated sessions, RBAC on every route (ADR 0005). Session
   cookies + HTMX form posts require **CSRF protection** (token per session, enforced on every
   mutating route).
2. **Engine ↔ API** — per-engine bearer token over mandatory TLS; engines may lease tasks and submit
   results, nothing else. The **lease response carries the source credential (task-scoped) and
   the fingerprint pepper** — the only moment either transits to an engine (ADR 0002, 0009). The
   separation is enforced by which dependency each route declares: an engine token cannot read
   findings or scans, and a browser session cannot lease a task or post results. Both directions are
   tested.
3. **Engine ↔ Redis** — a shared trust surface: any engine can read/enqueue broker messages.
   Mitigations: payloads are task-id hints only (no secrets, no specs), everything is validated
   at lease time, and Redis requires a password. **Transport to the broker is not encrypted by
   anything shipped here** — neither compose nor the chart provisions TLS, so the broker URL (which
   carries the password) and the task-id hints cross the network in clear unless the operator
   arranges otherwise: a `rediss://` endpoint, a service mesh, or a managed Redis. Treat the broker
   network as in-scope until then.
4. **Engine ↔ scanned content** — attachments and pages are **attacker-editable input**
   attacking the extraction parsers. Mitigations: size caps, extraction timeouts,
   decompression-ratio limits, per-unit failure isolation; consider sandboxing extraction.
5. **Engine ↔ source API** — the engine holds a task-scoped source credential and talks to a
   base URL an operator configured. The source decides what the responses say, including where
   they point: a Confluence attachment download answers with a redirect to a signed media URL, so
   redirects must be followed. They are followed **without the credential** — the target is named
   by the response, and a source that could point one at a host it controls would otherwise be
   handed the engine's token. Same reasoning as `POST /sources/{id}/test` refusing redirects
   outright; the difference is that a signed media URL authorises itself and needs nothing from us.
   Credentials never reach a log line: `Credential.__repr__` is overridden, because structlog and
   tracebacks both render values with `repr`.
6. **API ↔ Postgres** — only the API holds DB credentials.
7. **API ↔ secret store** — credentials and pepper accessed only through the `SecretStore`
   interface (ADR 0007).
8. **Engine ↔ credential provider (optional)** — disabled by default. When a deployment switch
   and an administrator-approved exact rule/provider policy both allow it, a detected credential
   is sent once to the fixed read-only HTTPS endpoint compiled into the reviewed adapter. The
   response body is discarded and only a fixed status/reason crosses back to the API (ADR 0010).

## Key mitigations
- **No plaintext at rest.** Redaction happens in the engine; only masked snippet + salted hash
  are stored (ADR 0004). A DB compromise does not leak secrets.
- **Engine credential isolation (honest statement).** A compromised engine can read the content
  it is given, the credential of sources whose tasks it leases, and the shared pepper — but not
  the findings DB, credentials at rest, or other engines' results. Narrower than direct-DB
  workers; not zero.
- **Peppered hashes.** Secret hashes use a pepper from the secret store, so they aren't
  brute-forceable offline from a DB dump. The hash itself is never exposed by the API; the
  analyst-only exposure-cluster views use a *correlation id* derived from it under a separate
  API-held key, which reveals equality and nothing else (ADR 0011).
- **Role-shaped remediation evidence.** Remediation notes and evidence-link URLs are analyst
  material: viewers see that an action happened and its link labels, never the URLs or free
  text, and a retention window can scrub URLs off long-resolved findings (ADR 0012).
- **Encrypted connector credentials.** Stored via the secret store (AES-GCM/Fernet by default;
  Vault in prod). Never logged; never returned by the API in plaintext.
- **Full audit trail.** Every finding state/assignee/comment change writes a `FindingEvent`.
- **RBAC.** admin/analyst/viewer enforced server-side; the UI is not the enforcement point.
- **Transport.** TLS everywhere; engine↔API mutual auth (mTLS) available as hardening.

## Outbound requests
Two features deliberately send traffic out of the deployment, both admin-gated and logged:

- **`POST /sources/{id}/test`** attaches a decrypted source credential to a single request against
  the operator-supplied `base_url`. That URL may be internal — Confluence Server usually is — so
  there is no address blocklist; the controls are that only an admin can trigger it, redirects are
  never followed (a `302` must not receive the credential), nothing from the response body is
  echoed back, exception text is reduced to its type (it can contain the URL), and the request is
  bounded to ten seconds. It is a stopgap: ADR 0009 says the API runs no connector code, and this
  check belongs behind the connector interface (#45) or in an engine task (#35).
- **Webhook notification channels**, below.

## Notification egress
Webhook channels send redacted snippets + resource locations to arbitrary URLs — a deliberate
egress channel. Channel configuration is **admin-only**, the payload is documented, and adding
a channel is audit-logged with the destination it points at.

A channel's signing secret is sealed through the secret store and never returned in a response —
the same contract source credentials have. Custom webhook *headers* are stored as plain JSON, so
the header names that carry authentication (`Authorization`, `Proxy-Authorization`, `Cookie`) are
**refused on write** with a pointer at the sealed `secret` field. A bearer token sitting in clear
text in `notification_channel.config` would be precisely the finding this product exists to report
in other people's systems.

At **dispatch** time (see [`notifications.md`](./notifications.md) for the full contract) the same
boundary applies to what goes over the wire:

- The payload is built from an **explicit field list**, never by serialising the ORM row, so a new
  column on `Finding` cannot silently start being exported. It carries the redacted snippet
  (ADR 0004) and the fingerprint — nothing reversible, and not the peppered secret hash — and no
  analyst notes or assignee.
- Requests are **signed** (`X-Iceberg-Signature`, HMAC-SHA256 over `timestamp.body`) when the
  channel has a secret, so a receiver can distinguish a real announcement from anything else that
  can reach its URL. The timestamp is inside the MAC, so replay has a bounded window.
- **Redirects are not followed.** A `302` would relocate where findings are sent without anyone
  editing the channel, so it is a failed delivery.
- Response bodies are never read into an error message or a log line: they are somebody else's
  data.
- Email is sent as **plain text**. Resource locators come from scanned systems, so an HTML message
  would carry attacker-influenced content into whatever client opens it.
## Rate limiting
Ceilings on the endpoints an unauthenticated caller can reach (#63). These are not the last line
of defence — authentication is — so they are sized to stop floods rather than to meter usage.

| Bucket | Keyed on | Default | Why |
|---|---|---|---|
| `/auth/login`, `/auth/callback` | client address | 20 / min | Unlimited, these are a way to make the API hammer the identity provider, and the callback is the cheapest way to make it verify a JWT against a JWKS. |
| Rejected engine tokens | client address | 30 / min | Bounds credential stuffing and puts it in the metrics. Only **failures** are charged, so a healthy fleet never touches this bucket. |
| Accepted engine requests | **engine id** | 600 / min | Per engine, not per address: a fleet behind one NAT must not share a budget, or `--scale engine=N` throttles itself. |

Three decisions are worth stating explicitly, because the alternatives all look reasonable:

- **It fails open.** If the counter store is unreachable, requests are allowed and a warning is
  logged. A limiter that locks every operator out of the console when Redis hiccups has done more
  damage than the traffic it was defending against.
- **`X-Forwarded-For` is ignored by default.** The header is caller-controlled, so trusting it
  would let an attacker take a fresh identity per request — the same as having no limit. Set
  `ICEBERG_TRUSTED_PROXY_HOPS` to the number of reverse proxies in front, and the client address is
  taken from the entry the outermost trusted proxy added. **Behind a load balancer, this must be
  set, or every request is charged to the balancer.**
- **Counters live in Redis** when it is configured, so a limit means the same thing across
  replicas. The in-memory fallback is exact for one replica and per-replica for several — a real
  limit, just a looser one.

Refusals answer `429` with `Retry-After`; allowed requests carry advisory `RateLimit-Limit`,
`RateLimit-Remaining` and `RateLimit-Reset` headers so a well-behaved client can back off before
it is refused.

## The browser surface (M3)
The console renders attacker-influenced strings — Confluence page titles, resource paths, redacted
snippets — which makes it the highest-value stored-XSS target in the deployment. The mitigations,
in full in [`web.md`](./web.md):

- **`script-src 'self'` with no `'unsafe-inline'` and no `'unsafe-eval'`.** Possible because the UI
  carries no inline JavaScript at all: Alpine runs from its CSP build, every component is registered
  in a same-origin `/static` file, and server data reaches it through
  `<script type="application/json">` islands. `style-src` keeps `'unsafe-inline'` for dynamic
  `style=` attributes only — the standard "strict CSP targets scripts" carve-out.
- **Every frontend dependency is first-party**, pinned in `static/assets.lock.json` with an SRI
  hash, and verified against the committed bytes by a test rather than by a network call. Fonts are
  self-hosted, so the console also works air-gapped.
- **`frame-ancestors 'none'`** (plus the legacy `X-Frame-Options: DENY`), `nosniff`,
  `Referrer-Policy: strict-origin-when-cross-origin` so a source name in the URL does not leak
  cross-origin, a deny-all `Permissions-Policy`, `Cross-Origin-Opener-Policy: same-origin`, and HSTS
  in production.
- **CSRF on every mutating browser route** — asserted across the whole router, not route by route.
- **No credential is ever rendered.** The source form has none to echo, the channels screen shows
  `sealed`/`none`, and an engine token appears once, in the response that minted it.

FastAPI's interactive docs (`/docs`, `/redoc`) are exempted from the CSP by path: they load Swagger
UI from a CDN and bootstrap it inline, and a policy loose enough to run them would be no policy.
They are a developer tool, not part of the product surface.

## Authentication in practice (ADR 0005)
- **Flow:** authorization code + PKCE. `state` lives in a short-lived signed cookie (blocks a forced
  login); `nonce` is checked inside the ID token (blocks replaying a token minted for another
  session); the ID token is verified against the provider's JWKS for signature, issuer, audience,
  and expiry — never merely decoded.
- **Sessions:** signed, expiring `HttpOnly` cookies (`SameSite=Lax`, `Secure` unless explicitly
  disabled for local HTTP). They carry the user id and a CSRF token and **no role**, so revocation
  is immediate. `ICEBERG_SESSION_SECRET` must be at least 32 bytes (RFC 7518 §3.2) or the API
  refuses to sign; rotating it logs everyone out, which is the intended blast radius.
- **CSRF:** the authoritative token is inside the session cookie, not a second cookie a sibling
  subdomain could set, and is echoed via `X-CSRF-Token` or a `csrf_token` form field on every
  mutating route.
- **Least privilege by default:** a first-time login lands as `viewer`. An account exists because
  the IdP knows the person, not because anyone decided what they may do.
- **Roles are ours, not the IdP's:** a returning user's role comes from the database, so no claim in
  a token can promote anyone.

## Bootstrap
- **First admin:** OIDC-only auth needs a seed — an env-configured OIDC subject (or email) is
  granted `admin` on first login. Matched **only at user creation**, so a bootstrap admin who is
  deliberately demoted is not re-promoted by logging in again. All later role changes happen in-app
  and are audited in `audit_event`.
- **No self-service role changes:** nobody may change their own role or disable their own account,
  admins included. That blocks self-promotion and removes any path to locking the last admin out.
- **First engine token:** minted at deploy time with
  `python -m iceberg_api mint-engine-token --name engine-1` (`./deploy/compose/engine-token.sh`
  wraps that for the dev stack) or a provisioning Job (Helm) —
  never a default credential baked into an image. Only the token's SHA-256 hash is stored, so it
  cannot be shown twice; re-running the command **rotates** it, which is also how an operator
  replaces a token they believe has leaked — rotation keeps the engine's id, so only the token has
  to be replaced. Registration through the API requires an admin session, because an engine that
  could enrol itself would let anyone reaching the API join the fleet.

  The command prints the engine's **id** as well, and the engine needs both
  (`ICEBERG_ENGINE_ID`, `ICEBERG_ENGINE_TOKEN`). An engine names itself in its heartbeat path and
  the API checks the two agree, so a token on its own can lease and report but never renew a lease —
  a degraded mode the worker warns about at startup rather than refusing to run, since scans still
  complete, just less efficiently. **No token at all is different:** the worker refuses to start,
  because an engine that connects to the broker without a credential consumes tasks it can only
  fail, and every one of them then sits until its lease lapses. That is why the compose engine waits
  behind a profile until a token exists (`docs/deployment.md` § Bringing up an engine).

## Secret store in practice (`EnvKeyBackend`)
The default backend (ADR 0007) is AES-256-GCM with a master key injected as
`ICEBERG_MASTER_KEY`. Secrets are stored as **sealed refs** — self-contained, opaque strings safe
to keep in a database column (`Source.credential_ref`), to log, and to return from the API:

```
envkey:1:<purpose>:<base64url(nonce || ciphertext || tag)>
```

- **Purpose binding.** `credential`, `pepper`, and `generic` refs are cryptographically distinct:
  the purpose is authenticated data, so a credential ref cannot be opened as the pepper, and
  editing the purpose in a database row makes the ref fail to open rather than open as something
  else.
- **Single reader of the environment.** Only `iceberg_core.config` reads env vars; everything else
  goes through the `SecretStore` interface. `packages/core/tests/test_no_raw_env_reads.py` walks the
  shipped source and fails on any `os.environ`/`os.getenv` elsewhere.
- **Bootstrap commands** (see `.env.example`):

  ```
  python -m iceberg_core.secrets generate-master-key   # → ICEBERG_MASTER_KEY
  python -m iceberg_core.secrets generate-pepper       # → ICEBERG_FINGERPRINT_PEPPER_REF
  python -m iceberg_core.secrets seal < credential     # → an opaque credential ref
  ```

  `generate-pepper` prints only the sealed ref — the pepper itself is never displayed. `seal` reads
  from stdin, never from arguments, because arguments are visible in `ps`.
- **Vault seam.** `ICEBERG_SECRET_STORE_BACKEND=vault` is recognised and fails with a pointer to
  ADR 0007 until the backend lands. A Vault backend implements the same two primitives, with the
  ref naming a Vault path instead of carrying ciphertext; no call site changes.

## Operator responsibilities (env-key backend)
With the default `EnvKeyBackend`, the operator owns:
- Protecting and rotating the master encryption key (via env/k8s secret).
- Protecting the fingerprint pepper — rotating it invalidates all finding identities and
  requires the documented re-key procedure (ADR 0007).
- Restricting network access to Postgres and Redis to the API/engine roles. Redis auth is
  configured; **TLS to the broker is not** — arrange it yourself (`rediss://` URLs, a mesh, or a
  managed Redis) and see boundary 3 for what is exposed until you do.
- Moving to the Vault backend for production-grade key separation (ADR 0007).

## Out of scope (MVP)
Multi-tenancy isolation, image OCR, external ticket creation. Adding any of these must revisit
this threat model.
