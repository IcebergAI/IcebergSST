# Credential liveness validation

IcebergSST can optionally ask an approved credential provider whether a detected
credential is currently accepted. This is prioritization evidence, not a
remediation action: it never suppresses a finding, changes its identity, or marks
it resolved.

## Safety boundary

Validation is off unless the deployment switch and an enabled administrator
policy both authorize the exact detector/validator pair. The candidate plaintext
exists only in engine memory and in the approved provider request. The API stores
only:

- provider and reviewed validator contract versions;
- `live`, `revoked`, `unknown`, `blocked`, or `error`;
- a fixed content-free reason; and
- the API acceptance timestamp.

No response body, header, account identity, URL, exception text, or plaintext is
sent back to the API. Provider calls use a fixed HTTPS origin and read-only path,
do not follow redirects, do not use environment proxies, make no retries, and are
bounded by policy time and request budgets. The per-minute budget is enforced by
an atomic Redis counter shared across engine replicas; Redis failure blocks the
provider call rather than falling back to a per-process allowance.

`live` means the reviewed provider contract positively accepted the credential.
`revoked` means it conclusively rejected it. Rate limits and ambiguous provider
responses are `unknown`; local policy or budget denial is `blocked`; transport,
timeout, provider availability, and protocol failures are `error`.

## Supported contract

`github-token-v1` applies only to `github-token` and
`github-fine-grained-pat`. It performs one authenticated `GET
https://api.github.com/user`, discards the body, maps `200` to `live` and `401`
to `revoked`, and treats every other response conservatively. This contract pins
GitHub REST API version `2022-11-28`, which GitHub documents as supported through
March 10, 2028.

Provider references:

- [Get the authenticated user](https://docs.github.com/en/rest/users/users#get-the-authenticated-user)
- [Authenticating to the REST API](https://docs.github.com/en/rest/authentication/authenticating-to-the-rest-api)
- [GitHub REST API versions](https://docs.github.com/en/rest/about-the-rest-api/api-versions)

No AWS, password, private-key, JWT, connection-string, or generic-entropy rule is
eligible. Those shapes either require additional material, lack a side-effect-free
identity request, or are too ambiguous for safe validation.

## Policy administration

Policies are CRUD-managed at `/validation-policies` (admin-only — a policy authorizes plaintext
egress to a provider, so it is an egress decision, not detection tuning). Routes and payloads are
in [`api.md`](./api.md) § Validation policies; the stored shape is in
[`data-model.md`](./data-model.md) § ValidationPolicy.

## Deployment controls

Production deployments must enforce outbound policy in addition to the
application allowlist. Standard Kubernetes NetworkPolicy cannot express an FQDN
provider allowlist; route provider traffic through an operator-controlled egress
proxy or use a policy engine/CNI with audited FQDN controls. Permit only required
DNS, Redis, API, scanned-source, and approved-provider traffic. Do not replace the
provider allowlist with unrestricted Internet TCP/443.

The provider adapter intentionally ignores `HTTP_PROXY`, `HTTPS_PROXY`, and
`NO_PROXY`. If an egress proxy is required, it must be introduced as a separately
reviewed fixed transport boundary rather than through ambient process settings.
