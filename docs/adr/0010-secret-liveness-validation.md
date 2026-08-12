# ADR 0010 — Credential liveness validation is an explicit provider disclosure

**Status:** Accepted

## Context

Pattern matches cannot distinguish a revoked or fabricated credential from one a
provider would still accept. Validation cannot be performed from the peppered
hash stored by the API: a provider must receive the candidate plaintext.

ADR 0004 previously said plaintext never leaves the engine. That remains the
default and the persistence boundary, but is too absolute for an explicitly
authorized liveness check.

## Decision

Credential validation is disabled by default and requires both:

1. the deployment-wide validation switch; and
2. an enabled administrator-approved policy for an exact rule and reviewed
   validator pair.

When both are present, plaintext may cross exactly one additional boundary:
the engine sends it over verified TLS to the fixed origin, method, path, and
authentication field compiled into the reviewed provider adapter. It never
crosses the engine-to-API, Redis, database, log, metric, audit, notification, or
browser boundaries.

Validators are allowlisted code, not plugins or request templates. They do not
follow redirects, inherit proxy environment variables, enumerate provider data,
retry, or retain response bodies. They return only a fixed status and reason.
Validation failure never changes scan coverage, suppresses a finding, or marks it
resolved. A Redis-backed fleet counter enforces the administrator's provider
request ceiling across every engine replica and fails closed when unavailable.

The first contract supports GitHub personal-access-token rules with one `GET
/user` request. AWS and generic detectors are ineligible: the detected value is
insufficient for a minimal authentication request or lacks a reviewed contract.

## Consequences

- The provider and its network edge see a discovered credential. Operators must
  authorize this disclosure and account for provider-side logging and policy.
- The findings database still contains no plaintext or reversible derivative.
- Old validation evidence is timestamped rather than silently cleared when a
  policy is disabled.
- A new provider requires code review, conformance tests, documented response
  semantics, and an independent security review before it can be enabled.
