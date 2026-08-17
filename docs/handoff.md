# Hand-over to an external workflow

Handing a finding to the system that already runs the work: an ITSM queue, a SOAR playbook, a
ticket tracker. A notification says *something happened*; a hand-over asks somebody to **do
something**, and creates an object in another system that then has a life of its own — an id, a
state, a person assigned to it.

The requirement everything here follows from: **repeated delivery creates one external work item.**

## One target type, deliberately

A hand-over target is a signed HTTP `POST`, and that is the only type there is. Every ITSM and SOAR
platform can receive one, usually through automation an operator has already built.

Building a Jira or ServiceNow client here would mean this project owning their authentication,
their pagination, and their field schemas — and being wrong about all three the next time any of
them changes. The vendor-specific field names belong on the receiving side, where somebody can fix
them without waiting for a release of this.

## One finding, one work item

Two independent mechanisms, because either alone leaves a duplicate path open:

1. **A unique constraint on `(target_id, finding_id)`.** A second hand-over of the same finding to
   the same target cannot be inserted, no matter how many times a button is pressed or a retry
   fires. Asking twice returns the hand-over that already exists rather than an error — a second
   click, a retried request, and two analysts reaching the same conclusion are the same event.
2. **An idempotency key that is never regenerated.** This covers what the constraint cannot: a
   request that *arrived* whose reply was lost. The retry carries the same key the receiver already
   deduplicated on. Replaying a failed hand-over resets its attempt counter but **not** its key —
   it is still the same hand-over of the same finding.

The key is derived from the pair it is unique on (`iceberg-handoff-<target-id>-<finding-id>`), so
it is reproducible from the row rather than something that has to be preserved.

## Who may do what

Two roles, and the split is the control:

- **Configuring a target is admin-only.** A target carries finding context off the deployment *and*
  creates work items in another system, so it is at least as consequential as a notification
  channel ([`notifications.md`](./notifications.md), docs/security.md § Notification egress). Every
  mutation is audited with the destination it points at — never with the secret.
- **Requesting a hand-over is analyst+**, like triage. Deciding that *this* finding belongs in that
  queue is an analyst's judgement, and the destinations they can choose from are the ones an admin
  already approved. Admins decide where; analysts decide which.

The target *list* is the one place those meet. An analyst has to know which destinations exist to
pick one, so the list is analyst+ and **role-shaped**: an admin sees the whole row, an analyst sees
`id`, `name`, and `type` for the enabled targets and nothing more. A disabled target is not offered,
because requesting it would only earn a `409` — for an admin the disabled state is the information,
for an analyst it is a choice that cannot be made.

Requesting and replaying are both audited, which announcing a finding deliberately is not: an
announcement is the system telling somebody, while a hand-over is a named person putting a finding
into somebody else's queue.

### Routes

- `GET /handoff/targets` (analyst+, role-shaped — see above)
- `POST /handoff/targets` · `GET/PATCH/DELETE /handoff/targets/{id}` (admin)
- `GET  /findings/{id}/handoffs` (analyst+) — where this finding has been sent, and what happened.
- `POST /findings/{id}/handoffs` (analyst+) — hand it to a target. `201` when the call created the
  hand-over, **`200` when one already existed** — asking twice is not an error, and the status code
  is what distinguishes the two.
- `POST /findings/{id}/handoffs/{hid}/replay` (analyst+) — queue a `failed` hand-over for another
  attempt. Only a failed one: a pending one is already queued, and a delivered one has a work item
  on the other side.

A target's `config` is validated by one definition that both `POST` and `PATCH` go through, so a
working target cannot be edited into a destination the sender will not deliver to. The URL is
parsed rather than prefix-matched — a missing host or an invalid port is refused when the target is
saved, by the admin who typed it. A target secret
is write-only exactly like a channel's: supplying one seals it through the secret store (ADR 0007),
no response carries the plaintext *or* the sealed ref, and `has_secret` says whether one exists.
Editing `config` keeps the sealed ref — fixing a typo in a URL is not a request to drop the signing
key.

Disabling a target stops delivery and keeps the history. Deleting one removes its hand-over rows
with it, which is why disabling is the operation for winding a destination down.

## How delivery works

A **transactional outbox**, the same shape as [notification dispatch](./notifications.md):

1. Requesting a hand-over writes one `finding_handoff` row and sends nothing. "The operator asked
   for this" commits before anything leaves the deployment, so no receiver timeout can turn a click
   into a `504` with an unknown outcome.
2. The maintenance loop — one replica at a time, under the same advisory lock as the scheduler —
   attempts rows that are due, and commits per row rather than per batch.
3. Success marks the row `delivered` and records what the receiver called the work item. Failure
   schedules a retry with exponential backoff. After the attempt ceiling the row becomes `failed`
   **and stays**, holding the error that ended it, so "what did we never manage to hand over?" is a
   query rather than a log search. An operator can replay it.

Retries are skipped, permanently, for failures that time cannot fix: a target with no URL, an
unreadable signing secret, a redirect, an HTTP 400/401/403/405/410/413/414/415. A **409 is
deliberately retryable** — a receiver that already holds this idempotency key may say so that way,
and the next attempt should collect its work item id.

Disabling a target stops what is already queued for it, not just what has not been asked for yet.

### Tuning

Shared with notification delivery, because the failure modes are identical and a second dialect for
the same idea would be a second one to get subtly wrong:

| Setting | Default | What it does |
|---|---|---|
| `ICEBERG_NOTIFICATION_MAX_ATTEMPTS` | `5` | Attempts before a hand-over is marked `failed`. |
| `ICEBERG_NOTIFICATION_RETRY_BACKOFF_SECONDS` | `60` | First retry delay; doubles each attempt. |
| `ICEBERG_NOTIFICATION_BATCH_SIZE` | `50` | Hand-overs attempted per maintenance round. |
| `ICEBERG_WEBHOOK_TIMEOUT_SECONDS` | `10` | Per-attempt ceiling for the POST. |

## Payload

`POST` to the target's URL, `Content-Type: application/json`.

```json
{
  "version": "1",
  "event": "handoff.requested",
  "idempotency_key": "iceberg-handoff-…-…",
  "handoff": {"id": "…", "requested_at": "2026-08-16T12:00:00+00:00", "attempt": 1},
  "target": {"id": "…", "name": "soar-prod"},
  "finding": {
    "id": "…",
    "fingerprint": "…",
    "rule_id": "aws-access-key",
    "rulepack_version": "2026.07.1",
    "severity": "high",
    "confidence": 0.92,
    "state": "open",
    "redacted_snippet": "AKIA****************",
    "resource_locator": {"path": "/space/DOCS/page-1"},
    "first_seen_at": "2026-07-31T06:12:44+00:00",
    "url": null
  },
  "source": {"id": "…", "name": "confluence-prod", "type": "confluence"},
  "ownership": {
    "owner_group": {"id": "…", "name": "payments"},
    "due_at": "2026-08-15T06:00:00+00:00"
  },
  "remediation": [
    {
      "kind": "rotated",
      "occurred_at": "2026-08-14T09:30:00+00:00",
      "verification": "confirmed",
      "evidence": ["rotation ticket"]
    }
  ]
}
```

`idempotency_key` is at the top level rather than inside the `handoff` block because it is the field
the *receiver* has to act on. It is identical on every attempt.

`version` is bumped when a field is **removed or changes meaning**. Adding a field does not bump it,
so receivers should ignore keys they do not recognise. It is a separate number from the notification
payload's: the two change for different reasons, and one number covering both would force a receiver
to care about the other's releases.

### What a notification does not carry

`ownership` and `remediation` are the half a hand-over adds, and the half that decides what the
person picking up the ticket actually does (#146, [ADR 0012](./adr/0012-remediation-evidence.md)).
They are not looking at this console. `owner_group` is null when nobody owns the finding, and
`due_at` is null when no clock is running. At most ten remediation actions are included — a work
item needs "what has been tried", not the full history of a finding somebody has been working for
months.

### What is deliberately not in there

- **The secret.** Only the snippet the engine already redacted
  ([ADR 0004](./adr/0004-secret-redaction.md)), never anything reversible.
- **Analyst notes and assignee.** Internal triage, written in the expectation that it is internal.
- **Evidence link URLs — only their labels.** An evidence link's URL is analyst-visible
  ([ADR 0012](./adr/0012-remediation-evidence.md)) and a work item often is not.

The payload is built from an explicit field list, so adding a column to `Finding` cannot silently
start exporting it.

### Headers

| Header | Value |
|---|---|
| `X-Iceberg-Event` | The `event` value, so a receiver can route without parsing the body. |
| `X-Iceberg-Timestamp` | Unix seconds, and part of the signed material. |
| `X-Iceberg-Signature` | `sha256=<hex>` — present only when the target has a secret. |
| `Idempotency-Key` | The same value as the body's, so a receiver can deduplicate before it parses anything — which is where deduplicating is cheapest and most likely to be implemented. |

The signature is the same scheme a notification webhook uses, verified the same way: see
[verifying the signature](./notifications.md#verifying-the-signature). An operator who has already
wired up one receiver should not have to learn a second scheme.

## The reply

The direction of information is the one real difference from a notification. A hand-over creates an
object somewhere else, so the reply is read for what that system called it:

```json
{"external_id": "SEC-1234", "external_url": "https://soar.example.test/tickets/SEC-1234"}
```

Both are optional, stored bounded, and never interpreted beyond being displayed — that reply is
somebody else's data. `external_url` is what turns a row in this database into something an analyst
can click through to.

**A reply that is unparseable is not a failure.** The `2xx` already said the work item was created,
and failing over a missing field would retry a create that already succeeded — the exact duplicate
the rest of this design prevents. The row simply carries no external id, which reads as "handed
over, receiver did not say where it went". The same applies to a reply larger than 64 KiB: it is
read against that cap and abandoned one chunk past it, rather than buffered whole and measured
afterwards.

## Receiver expectations

- Answer within the timeout, and answer `2xx`. Any `4xx`/`5xx` is a failed hand-over.
- **Deduplicate on `Idempotency-Key`.** A retry after a response lost in transit will deliver the
  same hand-over twice; that is the correct behaviour for an at-least-once system, and this key is
  what stops it becoming a second ticket.
- **Redirects are not followed.** A `301`/`302`/`307`/`308` is a failed hand-over, and a permanent
  one: following it would be a way to move where findings are sent without anyone editing the
  target, and retrying a canonical-host or trailing-slash redirect just produces the same redirect
  forever. Point the target at the URL you actually serve.
- Return the work item's id and URL if you have them. Everything still works if you do not.
