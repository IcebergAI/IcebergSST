# Notifications

How IcebergSST tells you a secret turned up. Channels are configured in the console (or through
`/notifications/channels`); this document is the delivery contract — what gets sent, when, to
whom, and what happens when it fails.

Configuration is **admin-only** and audit-logged, because a webhook channel is a deliberate way
for finding metadata to leave the deployment (see [`security.md`](./security.md) § Notification
egress).

## When something is announced

A finding is announced when **the scan that just completed opened it**:

- it was seen for the first time in that scan, or
- it had been resolved and this scan saw it again (the secret came back).

Not every open finding on every scan. Being told weekly about the same secret trains people to
ignore the alerts, and the finding is on the console either way.

Two things are never announced:

- **Suppressed findings.** A suppression is an analyst saying "stop telling me about this"
  (ADR 0008). Honouring that in the UI and mailing them anyway would be worse than not having
  suppressions.
- **Findings from a scan that did not complete.** Announcement happens after reconciliation, and
  reconciliation refuses to run for a partial or failed scan (ADR 0009 §4).

Each channel's **event filter** then decides whether that channel cares:

| Field | Meaning |
|---|---|
| `min_severity` | Announce this severity and above. Omitted means every severity. |
| `source_ids` | Restrict to these sources. Empty means all of them. |

## Escalation: a finding that missed its target (#146)

A second event, `finding.overdue`, for the opposite failure: not "a new secret appeared" but
"nobody fixed the one we told you about". It fires when an **open, unsuppressed** finding passes
the response target for its severity, which the maintenance loop notices — a deadline passing is
not something that *happens* to a finding, so nothing else would.

**Who hears about it** is deliberately narrower than an announcement:

| Finding | Escalates to |
|---|---|
| Owned, team has a channel | that team's channel, and nowhere else |
| Owned, team has no channel | nobody — silent by choice; the console's overdue queue is the record |
| Unowned, or owned by a disbanded team | every enabled channel whose event filter selects it |

Telling six channels about work that has an owner is how alerting becomes noise. The unowned
fallback exists because "late, **and** nobody has picked it up" is the state most worth saying out
loud, and it is exactly the state with no team to tell.

**Once per deadline.** The outbox row carries the `due_at` it is about, and a partial unique index
over `(channel_id, finding_id, due_at)` enforces one escalation per deadline per channel. The
existing constraint cannot do this: it includes `scan_id`, which is NULL on an escalation, and
NULLs do not collide — so without the index the loop would mail the owning team once a minute.

A reopened finding gets a fresh clock and therefore a fresh escalation if it misses the new target.
That is the intent: the team missed a new deadline, not the old one again. A message already queued
still reports the deadline **it** was queued for — the outbox row records which event it is, and the
finding only records where its clock is now.

A channel added later does not hear about findings that went overdue before it existed: the queue
is drained per (finding, deadline), the same rule an announcement follows when a new channel hears
about the next scan rather than every finding in the table.

## How delivery works

Dispatch is a **transactional outbox**, which is what makes "never lost silently" true rather
than aspirational.

1. Reconciliation writes one `notification_delivery` row per (channel, finding) in the same
   transaction that finishes the scan. If the scan commits, the intention to announce commits
   with it. Nothing is sent at this point, so a hung webhook cannot delay an engine's results.
2. The maintenance loop — one replica at a time, under the same advisory lock as the scheduler —
   picks up rows that are due and attempts them.
3. Success marks the row `delivered`. Failure schedules a retry with exponential backoff. After
   the attempt ceiling the row becomes `failed` **and stays**, holding the error that ended it,
   so "what were we never able to send?" is a query rather than a log search.

A `(channel, finding, scan)` uniqueness constraint makes enqueueing idempotent. This matters:
the safety sweep that re-finalizes a scan stranded by a crash re-runs enqueueing, and it must
not announce the same secret on every beat.

Retries are skipped, permanently, for failures that time cannot fix — a channel with no URL, a
relay that is not configured, an HTTP 401/403/400. Retrying those five times only delays the
operator finding out.

### Tuning

| Setting | Default | What it does |
|---|---|---|
| `ICEBERG_NOTIFICATION_MAX_ATTEMPTS` | `5` | Attempts before a delivery is marked `failed`. |
| `ICEBERG_NOTIFICATION_RETRY_BACKOFF_SECONDS` | `60` | First retry delay; doubles each attempt (≈16 min by the fifth). |
| `ICEBERG_NOTIFICATION_BATCH_SIZE` | `50` | Deliveries attempted per maintenance round. |
| `ICEBERG_WEBHOOK_TIMEOUT_SECONDS` | `10` | Per-attempt ceiling for a webhook POST. |

## Webhook payload

`POST` to the channel's URL, `Content-Type: application/json`.

```json
{
  "version": "1",
  "event": "finding.opened",
  "channel": {"id": "…", "name": "security-alerts"},
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
  "scan": {"id": "…", "trigger": "scheduled"}
}
```

An escalation is the same envelope with `"event": "finding.overdue"`, the same `finding` and
`source` blocks — so a receiver parses one shape and switches on `event` — no `scan` block, because
nothing scanned, and one block of its own:

```json
{
  "escalation": {
    "due_at": "2026-08-15T06:00:00+00:00",
    "overdue_by_hours": 30,
    "owner_group": {"id": "…", "name": "payments"}
  }
}
```

`owner_group` is null when nobody owns the finding — which, given the routing table above, is why
that message reached a general channel rather than a team's.

`version` is bumped when a field is **removed or changes meaning**. Adding a field does not bump
it, so receivers should ignore keys they do not recognise.

**What is deliberately not in there:** the secret (only the snippet the engine already redacted —
ADR 0004 — and never anything reversible), and analyst triage state such as notes and assignee.
The payload is built from an explicit field list, so adding a column to `Finding` cannot silently
start exporting it.

### Headers

| Header | Value |
|---|---|
| `X-Iceberg-Event` | The `event` value, so a receiver can route without parsing the body. |
| `X-Iceberg-Timestamp` | Unix seconds, and part of the signed material. |
| `X-Iceberg-Signature` | `sha256=<hex>` — present only when the channel has a secret. |

Custom headers configured on the channel are sent as-is, except that the header names carrying
credentials (`Authorization`, `Proxy-Authorization`, `Cookie`) are refused at write time — channel
config is stored as plain JSON, so a token there would be a plaintext secret at rest.

### Verifying the signature

The MAC covers `"<timestamp>." + <raw request body>` with the channel secret:

```python
import hashlib, hmac

def verify(body: bytes, timestamp: str, signature: str, secret: str) -> bool:
    expected = hmac.new(secret.encode(), f"{timestamp}.".encode() + body, hashlib.sha256)
    return hmac.compare_digest(f"sha256={expected.hexdigest()}", signature)
```

Verify against the **raw bytes**, not a re-serialised object. Reject a timestamp outside your
tolerance (a few minutes) so a captured request cannot be replayed indefinitely, and use a
constant-time comparison.

### Receiver expectations

- Answer within the timeout, and answer `2xx`. Any `4xx`/`5xx` is a failed delivery.
- **Redirects are not followed.** A `302` is a failed delivery, because following one would be a
  way to move where findings are sent without anyone editing the channel.
- Be idempotent on `finding.id` + `scan.id`. A retry after a response that was lost in transit
  will deliver the same announcement twice; that is the correct behaviour for an at-least-once
  system.

## Email

Plain text, one message per finding, to the channel's recipients. Plain text on purpose: an HTML
mail containing attacker-influenced content — a resource locator is a path from a scanned system —
is an injection surface in whatever client opens it, for no gain over a readable summary.

The subject is `[IcebergSST] <SEVERITY> secret in <source name>`, so severity sorts and filters in
an inbox.

Email needs a relay configured on the **api** role:

| Setting | Default | Notes |
|---|---|---|
| `ICEBERG_SMTP_HOST` | *(unset)* | Unset disables email delivery entirely. |
| `ICEBERG_SMTP_PORT` | `587` | Submission. |
| `ICEBERG_SMTP_USERNAME` / `ICEBERG_SMTP_PASSWORD` | *(unset)* | Omit for an unauthenticated relay. |
| `ICEBERG_SMTP_STARTTLS` | `true` | Certificates are verified. Turn off only for a relay on localhost. |
| `ICEBERG_SMTP_FROM` | `icebergsst@localhost` | Envelope and header sender. |
| `ICEBERG_SMTP_TIMEOUT_SECONDS` | `10` | Per-attempt ceiling. |

With no relay configured, an email channel's deliveries fail **permanently** with a message
naming `ICEBERG_SMTP_HOST` rather than retrying — a configured channel on an unconfigured
deployment should be loud, not quietly undelivered.

## Operating

Deliveries are rows, so the questions have answers:

```sql
-- what never went out, and why
SELECT channel_id, finding_id, attempts, last_error
FROM notification_delivery WHERE status = 'failed';

-- what is queued right now
SELECT count(*) FROM notification_delivery WHERE status = 'pending';
```

Logs carry the same events: `notifications_enqueued`, `notification_sent`,
`notification_retry_scheduled`, `notification_failed`.
