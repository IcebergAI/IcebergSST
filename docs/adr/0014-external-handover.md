# ADR 0014 — External hand-over: one signed POST, and a reply that is recorded rather than applied

**Status:** Accepted

## Context

A notification says *something happened*. It reaches an inbox or a channel, and then it is on
somebody to remember. The work of fixing a leaked credential does not happen here — it happens in
an ITSM queue, a SOAR playbook, a ticket tracker — and those systems already have the things this
one does not: an assignee, an SLA clock somebody's manager watches, a state that survives being
read.

So a finding needs a way to become a work item over there. That raises three questions this ADR
answers, and one requirement everything follows from: **repeated delivery creates one external work
item.** A duplicate ticket is not a cosmetic failure; it is two people doing the same remediation,
or neither, because each assumed the other had it.

"External ticket creation" was on the threat model's own out-of-scope list, whose instruction was
that adding it must revisit the threat model. That is done: trust boundary 9 and the hand-over
bullet under § Outbound requests in [`security.md`](../security.md).

## Decision

### 1. One target type: a signed HTTP POST

A hand-over target is a URL that receives a signed JSON `POST`. There is no Jira target type, no
ServiceNow target type, and no plugin interface for adding one.

Every ITSM and SOAR platform can receive a webhook, usually through automation the operator has
already built. Shipping vendor clients instead would mean this project owning their authentication
schemes, their pagination, and their field schemas — and being wrong about all three the next time
any of them changes, on our release cadence rather than theirs. The vendor-specific mapping belongs
on the receiving side, where the person who cares about it can fix it the same afternoon.

The cost is real and accepted: an operator with no automation platform has to write a small
receiver. That is a worse first-run experience than a "connect Jira" button, and a better second
year.

### 2. The wire format is the notification webhook's, deliberately

Same signature header, same `timestamp.body` MAC, same refusal to follow redirects, same explicit
field list rather than a serialised ORM row. An operator who has wired up one receiver has already
done the work for the other, and the security properties were argued once
([ADR 0004](./0004-secret-redaction.md), `notifications.md`) and are worth having twice.

The payload carries more than an announcement does — `ownership` and up to ten `remediation`
actions — because the person picking up the ticket is not looking at this console and needs to know
who owns it, when it is due, and what has already been tried. It still carries no secret (only the
snippet the engine redacted) and no analyst notes.

The version number is **separate** from the notification payload's. They change for different
reasons, and one number covering both would force every receiver to care about the other's
releases.

### 3. Dedup is two mechanisms, because either alone leaves a path open

1. **A unique constraint on `(target_id, finding_id)`.** A second hand-over of the same finding to
   the same target cannot be inserted — no matter how many times a button is pressed. Asking twice
   returns the existing hand-over rather than an error: a second click, a retried request, and two
   analysts reaching the same conclusion are the same event.
2. **An idempotency key that is never regenerated.** This covers what the constraint cannot: a
   request that *arrived* and whose reply was lost. The retry carries the key the receiver already
   deduplicated on. Replaying a failed hand-over resets its attempt counter but **not** its key.

The key is derived from the pair it is unique on (`iceberg-handoff-<target-id>-<finding-id>`), so
it is reproducible from the row rather than state that has to be preserved to stay correct.

### 4. Delivery is the notification outbox, not a synchronous call

Requesting a hand-over writes a row and returns. The maintenance round sends it. A receiver that
hangs for its full timeout therefore delays a ticket, not an analyst's request — and "what was
never handed over, and why" is a query rather than a log search.

### 5. Admins decide where; analysts decide which

Configuring a target is **admin-only**, because it carries finding context off the deployment *and*
creates work in another system: "who approved that destination" must have an answer, so every
mutation is audited with the destination — never the secret. Requesting a hand-over is
**analyst+**, like triage, and is itself audited with the person who asked.

The target *list* is where the two meet, and it is role-shaped rather than split into two routes:
an analyst sees `id`, `name` and `type` for enabled targets, an admin sees the row. An analyst has
to know which destinations exist to pick one; the URL and the secret's state are not part of that.

### 6. What comes back is recorded beside the finding, never written onto it

A receiver may call back to say its work item changed state. That callback is authenticated by the
**same secret, scheme and headers** as the outbound hand-over — a receiver that can verify our
signature can produce one, so there is no second credential to issue, rotate or leak, and a target
with no secret cannot call back at all.

What it says is **recorded, not applied**, and this is the load-bearing decision of the whole
feature. A finding's state is a decision made by a named analyst, through the triage path that
enforces the legal moves and the deployment's evidence policy
([ADR 0012](./0012-remediation-evidence.md)). A receiver is not a person; its report is *evidence
about the work item*. Applying it would mean either inventing an actor for the audit trail or
bypassing the evidence policy, and both are worse than the alternative.

So a callback writes to the hand-over row and stops. Where the two disagree, the API **shows the
disagreement** and an analyst settles it. That is the epic's "conflicts surface for review instead
of silently overwriting state", and it is also the only thing that could be correct here.

It is why the route answers `202` rather than `200`: this records what was said, and claiming to
have applied anything would be a lie.

## Consequences

- **A new inbound trust boundary**, the only one that is neither a browser session nor an engine
  token — sessionless, CSRF-exempt, and reachable by anyone who can route to the API. It is
  rate-limited per address on the same bucket as failed logins, charged before the body is read,
  bounded at 64 KiB, and answers every failure with one indistinguishable `401`. Written up as
  boundary 9 in [`security.md`](../security.md).
- **A compromised receiver's blast radius is one wrong claim about its own ticket**, sitting beside
  a finding whose analyst-set state it did not touch. That is the payoff for §6.
- **A target's secret does double duty** — signing outbound, authenticating inbound. Rotating it
  breaks both directions at once, which is the honest behaviour but means rotation is a
  coordinated change with the receiver rather than a unilateral one.
- **Two egress payload versions to maintain.** Worth it (§2), but a field that means the same thing
  in both has to be changed in both.
- **No delivery-state push.** A receiver learns nothing about the finding after the hand-over
  unless it asks; the flow is one-way out and one-way back, with no subscription.
- **Nothing purges hand-over rows.** They accumulate with finding history
  ([`retention.md`](../retention.md)).
