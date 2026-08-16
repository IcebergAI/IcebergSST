"""What crosses the boundary when a finding is handed over (#141).

A superset of the notification payload, for a different purpose. A notification
says *something happened*; a handoff asks somebody to **do something**, and the
person who picks up the ticket is not looking at this console. So it carries the
context that decides what they do — who owns it, when it is due, what has already
been tried — and the notification payload deliberately does not.

The three rules from :mod:`iceberg_api.notifications.payload` still hold, and one
matters more here because the destination is a work-queue that humans read:

* **Never the secret.** Only the snippet the engine already redacted (ADR 0004).
* **An explicit field list**, so adding a column to ``Finding`` cannot silently
  start exporting it.
* **Analyst notes stay behind.** They are internal triage, written in the
  expectation that they are internal.

The payload is a documented contract (``docs/handoff.md``) with its own version,
separate from the notification payload's: the two change for different reasons,
and one number covering both would force a receiver to care about the other's
releases.
"""

from datetime import UTC, datetime
from typing import Any

from iceberg_core.models import (
    Finding,
    FindingHandoff,
    HandoffTarget,
    OwnerGroup,
    RemediationAction,
    Source,
)

#: Bumped when a field is removed or changes meaning. Additive changes do not
#: bump it: a receiver that ignores unknown keys keeps working.
PAYLOAD_VERSION = "1"

#: An event name rather than a bare object, so a receiver routing several kinds
#: of message can switch on it.
EVENT_HANDOFF_REQUESTED = "handoff.requested"

#: Same cap as the notification payload, and for the same reason: a channel must
#: not become a way to stream a large document out one finding at a time.
_MAX_SNIPPET = 500

#: Remediation actions included. A work item needs "what has been tried", not the
#: full history of a finding somebody has been working for months.
_MAX_ACTIONS = 10


def handoff_requested(
    handoff: FindingHandoff,
    finding: Finding,
    *,
    source: Source,
    target: HandoffTarget,
    owner_group: OwnerGroup | None,
    remediations: list[RemediationAction],
    console_url: str | None = None,
) -> dict[str, Any]:
    """The JSON body for one hand-over.

    ``idempotency_key`` is at the top level rather than buried in the finding
    block, because it is the field the *receiver* has to act on: it is the same
    on every retry, and treating it as a dedup key is what keeps a lost response
    from becoming a second ticket.
    """
    return {
        "version": PAYLOAD_VERSION,
        "event": EVENT_HANDOFF_REQUESTED,
        # Ours, and stable across every attempt. See the class docstring on
        # `FindingHandoff.idempotency_key`.
        "idempotency_key": handoff.idempotency_key,
        "handoff": {
            "id": str(handoff.id),
            "requested_at": _utc(handoff.created_at).isoformat(),
            "attempt": handoff.attempts,
        },
        "target": {"id": str(target.id), "name": target.name},
        "finding": {
            "id": str(finding.id),
            "fingerprint": finding.fingerprint,
            "rule_id": finding.rule_id,
            "rulepack_version": finding.rulepack_version,
            "severity": finding.severity.value,
            "confidence": finding.confidence,
            "state": finding.state.value,
            # Redacted inside the engine before it ever reached the API.
            "redacted_snippet": finding.redacted_snippet[:_MAX_SNIPPET],
            "resource_locator": finding.resource_locator,
            "first_seen_at": _utc(finding.created_at).isoformat(),
            # Null today, and in the contract from the start. The API does not
            # know its own public address — it may be behind any proxy — and
            # inventing one would put a link in a ticket that goes nowhere. The
            # notification payload carries the same field for the same reason.
            "url": console_url,
        },
        "source": {"id": str(source.id), "name": source.name, "type": source.type.value},
        # The half a notification does not carry, and the half that decides what
        # the person picking up the ticket actually does (#146, ADR 0012).
        "ownership": {
            "owner_group": (
                {"id": str(owner_group.id), "name": owner_group.name} if owner_group else None
            ),
            "due_at": _utc(finding.due_at).isoformat() if finding.due_at else None,
        },
        "remediation": [
            {
                "kind": action.kind.value,
                "occurred_at": _utc(action.occurred_at).isoformat() if action.occurred_at else None,
                "verification": action.verification.value,
                # Labels, never URLs: an evidence link's URL is analyst-only
                # (ADR 0012), and a work item is read by people who are not.
                "evidence": [
                    str(link.get("label", ""))
                    for link in action.evidence_links
                    if link.get("label")
                ],
            }
            for action in remediations[:_MAX_ACTIONS]
        ],
    }


def _utc(value: datetime) -> datetime:
    """A stored timestamp as an aware UTC instant.

    SQLite hands them back without an offset, and a payload that said
    `2026-08-16T06:00:00` with no zone would be read as local time by whatever is
    on the other end — which is the sort of thing nobody notices until a due date
    is eleven hours out. Same normalisation as `iceberg_api.schemas._assume_utc`.
    """
    return value if value.tzinfo else value.replace(tzinfo=UTC)
