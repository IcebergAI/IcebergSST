"""What an announcement contains (#60).

This module is the whole answer to "what leaves the deployment when a finding
opens", which is why it is separate from the transports that send it and from the
loop that schedules it. A webhook receiver is operator-supplied and outside the
trust boundary (docs/security.md § Notification egress), so the payload is built
from an explicit field list rather than by serialising the ORM row: adding a
column to ``Finding`` must never silently start exporting it.

Two things are deliberately absent:

* **The secret.** Only the redacted snippet the engine produced (ADR 0004) and
  the peppered hash. Neither is reversible, and the plaintext never existed on
  this side of the boundary to begin with.
* **Anything an analyst wrote.** Notes and assignee are internal triage state;
  a chat relay does not need them, and they can contain anything a person typed.

The shape is a documented contract — ``docs/notifications.md`` publishes it and
``apps/api/tests/test_notification_dispatch.py`` pins it, so a receiver that
parses it keeps working.
"""

from datetime import UTC, datetime
from typing import Any

from iceberg_core.models import (
    Finding,
    NotificationChannel,
    OwnerGroup,
    Scan,
    Source,
)

#: Bumped when a field is removed or changes meaning. Additive changes do not
#: bump it: a receiver that ignores unknown keys keeps working, and one that
#: does not was going to break anyway.
PAYLOAD_VERSION = "1"

#: An event name rather than a bare object, so a receiver routing several kinds
#: of message can switch on it and so adding kinds later is not a breaking change.
EVENT_FINDING_OPENED = "finding.opened"

#: An escalation: this finding passed the response target for its severity and
#: is still open (#146). A distinct event rather than a flag on the one above,
#: so a receiver can route "new secret" and "nobody fixed it" differently — they
#: usually go to different people.
EVENT_FINDING_OVERDUE = "finding.overdue"

#: How much snippet to send. Already redacted; capped so a channel cannot be used
#: to stream a large document out through a series of findings.
_MAX_SNIPPET = 500


def _finding_block(finding: Finding, *, console_url: str | None) -> dict[str, Any]:
    """The finding, as every event describes it.

    One function rather than one per event, because a receiver should be able to
    read ``payload["finding"]`` the same way whatever arrived — and because an
    explicit field list is the guard against a new ``Finding`` column silently
    starting to leave the deployment (see the module docstring). A second copy
    would be the one that grew a field nobody reviewed.
    """
    return {
        "id": str(finding.id),
        "fingerprint": finding.fingerprint,
        "rule_id": finding.rule_id,
        "rulepack_version": finding.rulepack_version,
        "severity": finding.severity.value,
        "confidence": finding.confidence,
        "state": finding.state.value,
        # Redacted inside the engine before it ever reached the API (ADR 0004).
        "redacted_snippet": finding.redacted_snippet[:_MAX_SNIPPET],
        "resource_locator": finding.resource_locator,
        "first_seen_at": finding.created_at.isoformat(),
        "url": console_url,
    }


def finding_opened(
    finding: Finding,
    *,
    source: Source,
    scan: Scan,
    channel: NotificationChannel,
    console_url: str | None = None,
) -> dict[str, Any]:
    """The JSON body for a newly-opened finding.

    ``console_url`` is a deep link when the deployment knows its own address; the
    useful thing to put in an alert is a way to go and look at it.
    """
    return {
        "version": PAYLOAD_VERSION,
        "event": EVENT_FINDING_OPENED,
        "channel": {"id": str(channel.id), "name": channel.name},
        "finding": _finding_block(finding, console_url=console_url),
        "source": {"id": str(source.id), "name": source.name, "type": source.type.value},
        "scan": {"id": str(scan.id), "trigger": scan.trigger.value},
    }


def finding_overdue(
    finding: Finding,
    *,
    source: Source,
    channel: NotificationChannel,
    owner_group: OwnerGroup | None,
    at: datetime,
    console_url: str | None = None,
) -> dict[str, Any]:
    """The JSON body for a finding that missed its response target.

    Deliberately the same ``finding`` and ``source`` blocks as
    :func:`finding_opened`, so a receiver parses one shape and switches on
    ``event``. What differs is the ``escalation`` block: the deadline, how far
    past it this is, and who was supposed to be looking at it.

    No ``scan``: nothing scanned. A finding goes overdue by the clock passing.
    """
    due_at = finding.due_at
    if due_at is not None and due_at.tzinfo is None:
        # SQLite hands timestamps back naive; the stored value is UTC either way
        # (`iceberg_api.schemas._assume_utc`).
        due_at = due_at.replace(tzinfo=UTC)
    overdue_by = at - due_at if due_at is not None else None

    return {
        "version": PAYLOAD_VERSION,
        "event": EVENT_FINDING_OVERDUE,
        "channel": {"id": str(channel.id), "name": channel.name},
        "finding": _finding_block(finding, console_url=console_url),
        "source": {"id": str(source.id), "name": source.name, "type": source.type.value},
        "escalation": {
            "due_at": due_at.isoformat() if due_at else None,
            # Whole hours: a receiver formatting "3 hours late" should not have to
            # parse two timestamps, and a float of seconds reads as spurious
            # precision on a deadline measured in days.
            "overdue_by_hours": int(overdue_by.total_seconds() // 3600) if overdue_by else None,
            "owner_group": (
                {"id": str(owner_group.id), "name": owner_group.name} if owner_group else None
            ),
        },
    }


def email_subject(finding: Finding, source: Source) -> str:
    """The subject line. Severity first, because it is what triages the inbox."""
    return f"[IcebergSST] {finding.severity.value.upper()} secret in {source.name}"


def escalation_subject(finding: Finding, source: Source) -> str:
    """The subject line for an escalation. "Overdue" first, because that is what
    distinguishes it from the alert about the same finding opening."""
    return f"[IcebergSST] OVERDUE {finding.severity.value} secret in {source.name}"


def email_body(payload: dict[str, Any]) -> str:
    """A plain-text rendering of the same payload.

    Plain text on purpose: an HTML mail containing attacker-influenced content —
    a resource locator is a path from a scanned system — is a small XSS surface in
    whatever client opens it, for no gain over a readable summary.
    """
    finding = payload["finding"]
    source = payload["source"]
    escalation = payload.get("escalation")
    if escalation:
        owner = (escalation.get("owner_group") or {}).get("name") or "nobody"
        late = escalation.get("overdue_by_hours")
        opening = (
            f"A {finding['severity']} secret in {source['name']} ({source['type']}) has "
            f"passed its response target. Owner: {owner}."
        )
        if late is not None:
            opening += f" Overdue by {late}h (due {escalation.get('due_at')})."
    else:
        opening = (
            f"A {finding['severity']} secret was found in {source['name']} ({source['type']})."
        )
    lines = [
        opening,
        "",
        f"Rule:        {finding['rule_id']} (pack {finding['rulepack_version']})",
        f"Severity:    {finding['severity']}",
        f"Confidence:  {finding['confidence']}",
        f"Fingerprint: {finding['fingerprint']}",
        f"Location:    {finding['resource_locator']}",
        "",
        "Redacted context:",
        f"  {finding['redacted_snippet']}",
        "",
    ]
    if finding.get("url"):
        lines.append(f"Triage it here: {finding['url']}")
        lines.append("")
    lines.append("The secret itself is never included in this message.")
    return "\n".join(lines)
