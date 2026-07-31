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

from typing import Any

from iceberg_core.models import Finding, NotificationChannel, Scan, Source

#: Bumped when a field is removed or changes meaning. Additive changes do not
#: bump it: a receiver that ignores unknown keys keeps working, and one that
#: does not was going to break anyway.
PAYLOAD_VERSION = "1"

#: An event name rather than a bare object, so a receiver routing several kinds
#: of message can switch on it and so adding kinds later is not a breaking change.
EVENT_FINDING_OPENED = "finding.opened"

#: How much snippet to send. Already redacted; capped so a channel cannot be used
#: to stream a large document out through a series of findings.
_MAX_SNIPPET = 500


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
        "finding": {
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
        },
        "source": {"id": str(source.id), "name": source.name, "type": source.type.value},
        "scan": {"id": str(scan.id), "trigger": scan.trigger.value},
    }


def email_subject(finding: Finding, source: Source) -> str:
    """The subject line. Severity first, because it is what triages the inbox."""
    return f"[IcebergSST] {finding.severity.value.upper()} secret in {source.name}"


def email_body(payload: dict[str, Any]) -> str:
    """A plain-text rendering of the same payload.

    Plain text on purpose: an HTML mail containing attacker-influenced content —
    a resource locator is a path from a scanned system — is a small XSS surface in
    whatever client opens it, for no gain over a readable summary.
    """
    finding = payload["finding"]
    source = payload["source"]
    lines = [
        f"A {finding['severity']} secret was found in {source['name']} ({source['type']}).",
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
