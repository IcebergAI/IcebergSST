"""Accountable owners, the rules that pick them, and response targets (#146).

Three tables, one idea: **a finding that nobody owns is a finding nobody closes.**
Triage already records who decided what, but a decision needs someone accountable
before it, and "somebody will get to it" is not a state you can build a queue on.

* :class:`OwnerGroup` is the accountable team — the durable thing a finding is
  routed to. Individuals move teams; ``Finding.assignee_id`` is still the person
  currently holding it, and stays exactly what it was.
* :class:`RoutingRule` is how a finding acquires a group without anyone typing.
  Ordered, first match wins, and every matcher is optional so the last rule can be
  a catch-all.
* :class:`ResponseTarget` is how long a severity may sit before it is overdue.

All three are *tuning*, so they live in the database and are editable by an
operator rather than compiled in (CLAUDE.md invariant 3). None of them is
detection logic; changing a target changes a date, never what is found.
"""

import uuid
from typing import Any

from sqlalchemy import Index
from sqlmodel import Field

from iceberg_core.enums import Severity
from iceberg_core.models.base import TimestampedModel, enum_type, json_type


class OwnerGroup(TimestampedModel, table=True):
    """A team that can be held accountable for a finding.

    Deliberately not a set of users. Membership is the identity provider's
    business (ADR 0005) and a group whose meaning depends on a membership list
    this system maintains would be stale the first time somebody changed teams.
    What this row has to be is *stable* — findings point at it for their whole
    lifetime, and a queue titled "unowned" is only meaningful if the alternative
    does not evaporate.
    """

    __tablename__ = "owner_group"

    name: str = Field(max_length=255, unique=True)
    description: str | None = Field(default=None, max_length=1000)

    #: Where this group hears about its own findings. Optional: a group with no
    #: channel is still a valid owner, it is just one that has to come looking.
    #: SET NULL rather than CASCADE — deleting a channel must not silently
    #: dissolve the team that owned a hundred findings.
    notification_channel_id: uuid.UUID | None = Field(
        default=None,
        foreign_key="notification_channel.id",
        ondelete="SET NULL",
    )

    #: A disbanded team. Kept, never deleted, so its findings keep their history;
    #: routing skips it and the console can say "owned by a group that no longer
    #: exists" rather than showing an id.
    disabled: bool = Field(default=False)


class RoutingRule(TimestampedModel, table=True):
    """One "findings like this belong to that team" rule (#146).

    **Every matcher is optional and they are ANDed.** A rule with no matchers set
    matches everything, which is exactly how a default owner is expressed — give it
    the highest ``priority`` number so it is consulted last.

    **First match wins, in a total order.** ``priority`` ascending, then
    ``created_at``, then ``id``: ties are broken by something immutable, so the same
    rule set routes the same finding the same way on every replica and after every
    restart. ``priority`` is deliberately *not* unique — a unique column turns
    "put this rule above that one" into a dance around a constraint, and the
    tie-break already makes the order total.
    """

    __tablename__ = "routing_rule"
    __table_args__ = (
        # The evaluation order, as an index: routing loads the enabled rules in
        # precedence order on every ingest transaction.
        Index("ix_routing_rule_priority_created_at_id", "priority", "created_at", "id"),
    )

    #: Human label, for the console and for the audit trail. Unique because
    #: "which rule sent this to us?" needs an answer that is not a UUID.
    name: str = Field(max_length=255, unique=True)

    #: Lower runs first. Not unique; see the class docstring.
    priority: int = Field(default=100, ge=0, le=10_000, index=True)

    owner_group_id: uuid.UUID = Field(foreign_key="owner_group.id", ondelete="CASCADE", index=True)

    #: Matchers. Null (or empty, for ``source_tags``) means "do not narrow on
    #: this", never "match nothing" — the difference is what makes a catch-all
    #: expressible.
    source_id: uuid.UUID | None = Field(
        default=None,
        foreign_key="source.id",
        ondelete="CASCADE",
    )
    #: The detector, by rule-pack rule id. Exact, not a pattern: a glob here would
    #: be a second matching language to get subtly wrong beside suppressions.
    rule_id: str | None = Field(default=None, max_length=128)
    #: At or above, by :data:`~iceberg_core.enums.SEVERITY_RANK`.
    min_severity: Severity | None = Field(
        default=None,
        sa_type=enum_type(Severity, name="routing_rule_min_severity"),
    )
    #: Every listed tag must be present on the finding's source. A rule narrows,
    #: so more tags can only ever mean fewer findings.
    source_tags: list[str] = Field(default_factory=list, sa_type=json_type())

    enabled: bool = Field(default=True)


class ResponseTarget(TimestampedModel, table=True):
    """How long a finding of one severity may stay open before it is overdue.

    One row per severity, seeded by the migration so a fresh deployment has dates
    from the first scan rather than after somebody remembers to configure them.

    Stored in hours rather than days because "critical: same day" and "critical:
    24 hours" are different promises, and only one of them survives a scan that
    lands at 23:00.
    """

    __tablename__ = "response_target"

    severity: Severity = Field(
        unique=True,
        sa_type=enum_type(Severity, name="response_target_severity"),
    )
    #: Bounded above at ten years: a target nobody will live to see is a
    #: configuration mistake, not a policy.
    hours: int = Field(ge=1, le=87_600)


#: What a deployment gets before anyone configures anything. Not a fallback the
#: code reads at runtime — the migration writes these rows, so the targets in
#: force are always visible in the table an operator edits.
DEFAULT_RESPONSE_TARGET_HOURS: dict[Severity, int] = {
    Severity.CRITICAL: 24,
    Severity.HIGH: 72,
    Severity.MEDIUM: 24 * 14,
    Severity.LOW: 24 * 30,
}


def routing_matchers(rule: RoutingRule) -> dict[str, Any]:
    """A rule's matchers as a payload, for audit events and the console."""
    return {
        "source_id": str(rule.source_id) if rule.source_id else None,
        "rule_id": rule.rule_id,
        "min_severity": rule.min_severity.value if rule.min_severity else None,
        "source_tags": list(rule.source_tags),
    }
