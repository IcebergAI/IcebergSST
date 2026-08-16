"""The triage state machine and its audit trail (#39).

Every change to a finding that an analyst can make goes through :func:`apply`, so
there is exactly one place where a `FindingEvent` can be forgotten. Triage is the
product's whole point — an untracked state change is a decision nobody can trace
back to a person.

**All roads back through `open`.** The legal moves are `open` → a judgement, and a
judgement → `open`; there is no direct `false_positive` → `resolved`. Judgements
are decisions about a secret, not labels to be swapped: relabelling one in place
would leave an audit trail that reads "it was always this" rather than "somebody
reopened it and decided again". Two calls is the cost, and the second is a reopen
that says who did it.

**Only real changes are recorded.** Re-sending the state a finding is already in is
a no-op rather than a conflict — a retried request and an idle "Save" click are not
errors, and an audit log full of "open → open" is one nobody reads.
"""

import uuid
from collections.abc import Callable

import structlog
from iceberg_core.enums import FindingEventKind, FindingResolution, FindingState
from iceberg_core.models import Finding, FindingEvent
from sqlmodel import Session

from iceberg_api.findings.schemas import FindingUpdate

logger = structlog.get_logger()

#: Legal moves. Anything not listed here is refused, including a move out of a
#: judgement into another judgement.
LEGAL_TRANSITIONS: dict[FindingState, frozenset[FindingState]] = {
    FindingState.OPEN: frozenset(
        {FindingState.FALSE_POSITIVE, FindingState.ACCEPTED_RISK, FindingState.RESOLVED}
    ),
    FindingState.FALSE_POSITIVE: frozenset({FindingState.OPEN}),
    FindingState.ACCEPTED_RISK: frozenset({FindingState.OPEN}),
    FindingState.RESOLVED: frozenset({FindingState.OPEN}),
}


class IllegalTransition(ValueError):
    """A requested state change is not a move this state machine allows."""

    def __init__(self, source: FindingState, target: FindingState) -> None:
        super().__init__(
            f"cannot move a finding from {source.value} to {target.value}; "
            f"reopen it first if that is what you mean"
        )
        self.source = source
        self.target = target


class EvidenceRequired(ValueError):
    """The deployment's policy demands evidence before this resolution (#142).

    Raised before anything is written, like :class:`IllegalTransition`: a
    refused resolution must not half-apply an assignment either.
    """

    def __init__(self) -> None:
        super().__init__(
            "resolving a finding of this severity requires a remediation action "
            "with evidence; record one first (ADR 0012)"
        )


def apply(
    db: Session,
    finding: Finding,
    changes: FindingUpdate,
    *,
    actor_id: uuid.UUID,
    evidence_check: Callable[[Finding], bool] | None = None,
) -> list[FindingEvent]:
    """Apply a triage change, writing one event per real change. Does not commit.

    Raises :class:`IllegalTransition` if the state move is not allowed; nothing is
    written in that case, so a rejected transition cannot leave a half-applied
    assignment behind.

    ``evidence_check`` is the required-evidence policy (#142), passed by the
    route when the deployment configured one: called only for a move to
    ``resolved``, and a ``False`` refuses the change with
    :class:`EvidenceRequired` — same all-or-nothing contract. The judgement
    states are exempt by design: ``false_positive`` and ``accepted_risk`` are
    decisions that no secret needed rotating, so there is nothing to evidence.
    """
    # A state equal to the current one is nothing to do, not a transition to check.
    moving_to = changes.state if changes.state is not finding.state else None

    # Validate before mutating anything: a PATCH that changes state *and* assignee
    # either applies as a whole or not at all.
    if moving_to is not None and moving_to not in LEGAL_TRANSITIONS[finding.state]:
        raise IllegalTransition(finding.state, moving_to)
    if (
        moving_to is FindingState.RESOLVED
        and evidence_check is not None
        and not evidence_check(finding)
    ):
        raise EvidenceRequired()

    events: list[FindingEvent] = []
    supplied = changes.model_fields_set

    if moving_to is not None:
        events.append(_transition(finding, moving_to, actor_id, changes.comment))

    # `null` unassigns; an omitted field leaves the assignee alone. Pydantic cannot
    # express that distinction in the type, so it is read off the raw request.
    if "assignee_id" in supplied and changes.assignee_id != finding.assignee_id:
        events.append(_assign(finding, changes.assignee_id, actor_id, changes.comment))

    # Owner is read the same way, but pins on *any* supplied value — including one
    # equal to the current owner. "Yes, this really is ours" is a decision worth
    # honouring: without it, confirming a routed owner would leave the finding
    # still eligible to be re-routed, and the confirmation would mean nothing.
    if "owner_group_id" in supplied:
        events.extend(_own(finding, changes.owner_group_id, actor_id, changes.comment))

    if "notes" in supplied and changes.notes != finding.notes:
        events.append(_annotate(finding, changes.notes, actor_id))

    for event in events:
        db.add(event)
    if events:
        db.add(finding)
        logger.info(
            "finding_triaged",
            finding_id=str(finding.id),
            actor_id=str(actor_id),
            kinds=[event.kind.value for event in events],
        )
    return events


def _transition(
    finding: Finding,
    target: FindingState,
    actor_id: uuid.UUID,
    comment: str | None,
) -> FindingEvent:
    previous = finding.state
    finding.state = target
    # `manual` and `auto` describe *who* resolved it, and only a resolved finding
    # has been resolved by anyone: leaving a stale `auto` on a reopened finding
    # would tell reconciliation's story about a decision a person made.
    finding.resolution = FindingResolution.MANUAL if target is FindingState.RESOLVED else None

    return FindingEvent(
        finding_id=finding.id,
        actor_id=actor_id,
        # A move back to `open` is a reopen — the same event ingest and
        # reconciliation write when a secret comes back, so "when did this become
        # live again?" has one answer whoever asked the question.
        kind=(
            FindingEventKind.REOPENED
            if target is FindingState.OPEN
            else FindingEventKind.STATE_CHANGE
        ),
        from_value=previous.value,
        to_value=target.value,
        comment=comment,
    )


def _assign(
    finding: Finding,
    assignee_id: uuid.UUID | None,
    actor_id: uuid.UUID,
    comment: str | None,
) -> FindingEvent:
    previous = finding.assignee_id
    finding.assignee_id = assignee_id
    return FindingEvent(
        finding_id=finding.id,
        actor_id=actor_id,
        kind=FindingEventKind.ASSIGN,
        from_value=str(previous) if previous else None,
        to_value=str(assignee_id) if assignee_id else None,
        comment=comment,
    )


def _own(
    finding: Finding,
    owner_group_id: uuid.UUID | None,
    actor_id: uuid.UUID,
    comment: str | None,
) -> list[FindingEvent]:
    """Set the accountable group by hand, and pin it there (#146).

    Pinning is the point: automatic routing establishes an owner for a finding
    nobody has looked at, and the moment somebody has, the machine stops having an
    opinion. That holds even when the person agrees with the routing — confirming
    an owner is how a team says "yes, ours", and a confirmation that left the
    finding re-routable would be worth nothing.

    Returns no event when there is nothing to record: the same owner, already
    pinned. Re-sending an unchanged decision is a retried request, not a second
    one, and this trail is read by people (see the module docstring).
    """
    if finding.owner_group_id == owner_group_id and finding.owner_pinned:
        return []
    previous = finding.owner_group_id
    finding.owner_group_id = owner_group_id
    finding.owner_pinned = True
    return [
        FindingEvent(
            finding_id=finding.id,
            actor_id=actor_id,
            kind=FindingEventKind.OWNER,
            from_value=str(previous) if previous else None,
            to_value=str(owner_group_id) if owner_group_id else None,
            comment=comment,
        )
    ]


def _annotate(finding: Finding, notes: str | None, actor_id: uuid.UUID) -> FindingEvent:
    """Record the note itself, not the fact that a note changed.

    ``Finding.notes`` is overwritten in place, so without this the previous text is
    gone. Keeping each version in the trail is what makes the notes field safe to
    edit.
    """
    finding.notes = notes
    return FindingEvent(
        finding_id=finding.id,
        actor_id=actor_id,
        kind=FindingEventKind.COMMENT,
        comment=notes,
    )
