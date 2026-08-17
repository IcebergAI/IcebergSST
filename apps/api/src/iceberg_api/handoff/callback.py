"""What comes back from the receiving system, and what it is allowed to do (#141).

Two rules, and the second is the one that shapes everything else.

**The reply is authenticated by the same secret the request was signed with.**
Same scheme, same header, same timestamp-inside-the-MAC as the outbound
hand-over and the notification webhook — an operator who wired up one direction
has already done the work for the other. There is no second credential to issue,
rotate, or leak: a receiver that can verify our signature can produce one.

**What it says is recorded, never applied.** A finding's state is a decision made
by a named analyst through :mod:`iceberg_api.findings.triage`, which enforces the
legal moves and the deployment's evidence policy. A receiver is not a person; its
report is evidence about the work item. So a callback writes to the hand-over row
and stops there, and where the two disagree the API *shows* the disagreement
(:func:`conflict_of`) rather than resolving it on somebody's behalf.

That is the epic's "conflicts surface for review instead of silently overwriting
state", and it is also the only thing that could be correct here: the alternative
is inventing an actor for the audit trail or bypassing the evidence policy, and
both are worse than telling an analyst that two systems disagree.
"""

import hmac
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import structlog
from iceberg_core.config import ApiSettings
from iceberg_core.enums import (
    HANDOFF_EXTERNAL_TERMINAL,
    FindingState,
    HandoffExternalState,
    HandoffStatus,
)
from iceberg_core.models import Finding, FindingHandoff, HandoffTarget
from iceberg_core.secrets import SecretStore, SecretStoreError
from sqlmodel import Session, col, select

from iceberg_api.notifications.schemas import SECRET_REF_KEY
from iceberg_api.notifications.transports import sign

logger = structlog.get_logger()

#: How far out of step a callback's timestamp may be. The timestamp is inside the
#: MAC, so it cannot be edited without breaking the signature — this is what
#: stops a captured request being replayed indefinitely, which the signature
#: alone does not. Generous enough for ordinary clock drift between two systems
#: nobody is synchronising.
CALLBACK_TOLERANCE = timedelta(minutes=5)


class CallbackRefused(ValueError):
    """The callback is not one we will act on. Carries nothing a caller can probe."""


@dataclass(frozen=True, slots=True)
class Conflict:
    """A disagreement between what the receiver says and what the finding says."""

    #: Stable enough to switch on in a client; the prose is for a human.
    kind: str
    reason: str


def verify(
    body: bytes,
    *,
    signature: str | None,
    timestamp: str | None,
    target: HandoffTarget,
    store: SecretStore,
    now: datetime | None = None,
) -> None:
    """Authenticate one callback, or raise :class:`CallbackRefused`.

    Every failure raises the same exception with a message the route does not
    echo back: which of "no secret configured", "bad signature" and "stale
    timestamp" failed is not something an unauthenticated caller gets to learn by
    trying.
    """
    ref = target.config.get(SECRET_REF_KEY)
    if not ref:
        # A target with no secret cannot receive state back, because there is
        # nothing to authenticate it with. Configuring one is the fix, and it is
        # the same secret that signs what goes out.
        raise CallbackRefused("target has no signing secret")
    if not signature or not timestamp:
        raise CallbackRefused("signature and timestamp are required")

    try:
        stamped = datetime.fromtimestamp(int(timestamp), tz=UTC)
    except (ValueError, OverflowError, OSError) as exc:
        raise CallbackRefused("timestamp is not a unix time") from exc
    if abs((now or datetime.now(UTC)) - stamped) > CALLBACK_TOLERANCE:
        raise CallbackRefused("timestamp is outside the tolerance")

    try:
        secret = store.open(str(ref)).get_secret_value()
    except SecretStoreError as exc:
        raise CallbackRefused("signing secret is unreadable") from exc

    # Constant-time, and over the raw bytes rather than a re-serialised object:
    # re-encoding the JSON would compare a signature against something the sender
    # never signed.
    if not hmac.compare_digest(sign(body, secret, timestamp), signature):
        raise CallbackRefused("signature does not match")


def find_handoff(db: Session, idempotency_key: str) -> FindingHandoff:
    """The hand-over a callback is about, by the key we sent it under.

    The key rather than a row id, because the key is the value the receiver was
    told to treat as the work item's identity — asking it to give back something
    else would be asking it to store a second identifier for no reason.
    """
    handoff = db.exec(
        select(FindingHandoff).where(col(FindingHandoff.idempotency_key) == idempotency_key)
    ).first()
    if handoff is None:
        raise CallbackRefused("no handoff for that idempotency key")
    return handoff


def record(
    db: Session,
    handoff: FindingHandoff,
    *,
    state: HandoffExternalState,
    external_id: str | None = None,
    external_url: str | None = None,
    state_at: datetime | None = None,
    now: datetime | None = None,
) -> FindingHandoff:
    """Write what the receiver said onto the hand-over. Does not commit.

    Accepted on a ``failed`` hand-over as well as a delivered one, and
    deliberately: a delivery whose reply was lost is recorded here as failed
    while the work item exists over there, and a callback is exactly the evidence
    that settles it. Refusing one because our own send did not complete would
    throw away the better information.
    """
    at = now or datetime.now(UTC)
    previous = handoff.external_state

    # Callbacks can arrive out of order — a retried `in_progress` overtaking the
    # `resolved` that followed it is ordinary once anything queues or retries in
    # between. Applying it would move the work item backwards and raise a
    # conflict that stopped being true.
    #
    # Only a receiver's own `state_at` can order them: our arrival time is the
    # order they reached us, which is the thing in question. Without one there is
    # nothing to compare, so the newest wins — the honest answer when the sender
    # has given us no way to tell.
    stale = (
        state_at is not None
        and handoff.external_state_at is not None
        and state_at < _aware(handoff.external_state_at)
    )
    if stale:
        # Still a callback: it is evidence the integration is alive, which is
        # what `last_callback_at` is for, and losing that would make a chatty
        # receiver look silent.
        handoff.last_callback_at = at
        db.add(handoff)
        logger.info(
            "handoff_callback_out_of_order",
            handoff_id=str(handoff.id),
            offered=state.value,
            kept=previous.value if previous else None,
        )
        return handoff

    handoff.external_state = state
    handoff.external_state_at = state_at or at
    handoff.last_callback_at = at
    # The receiver may be telling us the id for the first time — a lost reply to
    # the original POST is the ordinary way that happens. Never blanked by a
    # later callback that omits them: silence is not a retraction.
    if external_id:
        handoff.external_id = external_id[:255]
    if external_url:
        handoff.external_url = external_url[:2048]
    db.add(handoff)

    logger.info(
        "handoff_callback_recorded",
        handoff_id=str(handoff.id),
        external_state=state.value,
        previous_state=previous.value if previous else None,
    )
    return handoff


def _aware(value: datetime) -> datetime:
    """A stored timestamp as an aware UTC instant.

    SQLite hands them back without an offset, and comparing one of those against
    a receiver's offset-aware timestamp raises rather than ordering wrongly —
    which is the better failure, but not one an out-of-order callback should
    cause. Same normalisation as `iceberg_api.schemas._assume_utc`.
    """
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def conflict_of(handoff: FindingHandoff, finding: Finding) -> Conflict | None:
    """The disagreement between the two systems, if there is one now.

    Derived rather than stored, so it cannot go stale: it clears the moment the
    two agree, whether that is a new callback or an analyst triaging the finding
    in the ordinary way. There is no "resolve the conflict" endpoint that applies
    the external state, because that is just triage — and triage already has a
    route, a state machine, and an evidence policy.

    A dismissal silences only the state it was made about (see the model), so a
    receiver moving on raises the question again.
    """
    external = handoff.external_state
    if external is None:
        return None
    if handoff.conflict_dismissed_state is external:
        return None

    open_here = finding.state is FindingState.OPEN
    if external in HANDOFF_EXTERNAL_TERMINAL and open_here:
        # The louder direction: everyone over there has stopped, and the secret
        # is still exposed as far as this system knows.
        return Conflict(
            kind=f"external_{external.value}_finding_open",
            reason=(
                f"the work item is {external.value} but the finding is still open — "
                f"nobody is working this unless somebody here picks it up"
            ),
        )
    if external not in HANDOFF_EXTERNAL_TERMINAL and not open_here:
        return Conflict(
            kind=f"finding_{finding.state.value}_external_open",
            reason=(
                f"the finding is {finding.state.value} here but the work item is still "
                f"{external.value} — somebody may be working something already decided"
            ),
        )
    return None


def dismiss(handoff: FindingHandoff, *, actor_id: uuid.UUID, now: datetime | None = None) -> None:
    """Record that somebody looked at this divergence and accepted it.

    Pinned to the current external state: this is a judgement about *this*
    disagreement, not a permanent exemption from being told about that hand-over
    again.
    """
    handoff.conflict_dismissed_state = handoff.external_state
    handoff.conflict_dismissed_at = now or datetime.now(UTC)
    handoff.conflict_dismissed_by_id = actor_id


def open_conflicts(db: Session) -> list[tuple[FindingHandoff, Finding, Conflict]]:
    """Every hand-over whose two systems currently disagree.

    Only ``delivered`` and ``failed`` rows can qualify — a pending one has not
    reached anybody yet, so there is no second opinion to disagree with. The
    filter is on ``external_state`` being set, which says the same thing more
    directly and needs no join to evaluate.
    """
    rows = db.exec(
        select(FindingHandoff)
        .where(col(FindingHandoff.external_state).is_not(None))
        .order_by(col(FindingHandoff.external_state_at))
    )
    found: list[tuple[FindingHandoff, Finding, Conflict]] = []
    for handoff in rows:
        finding = db.get(Finding, handoff.finding_id)
        if finding is None:
            continue
        conflict = conflict_of(handoff, finding)
        if conflict is not None:
            found.append((handoff, finding, conflict))
    return found


def stale_handoffs(
    db: Session, settings: ApiSettings, *, now: datetime | None = None
) -> list[FindingHandoff]:
    """Delivered hand-overs that no receiver has ever said anything about.

    Sync health, and the question it answers is "did that integration quietly
    stop?" — which nothing else can answer, because a receiver that never calls
    back looks exactly like one that has nothing to report.
    """
    cutoff = (now or datetime.now(UTC)) - timedelta(
        hours=settings.handoff_silent_after_hours,
    )
    rows = db.exec(
        select(FindingHandoff)
        .where(col(FindingHandoff.status) == HandoffStatus.DELIVERED)
        .where(col(FindingHandoff.last_callback_at).is_(None))
        .where(col(FindingHandoff.delivered_at) < cutoff)
        .order_by(col(FindingHandoff.delivered_at))
    )
    return list(rows)
