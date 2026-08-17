"""Configuring hand-over targets, and asking for a hand-over (#141).

Two audiences, two roles, and the split is the point:

* **Configuring a target is admin-only**, like a notification channel and for a
  stronger version of the same reason (ADR 0005, docs/security.md § Notification
  egress). A target carries finding context off the deployment *and* creates work
  items in another system. "Who approved that destination" must have an answer.
* **Requesting a hand-over is analyst+**, like triage. Deciding that this finding
  belongs in that queue is an analyst's judgement, and the destinations they may
  choose from are the ones an admin already approved. That is the whole shape of
  the control: admins decide *where*, analysts decide *which*.

Delivery is not here. Requesting writes an outbox row and returns; the
maintenance round sends it (docs/handoff.md § How delivery works), so a receiver
that hangs for its full timeout delays a ticket instead of an analyst's request.
"""

import uuid
from typing import Any

import structlog
from fastapi import APIRouter, HTTPException, Response, status
from iceberg_core.enums import HandoffStatus, HandoffTargetType
from iceberg_core.models import (
    AUDIT_HANDOFF_REPLAYED,
    AUDIT_HANDOFF_TARGET_CREATED,
    AUDIT_HANDOFF_TARGET_DELETED,
    AUDIT_HANDOFF_TARGET_SECRET_SET,
    AUDIT_HANDOFF_TARGET_UPDATED,
    AUDIT_TARGET_HANDOFF,
    AUDIT_TARGET_HANDOFF_TARGET,
    Finding,
    FindingHandoff,
    HandoffTarget,
)
from iceberg_core.secrets import SecretStoreError
from pydantic import ValidationError
from sqlmodel import col, select

from iceberg_api import audit
from iceberg_api.auth.dependencies import CsrfProtected, SecretStoreDep, SessionDep
from iceberg_api.auth.rbac import AdminUser, AnalystUser
from iceberg_api.handoff import service
from iceberg_api.handoff.schemas import (
    FindingHandoffRead,
    HandoffRequest,
    HandoffTargetCreate,
    HandoffTargetRead,
    HandoffTargetUpdate,
    public_config,
    validate_config,
)
from iceberg_api.notifications.schemas import SECRET_REF_KEY, EventFilter

router = APIRouter(tags=["handoff"])
logger = structlog.get_logger()


def _read_target(target: HandoffTarget) -> HandoffTargetRead:
    return HandoffTargetRead(
        id=target.id,
        name=target.name,
        type=target.type,
        config=public_config(target.config),
        event_filter=EventFilter.model_validate(target.event_filter),
        has_secret=target.config.get(SECRET_REF_KEY) is not None,
        enabled=target.enabled,
        created_at=target.created_at,
        updated_at=target.updated_at,
    )


def _read_handoff(handoff: FindingHandoff, target_name: str) -> FindingHandoffRead:
    return FindingHandoffRead(
        id=handoff.id,
        target_id=handoff.target_id,
        target_name=target_name,
        finding_id=handoff.finding_id,
        status=handoff.status,
        attempts=handoff.attempts,
        idempotency_key=handoff.idempotency_key,
        external_id=handoff.external_id,
        external_url=handoff.external_url,
        last_error=handoff.last_error,
        requested_by_id=handoff.requested_by_id,
        next_attempt_at=handoff.next_attempt_at,
        delivered_at=handoff.delivered_at,
        created_at=handoff.created_at,
        updated_at=handoff.updated_at,
    )


def _validated_config(target_type: HandoffTargetType, config: dict[str, Any]) -> dict[str, Any]:
    """Validate a config blob, turning a schema failure into a 422.

    A caller-supplied ``secret_ref`` is dropped first: the ref is minted here when
    a secret is sealed, and accepting one from a request would let a caller point
    a target at another object's sealed material.
    """
    submitted = {key: value for key, value in config.items() if key != SECRET_REF_KEY}
    try:
        return validate_config(target_type, submitted)
    except ValidationError as exc:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            [
                {"loc": list(error["loc"]), "msg": error["msg"], "type": error["type"]}
                for error in exc.errors()
            ],
        ) from exc


def _load_target(db: SessionDep, target_id: uuid.UUID) -> HandoffTarget:
    target = db.get(HandoffTarget, target_id)
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "handoff target not found")
    return target


def _load_finding(db: SessionDep, finding_id: uuid.UUID) -> Finding:
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "finding not found")
    return finding


def _seal(store: SecretStoreDep, plaintext: str) -> str:
    if not plaintext.strip():
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "secret must not be blank")
    try:
        return store.seal(plaintext)
    except SecretStoreError as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc)) from exc


def _destination(target: HandoffTarget) -> str:
    """Where this target sends, for the audit trail. Never the secret.

    Truncated to the audit column's width so a 2048-character URL cannot make the
    insert fail — losing the audit row would be worse than a clipped one.
    """
    return str(target.config.get("url", ""))[:255]


# ─── Targets (admin) ──────────────────────────────────────────────────────────


@router.get("/handoff/targets")
async def list_targets(admin: AdminUser, db: SessionDep) -> list[HandoffTargetRead]:
    """Every target, by name. Never any secret material.

    Not paginated, for the reason channels are not: a deployment has a handful,
    and an admin auditing where findings go should see all of them at once rather
    than discover a second page exists.
    """
    targets = db.exec(select(HandoffTarget).order_by(col(HandoffTarget.name)))
    return [_read_target(target) for target in targets]


@router.get("/handoff/targets/{target_id}")
async def read_target(target_id: uuid.UUID, admin: AdminUser, db: SessionDep) -> HandoffTargetRead:
    return _read_target(_load_target(db, target_id))


@router.post("/handoff/targets", status_code=status.HTTP_201_CREATED, dependencies=[CsrfProtected])
async def create_target(
    body: HandoffTargetCreate,
    admin: AdminUser,
    db: SessionDep,
    store: SecretStoreDep,
) -> HandoffTargetRead:
    """Approve a destination, sealing its secret before anything is persisted."""
    if db.exec(select(HandoffTarget).where(HandoffTarget.name == body.name)).first() is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "a target with that name already exists")

    config = _validated_config(body.type, body.config)
    if body.secret is not None:
        config[SECRET_REF_KEY] = _seal(store, body.secret.get_secret_value())

    target = HandoffTarget(
        name=body.name,
        type=body.type,
        config=config,
        event_filter=body.event_filter.model_dump(mode="json"),
        enabled=body.enabled,
    )
    db.add(target)
    db.flush()
    audit.record(
        db,
        actor_id=admin.id,
        action=AUDIT_HANDOFF_TARGET_CREATED,
        target_type=AUDIT_TARGET_HANDOFF_TARGET,
        target_id=target.id,
        to_value=target.name,
        detail={"type": target.type.value, "destination": _destination(target)},
    )
    if body.secret is not None:
        audit.record(
            db,
            actor_id=admin.id,
            action=AUDIT_HANDOFF_TARGET_SECRET_SET,
            target_type=AUDIT_TARGET_HANDOFF_TARGET,
            target_id=target.id,
        )
    db.commit()
    db.refresh(target)
    logger.info("handoff_target_created", target_id=str(target.id), actor_id=str(admin.id))
    return _read_target(target)


@router.patch("/handoff/targets/{target_id}", dependencies=[CsrfProtected])
async def update_target(
    target_id: uuid.UUID,
    changes: HandoffTargetUpdate,
    admin: AdminUser,
    db: SessionDep,
    store: SecretStoreDep,
) -> HandoffTargetRead:
    """Edit a target, and rotate its secret if a new one is supplied.

    ``config`` goes through the **same** validator ``POST`` uses. That is #180:
    the update schema used to declare its own ``url`` without one, so a target
    could be edited into a scheme the sender cannot deliver to and would only fail
    once a finding had been handed to it.
    """
    target = _load_target(db, target_id)
    changed: list[str] = []

    if changes.name is not None and changes.name != target.name:
        clash = db.exec(select(HandoffTarget).where(HandoffTarget.name == changes.name)).first()
        if clash is not None and clash.id != target.id:
            raise HTTPException(status.HTTP_409_CONFLICT, "a target with that name already exists")
        target.name = changes.name
        changed.append("name")

    if changes.config is not None:
        # The sealed ref survives a config edit: it is ours, not the caller's, and
        # an admin fixing a typo in a URL has not asked to drop the signing key.
        existing_ref = target.config.get(SECRET_REF_KEY)
        config = _validated_config(target.type, changes.config)
        if existing_ref is not None:
            config[SECRET_REF_KEY] = existing_ref
        target.config = config
        changed.append("config")

    if changes.event_filter is not None:
        target.event_filter = changes.event_filter.model_dump(mode="json")
        changed.append("event_filter")

    if changes.enabled is not None and changes.enabled != target.enabled:
        target.enabled = changes.enabled
        changed.append("enabled")

    if changed:
        audit.record(
            db,
            actor_id=admin.id,
            action=AUDIT_HANDOFF_TARGET_UPDATED,
            target_type=AUDIT_TARGET_HANDOFF_TARGET,
            target_id=target.id,
            to_value=",".join(changed),
            detail={"destination": _destination(target)},
        )

    if changes.secret is not None:
        # Rotation is its own event: "who changed this target" and "who last
        # replaced its signing key" are different questions.
        target.config = target.config | {
            SECRET_REF_KEY: _seal(store, changes.secret.get_secret_value())
        }
        audit.record(
            db,
            actor_id=admin.id,
            action=AUDIT_HANDOFF_TARGET_SECRET_SET,
            target_type=AUDIT_TARGET_HANDOFF_TARGET,
            target_id=target.id,
        )

    db.add(target)
    db.commit()
    db.refresh(target)
    return _read_target(target)


@router.delete(
    "/handoff/targets/{target_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[CsrfProtected],
)
async def delete_target(
    target_id: uuid.UUID,
    admin: AdminUser,
    db: SessionDep,
) -> Response:
    """Remove a target, and with it the record of what was handed to it.

    The hand-over rows cascade. That is deliberate and is why *disabling* exists:
    disabling stops delivery and keeps the history, which is what an operator
    winding a destination down almost always wants. Deleting is for a destination
    that should never have been approved.
    """
    target = _load_target(db, target_id)
    audit.record(
        db,
        actor_id=admin.id,
        action=AUDIT_HANDOFF_TARGET_DELETED,
        target_type=AUDIT_TARGET_HANDOFF_TARGET,
        target_id=target.id,
        from_value=target.name,
        detail={"type": target.type.value, "destination": _destination(target)},
    )
    db.delete(target)
    db.commit()
    logger.info("handoff_target_deleted", target_id=str(target_id), actor_id=str(admin.id))
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ─── Hand-overs (analyst) ─────────────────────────────────────────────────────


@router.get("/findings/{finding_id}/handoffs")
async def list_handoffs(
    finding_id: uuid.UUID,
    analyst: AnalystUser,
    db: SessionDep,
) -> list[FindingHandoffRead]:
    """Where this finding has been sent, and what happened to it.

    Analyst+ rather than viewer+: this answers "which external systems hold this
    secret's details", which is the same class of question as the target list
    itself rather than part of reading a finding.
    """
    _load_finding(db, finding_id)
    handoffs = db.exec(
        select(FindingHandoff)
        .where(col(FindingHandoff.finding_id) == finding_id)
        .order_by(col(FindingHandoff.created_at))
    )
    return [_read_handoff(handoff, _target_name(db, handoff)) for handoff in handoffs]


@router.post(
    "/findings/{finding_id}/handoffs",
    status_code=status.HTTP_201_CREATED,
    dependencies=[CsrfProtected],
)
async def request_handoff(
    finding_id: uuid.UUID,
    body: HandoffRequest,
    analyst: AnalystUser,
    db: SessionDep,
    response: Response,
) -> FindingHandoffRead:
    """Hand this finding to that target. Idempotent, including under a race.

    Asking twice is not an error: a second click, a retried request, and two
    analysts reaching the same conclusion are the same event, and the honest
    answer is the hand-over that already exists. The status code says which
    happened — 201 when this call created it, 200 when it did not (#181).
    """
    finding = _load_finding(db, finding_id)
    target = _load_target(db, body.target_id)

    try:
        handoff, created = service.request_committed(db, finding, target, actor_id=analyst.id)
    except service.HandoffRefused as exc:
        # The target is disabled, or its filter does not select this finding.
        # Refused rather than silently dropped: an operator who pressed the button
        # is owed an answer about why nothing happened.
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc

    if not created:
        response.status_code = status.HTTP_200_OK
    return _read_handoff(handoff, target.name)


@router.post("/findings/{finding_id}/handoffs/{handoff_id}/replay", dependencies=[CsrfProtected])
async def replay_handoff(
    finding_id: uuid.UUID,
    handoff_id: uuid.UUID,
    analyst: AnalystUser,
    db: SessionDep,
) -> FindingHandoffRead:
    """Queue a failed hand-over for another attempt.

    Only a ``failed`` row can be replayed. A pending one is already queued, and a
    delivered one has a work item on the other side — replaying that would be
    asking for the duplicate the idempotency key exists to prevent, and the fact
    that the receiver would probably deduplicate it is not a reason to send it.
    """
    handoff = db.get(FindingHandoff, handoff_id)
    if handoff is None or handoff.finding_id != finding_id:
        # A mismatched pair is a 404, not a 403: the ids simply do not name a
        # record, and saying more would confirm the other id exists.
        raise HTTPException(status.HTTP_404_NOT_FOUND, "handoff not found")
    if handoff.status is not HandoffStatus.FAILED:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"only a failed handoff can be replayed; this one is {handoff.status.value}",
        )

    service.replay(handoff)
    db.add(handoff)
    audit.record(
        db,
        actor_id=analyst.id,
        action=AUDIT_HANDOFF_REPLAYED,
        target_type=AUDIT_TARGET_HANDOFF,
        target_id=handoff.id,
        detail={"finding_id": str(handoff.finding_id), "target_id": str(handoff.target_id)},
    )
    db.commit()
    db.refresh(handoff)
    logger.info("handoff_replayed", handoff_id=str(handoff.id), actor_id=str(analyst.id))
    return _read_handoff(handoff, _target_name(db, handoff))


def _target_name(db: SessionDep, handoff: FindingHandoff) -> str:
    target = db.get(HandoffTarget, handoff.target_id)
    return target.name if target is not None else ""
