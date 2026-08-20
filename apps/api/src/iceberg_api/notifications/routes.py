"""Notification-channel CRUD (#72).

Admin-only, every route: a webhook channel is an egress path that carries
redacted snippets and resource locations off the deployment, so who may create
one is the control (ADR 0005, docs/security.md § Notification egress). Every
mutation is audited for the same reason — "who pointed our findings at that URL"
must always have an answer.

Dispatch itself is M4. This is the configuration surface the UI drives; the
delivery loop reads these rows.
"""

import uuid
from typing import Any

import structlog
from fastapi import APIRouter, HTTPException, Response, status
from iceberg_core.enums import NotificationChannelType
from iceberg_core.models import (
    AUDIT_CHANNEL_CREATED,
    AUDIT_CHANNEL_DELETED,
    AUDIT_CHANNEL_SECRET_SET,
    AUDIT_CHANNEL_UPDATED,
    AUDIT_TARGET_CHANNEL,
    NotificationChannel,
)
from iceberg_core.secrets import SecretStoreError
from pydantic import ValidationError
from sqlmodel import col, select

from iceberg_api import audit
from iceberg_api.auth.dependencies import CsrfProtected, SecretStoreDep, SessionDep
from iceberg_api.auth.rbac import AdminUser
from iceberg_api.conflicts import commit_or_conflict
from iceberg_api.notifications.schemas import (
    SECRET_REF_KEY,
    EventFilter,
    NotificationChannelCreate,
    NotificationChannelRead,
    NotificationChannelUpdate,
    public_config,
    validate_config,
)

router = APIRouter(prefix="/notifications", tags=["notifications"])
logger = structlog.get_logger()


def _read(channel: NotificationChannel) -> NotificationChannelRead:
    return NotificationChannelRead(
        id=channel.id,
        name=channel.name,
        type=channel.type,
        config=public_config(channel.config),
        event_filter=EventFilter.model_validate(channel.event_filter),
        has_secret=channel.config.get(SECRET_REF_KEY) is not None,
        enabled=channel.enabled,
        created_at=channel.created_at,
        updated_at=channel.updated_at,
    )


def _validated_config(
    channel_type: NotificationChannelType, config: dict[str, Any]
) -> dict[str, Any]:
    """Validate a config blob, turning a schema failure into a 422.

    A caller-supplied ``secret_ref`` is dropped first: the ref is minted here when
    a secret is sealed, and accepting one from a request would let a caller point
    a channel at another object's sealed material.
    """
    submitted = {key: value for key, value in config.items() if key != SECRET_REF_KEY}
    try:
        return validate_config(channel_type, submitted)
    except ValidationError as exc:
        # Pydantic's raw errors carry exception objects in ``ctx``, which will not
        # serialize; reduce them to where/what, which is what a client can act on.
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            [
                {"loc": list(error["loc"]), "msg": error["msg"], "type": error["type"]}
                for error in exc.errors()
            ],
        ) from exc


def _load(db: SessionDep, channel_id: uuid.UUID) -> NotificationChannel:
    channel = db.get(NotificationChannel, channel_id)
    if channel is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "channel not found")
    return channel


def _seal(store: SecretStoreDep, plaintext: str) -> str:
    if not plaintext.strip():
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "secret must not be blank")
    try:
        return store.seal(plaintext)
    except SecretStoreError as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc)) from exc


@router.get("/channels")
async def list_channels(admin: AdminUser, db: SessionDep) -> list[NotificationChannelRead]:
    """Every channel, by name. Never any secret material.

    Not paginated: a deployment has a handful of channels, and an admin auditing
    where findings go should see all of them on one screen rather than discover a
    second page exists.
    """
    channels = db.exec(select(NotificationChannel).order_by(col(NotificationChannel.name)))
    return [_read(channel) for channel in channels]


@router.get("/channels/{channel_id}")
async def read_channel(
    channel_id: uuid.UUID, admin: AdminUser, db: SessionDep
) -> NotificationChannelRead:
    return _read(_load(db, channel_id))


@router.post("/channels", status_code=status.HTTP_201_CREATED, dependencies=[CsrfProtected])
async def create_channel(
    body: NotificationChannelCreate,
    admin: AdminUser,
    db: SessionDep,
    store: SecretStoreDep,
) -> NotificationChannelRead:
    """Add a channel, sealing its secret before anything is persisted."""
    if (
        db.exec(select(NotificationChannel).where(NotificationChannel.name == body.name)).first()
        is not None
    ):
        raise HTTPException(status.HTTP_409_CONFLICT, "a channel with that name already exists")

    config = _validated_config(body.type, body.config)
    if body.secret is not None:
        config[SECRET_REF_KEY] = _seal(store, body.secret.get_secret_value())

    channel = NotificationChannel(
        name=body.name,
        type=body.type,
        config=config,
        event_filter=body.event_filter.model_dump(mode="json"),
        enabled=body.enabled,
    )
    db.add(channel)
    db.flush()
    audit.record(
        db,
        actor_id=admin.id,
        action=AUDIT_CHANNEL_CREATED,
        target_type=AUDIT_TARGET_CHANNEL,
        target_id=channel.id,
        to_value=channel.name,
        # The destination, not the secret: "where do our findings go" is the
        # question this trail exists to answer.
        detail={"type": channel.type.value, "destination": _destination(channel)},
    )
    if body.secret is not None:
        audit.record(
            db,
            actor_id=admin.id,
            action=AUDIT_CHANNEL_SECRET_SET,
            target_type=AUDIT_TARGET_CHANNEL,
            target_id=channel.id,
        )
    commit_or_conflict(db, "a channel with that name already exists")
    db.refresh(channel)
    logger.info(
        "notification_channel_created",
        channel_id=str(channel.id),
        type=channel.type.value,
        actor_id=str(admin.id),
    )
    return _read(channel)


@router.patch("/channels/{channel_id}", dependencies=[CsrfProtected])
async def update_channel(
    channel_id: uuid.UUID,
    changes: NotificationChannelUpdate,
    admin: AdminUser,
    db: SessionDep,
    store: SecretStoreDep,
) -> NotificationChannelRead:
    """Edit a channel, and rotate its secret if a new one is supplied.

    The channel's ``type`` is not editable: a config validated as an email list is
    not a webhook config, and changing the type in place would leave the row
    describing something it is not. Create the replacement instead.
    """
    channel = _load(db, channel_id)
    changed: list[str] = []

    if changes.name is not None and changes.name != channel.name:
        clash = db.exec(
            select(NotificationChannel).where(NotificationChannel.name == changes.name)
        ).first()
        if clash is not None and clash.id != channel.id:
            raise HTTPException(status.HTTP_409_CONFLICT, "a channel with that name already exists")
        channel.name = changes.name
        changed.append("name")

    if changes.config is not None:
        # The sealed ref survives a config edit: it is ours, not the caller's, and
        # an admin fixing a typo in a URL has not asked to drop the signing key.
        existing_ref = channel.config.get(SECRET_REF_KEY)
        config = _validated_config(channel.type, changes.config)
        if existing_ref is not None:
            config[SECRET_REF_KEY] = existing_ref
        channel.config = config
        changed.append("config")

    if changes.event_filter is not None:
        channel.event_filter = changes.event_filter.model_dump(mode="json")
        changed.append("event_filter")

    if changes.enabled is not None and changes.enabled != channel.enabled:
        channel.enabled = changes.enabled
        changed.append("enabled")

    if changed:
        audit.record(
            db,
            actor_id=admin.id,
            action=AUDIT_CHANNEL_UPDATED,
            target_type=AUDIT_TARGET_CHANNEL,
            target_id=channel.id,
            to_value=",".join(changed),
            detail={"destination": _destination(channel)},
        )

    if changes.secret is not None:
        # Rotation is its own event: "who changed this channel" and "who last
        # replaced its signing key" are different questions.
        channel.config = channel.config | {
            SECRET_REF_KEY: _seal(store, changes.secret.get_secret_value())
        }
        audit.record(
            db,
            actor_id=admin.id,
            action=AUDIT_CHANNEL_SECRET_SET,
            target_type=AUDIT_TARGET_CHANNEL,
            target_id=channel.id,
        )

    db.add(channel)
    commit_or_conflict(db, "a channel with that name already exists")
    db.refresh(channel)
    return _read(channel)


@router.delete(
    "/channels/{channel_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[CsrfProtected],
)
async def delete_channel(
    channel_id: uuid.UUID,
    admin: AdminUser,
    db: SessionDep,
) -> Response:
    """Remove a channel. Nothing is announced through it again."""
    channel = _load(db, channel_id)
    audit.record(
        db,
        actor_id=admin.id,
        action=AUDIT_CHANNEL_DELETED,
        target_type=AUDIT_TARGET_CHANNEL,
        target_id=channel.id,
        from_value=channel.name,
        detail={"type": channel.type.value, "destination": _destination(channel)},
    )
    db.delete(channel)
    db.commit()
    logger.info("notification_channel_deleted", channel_id=str(channel_id), actor_id=str(admin.id))
    return Response(status_code=status.HTTP_204_NO_CONTENT)


def _destination(channel: NotificationChannel) -> str:
    """Where this channel sends, for the audit trail. Never the secret.

    Truncated to the audit column's width so a 2048-character URL cannot make the
    insert fail — losing the audit row would be a worse outcome than a clipped one.
    """
    if channel.type is NotificationChannelType.WEBHOOK:
        return str(channel.config.get("url", ""))[:255]
    recipients = channel.config.get("recipients", [])
    count = len(recipients) if isinstance(recipients, list) else 0
    return f"{count} recipient(s)"
