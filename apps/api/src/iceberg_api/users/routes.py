"""Admin user and role management (#69).

Roles are assigned inside IcebergSST rather than mapped from IdP claims
(ADR 0005), which means there has to be somewhere to assign them. Admin-only, and
every change is audited: "who made this person an admin" must always have an
answer.

Nobody may modify their own account here. It closes the obvious privilege
escalation (an analyst promoting themselves is already blocked by the role check,
but an admin cannot quietly rewrite their own record either), it removes any path
to locking the last admin out of their own instance, and a legitimate change to
your own role is something another admin can do for you.
"""

import uuid

import structlog
from fastapi import APIRouter, HTTPException, Query, status
from iceberg_core.models import (
    AUDIT_TARGET_USER,
    AUDIT_USER_DISABLED,
    AUDIT_USER_ENABLED,
    AUDIT_USER_ROLE_CHANGED,
    AuditEvent,
    User,
)
from sqlmodel import Session, select

from iceberg_api.auth.dependencies import CsrfProtected, SessionDep
from iceberg_api.auth.rbac import AdminUser
from iceberg_api.pagination import (
    DEFAULT_LIMIT,
    MAX_LIMIT,
    Cursor,
    CursorError,
    after,
    resolve_cursor,
)
from iceberg_api.schemas import Page, UserRead, UserUpdate

router = APIRouter(prefix="/users", tags=["users"])
logger = structlog.get_logger()


@router.get("")
async def list_users(
    admin: AdminUser,
    db: SessionDep,
    limit: int = Query(default=DEFAULT_LIMIT, ge=1, le=MAX_LIMIT),
    cursor: str | None = Query(default=None),
) -> Page[UserRead]:
    """List users, oldest first, in stable `(created_at, id)` order."""
    try:
        position = resolve_cursor(cursor)
    except CursorError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "cursor is not valid") from exc

    statement = after(
        select(User),
        created_at=User.created_at,  # type: ignore[arg-type]  # instrumented attribute
        row_id=User.id,  # type: ignore[arg-type]
        cursor=position,
    )
    # One extra row answers "is there another page?" without a second count query.
    rows = list(db.exec(statement.limit(limit + 1)))
    page, has_more = rows[:limit], len(rows) > limit

    return Page(
        items=[UserRead.model_validate(user) for user in page],
        next_cursor=(
            Cursor(created_at=page[-1].created_at, row_id=page[-1].id).encode()
            if has_more and page
            else None
        ),
    )


@router.patch("/{user_id}", dependencies=[CsrfProtected])
async def update_user(
    user_id: uuid.UUID,
    changes: UserUpdate,
    admin: AdminUser,
    db: SessionDep,
) -> UserRead:
    """Change a user's role or disable them. Admin only, always audited."""
    if user_id == admin.id:
        # See the module docstring: no self-service role changes, in either
        # direction, for anyone.
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "you cannot change your own role or disable your own account",
        )

    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")

    events: list[AuditEvent] = []

    if changes.role is not None and changes.role is not user.role:
        events.append(
            _audit(
                admin.id,
                AUDIT_USER_ROLE_CHANGED,
                user.id,
                from_value=user.role.value,
                to_value=changes.role.value,
            )
        )
        user.role = changes.role

    if changes.disabled is not None and changes.disabled != user.disabled:
        events.append(
            _audit(
                admin.id,
                AUDIT_USER_DISABLED if changes.disabled else AUDIT_USER_ENABLED,
                user.id,
                from_value=str(user.disabled).lower(),
                to_value=str(changes.disabled).lower(),
            )
        )
        user.disabled = changes.disabled

    for event in events:
        db.add(event)
        logger.info(
            "user_administered",
            action=event.action,
            actor_id=str(admin.id),
            target_user_id=str(user.id),
            from_value=event.from_value,
            to_value=event.to_value,
        )
    db.add(user)
    db.commit()
    db.refresh(user)
    return UserRead.model_validate(user)


def _audit(
    actor_id: uuid.UUID,
    action: str,
    target_id: uuid.UUID,
    *,
    from_value: str,
    to_value: str,
) -> AuditEvent:
    return AuditEvent(
        actor_id=actor_id,
        action=action,
        target_type=AUDIT_TARGET_USER,
        target_id=target_id,
        from_value=from_value,
        to_value=to_value,
    )


def audit_events_for(db: Session, target_id: uuid.UUID) -> list[AuditEvent]:
    """Every recorded action against one user, oldest first. Used by tests and #64."""
    statement = (
        select(AuditEvent)
        .where(AuditEvent.target_type == AUDIT_TARGET_USER)
        .where(AuditEvent.target_id == target_id)
        .order_by(AuditEvent.created_at)  # type: ignore[arg-type]
    )
    return list(db.exec(statement))
