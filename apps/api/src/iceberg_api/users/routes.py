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
from iceberg_core.enums import UserRole
from iceberg_core.models import (
    AUDIT_TARGET_USER,
    AUDIT_USER_DISABLED,
    AUDIT_USER_ENABLED,
    AUDIT_USER_ROLE_CHANGED,
    AuditEvent,
    User,
)
from sqlmodel import Session, col, select

from iceberg_api import audit
from iceberg_api.auth.dependencies import CsrfProtected, SessionDep
from iceberg_api.auth.rbac import AdminUser
from iceberg_api.pagination import (
    DEFAULT_LIMIT,
    MAX_LIMIT,
    after,
    build_page,
    position,
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
    statement = after(
        select(User),
        created_at=User.created_at,  # type: ignore[arg-type]  # instrumented attribute
        row_id=User.id,  # type: ignore[arg-type]
        cursor=position(cursor),
    )
    # One extra row answers "is there another page?" without a second count query.
    rows = list(db.exec(statement.limit(limit + 1)))
    return build_page(rows, limit=limit, read=UserRead.model_validate)


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

    _guard_last_admin(db, user, changes)

    if changes.role is not None and changes.role is not user.role:
        audit.record(
            db,
            actor_id=admin.id,
            action=AUDIT_USER_ROLE_CHANGED,
            target_type=AUDIT_TARGET_USER,
            target_id=user.id,
            from_value=user.role.value,
            to_value=changes.role.value,
        )
        user.role = changes.role

    if changes.disabled is not None and changes.disabled != user.disabled:
        audit.record(
            db,
            actor_id=admin.id,
            action=AUDIT_USER_DISABLED if changes.disabled else AUDIT_USER_ENABLED,
            target_type=AUDIT_TARGET_USER,
            target_id=user.id,
            from_value=str(user.disabled).lower(),
            to_value=str(changes.disabled).lower(),
        )
        user.disabled = changes.disabled

    db.add(user)
    db.commit()
    db.refresh(user)
    return UserRead.model_validate(user)


def _guard_last_admin(db: Session, user: User, changes: UserUpdate) -> None:
    """Refuse a change that would leave the instance with no enabled admin.

    Blocking self-modification is not enough on its own: two admins can disable or
    demote *each other* at the same time, each passing the self-check, and end with
    zero admins and no in-app way back (the seed only applies at user creation). The
    whole admin set is locked FOR UPDATE so the two requests serialise on a common
    row — the second then sees the first's commit and is refused.
    """
    demoting = changes.role is not None and changes.role is not UserRole.ADMIN
    disabling = changes.disabled is True
    if user.role is not UserRole.ADMIN or not (demoting or disabling):
        return

    admins = db.exec(select(User).where(col(User.role) == UserRole.ADMIN).with_for_update()).all()
    others_enabled = [other for other in admins if other.id != user.id and not other.disabled]
    if not others_enabled:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "this is the last enabled administrator; promote another before removing this one",
        )


def audit_events_for(db: Session, target_id: uuid.UUID) -> list[AuditEvent]:
    """Every recorded action against one user, oldest first. Used by tests and #64."""
    return audit.events_for(db, AUDIT_TARGET_USER, target_id)
