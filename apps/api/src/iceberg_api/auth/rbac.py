"""Role-based access control (#29, ADR 0005).

Authorization is enforced here and only here. A route is protected because it
depends on :data:`AdminUser`, :data:`AnalystUser`, or :data:`ViewerUser` — never
because a template hid a button. The UI reflects permissions; it is not the
enforcement point.

Roles are **ranked**, not compared for equality: an admin can do anything an
analyst can, and an analyst anything a viewer can. Equality checks would mean
every new route enumerating three roles, and eventually forgetting one.
"""

from collections.abc import Callable
from typing import Annotated

import structlog
from fastapi import Depends, HTTPException, status
from iceberg_core.enums import UserRole
from iceberg_core.models import User

from iceberg_api.auth.dependencies import CurrentUser

#: viewer ⊂ analyst ⊂ admin.
ROLE_RANK: dict[UserRole, int] = {
    UserRole.VIEWER: 0,
    UserRole.ANALYST: 1,
    UserRole.ADMIN: 2,
}

logger = structlog.get_logger()


def require_role(minimum: UserRole) -> Callable[[User], User]:
    """Build a dependency that admits ``minimum`` and above."""

    def dependency(user: CurrentUser) -> User:
        if ROLE_RANK[user.role] < ROLE_RANK[minimum]:
            # Logged at info: one denial is ordinary, a burst of them is a signal,
            # and the audit-coverage review in #64 needs them to exist at all.
            logger.info(
                "authorization_denied",
                user_id=str(user.id),
                role=user.role.value,
                required_role=minimum.value,
            )
            raise HTTPException(status.HTTP_403_FORBIDDEN, "insufficient role")
        return user

    return dependency


#: Manage sources, schedules, engines, users, channels.
AdminUser = Annotated[User, Depends(require_role(UserRole.ADMIN))]
#: Run scans, triage findings, manage suppressions.
AnalystUser = Annotated[User, Depends(require_role(UserRole.ANALYST))]
#: Read findings and scans.
ViewerUser = Annotated[User, Depends(require_role(UserRole.VIEWER))]
