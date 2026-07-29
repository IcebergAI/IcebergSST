"""Turn a verified OIDC identity into a `User` row (#30).

Users are created on first login and keyed on the OIDC subject, never on email:
an address can be reassigned to a different person, and identity that changes
hands would silently inherit the old owner's triage history and role.

Roles live in IcebergSST rather than in the token. The identity provider says who
someone is; an IcebergSST admin says what they may do (ADR 0005).
"""

import structlog
from iceberg_core.config import ApiSettings
from iceberg_core.enums import UserRole
from iceberg_core.models import User, utc_now
from sqlmodel import Session, select

from iceberg_api.auth.oidc import IdentityClaims

logger = structlog.get_logger()


class AccountDisabled(Exception):
    """A disabled user authenticated successfully with the provider."""


def provision_user(db: Session, claims: IdentityClaims, settings: ApiSettings) -> User:
    """Create or refresh the user behind ``claims`` and stamp the login."""
    user = db.exec(select(User).where(User.oidc_subject == claims.subject)).first()

    if user is None:
        user = User(
            oidc_subject=claims.subject,
            email=claims.email,
            display_name=claims.display_name,
            role=_initial_role(claims, settings),
        )
        db.add(user)
        logger.info(
            "user_provisioned",
            user_subject=claims.subject,
            role=user.role.value,
            bootstrap_admin=user.role is UserRole.ADMIN,
        )
    elif user.disabled:
        # Authentication succeeded at the provider; authorization stops here.
        logger.info("disabled_user_login_rejected", user_id=str(user.id))
        raise AccountDisabled(claims.subject)
    else:
        # The provider is authoritative for the profile, not for the role.
        user.email = claims.email or user.email
        user.display_name = claims.display_name or user.display_name

    user.last_login_at = utc_now()
    db.flush()
    return user


def _initial_role(claims: IdentityClaims, settings: ApiSettings) -> UserRole:
    """Grant admin to the configured bootstrap identity, viewer to everyone else.

    OIDC-only auth has a chicken-and-egg problem: no local accounts means no
    first administrator. The seed is an env-configured subject (or email), matched
    **only when the user is created** — a bootstrap admin who is later demoted on
    purpose must not be re-promoted by logging in again
    (docs/security.md § Bootstrap).

    Least privilege for everyone else: an account that appears because someone
    can log in to the IdP starts read-only.
    """
    subject = settings.bootstrap_admin_subject
    email = settings.bootstrap_admin_email
    if subject and claims.subject == subject:
        return UserRole.ADMIN
    if email and claims.email and claims.email.casefold() == email.casefold():
        return UserRole.ADMIN
    return UserRole.VIEWER
