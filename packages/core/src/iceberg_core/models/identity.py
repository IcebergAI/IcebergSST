"""Identity: the OIDC-backed user (ADR 0005)."""

from datetime import datetime

from sqlmodel import Field

from iceberg_core.enums import UserRole
from iceberg_core.models.base import TimestampedModel, enum_type, utc_timestamp_type


class User(TimestampedModel, table=True):
    """A person, keyed on their OIDC subject.

    Passwords are absent by design: authentication is the identity provider's job
    (ADR 0005). Users are provisioned on first login, and ``disabled`` is checked
    at session validation so revoking access does not wait for token expiry.
    """

    # "user" is a reserved word in Postgres; naming the table around it beats
    # quoting it in every hand-written query forever.
    __tablename__ = "app_user"

    oidc_subject: str = Field(max_length=255, unique=True, index=True)
    email: str = Field(max_length=320, index=True)
    display_name: str = Field(max_length=255)
    role: UserRole = Field(
        default=UserRole.VIEWER,
        sa_type=enum_type(UserRole, name="user_role"),
    )
    last_login_at: datetime | None = Field(default=None, sa_type=utc_timestamp_type())
    disabled: bool = Field(default=False)
