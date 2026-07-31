"""The operator screens: engines, rules, notification channels, users (#58, #72).

Everything here except the rules listing is admin-only, because every API route
behind it is. The rail hides the group for other roles, and ``rbac.require_role``
refuses it — the first is a courtesy, the second is the control.

Two of these screens handle credentials, and both follow the same rule the source
form does: a secret is shown once at the moment it is minted and never again.
"""

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Form, HTTPException, Query, Request, Response
from iceberg_core.enums import NotificationChannelType, UserRole
from pydantic import SecretStr, ValidationError

from iceberg_api.auth.dependencies import CsrfProtected, SecretStoreDep, SessionDep, SettingsDep
from iceberg_api.engines.routes import list_engines, register_engine
from iceberg_api.engines.schemas import EngineRegister
from iceberg_api.notifications import routes as channels_api
from iceberg_api.notifications.schemas import (
    EventFilter,
    NotificationChannelCreate,
    NotificationChannelUpdate,
)
from iceberg_api.pagination import DEFAULT_LIMIT
from iceberg_api.rules import list_rules
from iceberg_api.schemas import UserUpdate
from iceberg_api.users.routes import list_users, update_user
from iceberg_api.web.dependencies import CurrentViewer, WebAdmin, WebViewer
from iceberg_api.web.forms import checkbox, error_text, optional, string_list
from iceberg_api.web.templating import hx_redirect, id_or_none, render_page

router = APIRouter(include_in_schema=False)


def _quote(text: str) -> str:
    from urllib.parse import quote

    return quote(text, safe="")


# ─── Engines ─────────────────────────────────────────────────────────────────


@router.get("/engines")
async def engines_page(
    request: Request,
    viewer: CurrentViewer,
    admin: WebAdmin,
    db: SessionDep,
    settings: SettingsDep,
    error: Annotated[str | None, Query()] = None,
) -> Response:
    """Fleet health, and the enrolment form that mints a token."""
    engines = await list_engines(admin=admin, db=db)
    rules = await list_rules(user=admin, db=db, settings=settings)
    return render_page(
        request,
        "admin/engines.html",
        viewer,
        {
            "engines": engines,
            "rules": rules,
            # A minted token is never rendered from a stored value — only from
            # the one response that carried it, in the POST below.
            "credential": None,
            "error": error,
        },
    )


@router.post("/engines/register", dependencies=[CsrfProtected])
async def register_engine_form(
    request: Request,
    viewer: CurrentViewer,
    admin: WebAdmin,
    db: SessionDep,
    settings: SettingsDep,
    name: Annotated[str, Form()],
    csrf_token: Annotated[str, Form()] = "",
) -> Response:
    """Enrol an engine (or rotate an existing one's token) and show it once.

    Rendered rather than redirected precisely because the token cannot be
    fetched again: a redirect would either lose it or have to carry a live
    credential through a URL, which would put it in the browser history and any
    proxy log on the way.
    """
    try:
        credential = await register_engine(
            body=EngineRegister(name=name.strip()), admin=admin, db=db
        )
    except (HTTPException, ValidationError, ValueError) as exc:
        return hx_redirect(f"/engines?error={_quote(error_text(exc))}")

    engines = await list_engines(admin=admin, db=db)
    rules = await list_rules(user=admin, db=db, settings=settings)
    return render_page(
        request,
        "admin/engines.html",
        viewer,
        {"engines": engines, "rules": rules, "credential": credential, "error": None},
    )


# ─── Rules ───────────────────────────────────────────────────────────────────


@router.get("/rules")
async def rules_page(
    request: Request,
    viewer: CurrentViewer,
    user: WebViewer,
    db: SessionDep,
    settings: SettingsDep,
) -> Response:
    """What the live fleet is actually detecting.

    Sourced from what engines report, so mid-deploy disagreement is shown as
    disagreement rather than resolved to whichever version the API happens to
    prefer (docs/api.md § Rules).
    """
    rules = await list_rules(user=user, db=db, settings=settings)
    return render_page(request, "admin/rules.html", viewer, {"rules": rules})


# ─── Notification channels (#72) ─────────────────────────────────────────────


@router.get("/channels")
async def channels_page(
    request: Request,
    viewer: CurrentViewer,
    admin: WebAdmin,
    db: SessionDep,
    error: Annotated[str | None, Query()] = None,
) -> Response:
    """Where findings are announced. Admin-only, and no secret is ever rendered."""
    channels = await channels_api.list_channels(admin=admin, db=db)
    return render_page(
        request,
        "admin/channels.html",
        viewer,
        {
            "channels": channels,
            "types": list(NotificationChannelType),
            "island": {"type": "webhook", "hasSecret": False},
            "error": error,
        },
    )


@router.post("/channels", dependencies=[CsrfProtected])
async def create_channel(  # one parameter per form field
    admin: WebAdmin,
    db: SessionDep,
    store: SecretStoreDep,
    name: Annotated[str, Form()],
    channel_type: Annotated[str, Form(alias="type")],
    url: Annotated[str, Form()] = "",
    recipients: Annotated[list[str], Form()] = [],  # noqa: B006  # FastAPI reads the default
    secret: Annotated[str, Form()] = "",
    min_severity: Annotated[str, Form()] = "",
    enabled: Annotated[str | None, Form()] = None,
    csrf_token: Annotated[str, Form()] = "",
) -> Response:
    """Add a channel. The secret is sealed on the way in and never echoed back."""
    try:
        kind = NotificationChannelType(channel_type)
        body = NotificationChannelCreate(
            name=name.strip(),
            type=kind,
            config=_channel_config(kind, url=url, recipients=recipients),
            event_filter=EventFilter(min_severity=optional(min_severity)),  # type: ignore[arg-type]
            secret=SecretStr(secret) if secret else None,
            enabled=checkbox(enabled),
        )
        await channels_api.create_channel(body=body, admin=admin, db=db, store=store)
    except (HTTPException, ValidationError, ValueError) as exc:
        return hx_redirect(f"/channels?error={_quote(error_text(exc))}")
    return hx_redirect("/channels")


@router.post("/channels/{channel_id}", dependencies=[CsrfProtected])
async def update_channel(  # one parameter per form field
    channel_id: uuid.UUID,
    admin: WebAdmin,
    db: SessionDep,
    store: SecretStoreDep,
    name: Annotated[str, Form()],
    channel_type: Annotated[str, Form(alias="type")],
    url: Annotated[str, Form()] = "",
    recipients: Annotated[list[str], Form()] = [],  # noqa: B006  # see create_channel
    secret: Annotated[str, Form()] = "",
    min_severity: Annotated[str, Form()] = "",
    enabled: Annotated[str | None, Form()] = None,
    csrf_token: Annotated[str, Form()] = "",
) -> Response:
    """Edit a channel. A blank secret field keeps the sealed one in place."""
    try:
        kind = NotificationChannelType(channel_type)
        changes = NotificationChannelUpdate(
            name=name.strip(),
            config=_channel_config(kind, url=url, recipients=recipients),
            event_filter=EventFilter(min_severity=optional(min_severity)),  # type: ignore[arg-type]
            secret=SecretStr(secret) if secret else None,
            enabled=checkbox(enabled),
        )
        await channels_api.update_channel(
            channel_id=channel_id, changes=changes, admin=admin, db=db, store=store
        )
    except (HTTPException, ValidationError, ValueError) as exc:
        return hx_redirect(f"/channels?error={_quote(error_text(exc))}")
    return hx_redirect("/channels")


@router.delete("/channels/{channel_id}", dependencies=[CsrfProtected])
async def delete_channel(
    channel_id: uuid.UUID,
    admin: WebAdmin,
    db: SessionDep,
) -> Response:
    await channels_api.delete_channel(channel_id=channel_id, admin=admin, db=db)
    return hx_redirect("/channels")


def _channel_config(
    kind: NotificationChannelType, *, url: str, recipients: list[str]
) -> dict[str, Any]:
    """The per-type config blob, assembled from the form's flat fields.

    Custom webhook headers are deliberately not on this form: they are stored in
    the clear, the API refuses the header names that carry credentials, and a
    free-text header editor is an invitation to put one there anyway. The
    ``secret`` field is the sealed path.
    """
    if kind is NotificationChannelType.WEBHOOK:
        return {"url": url.strip()}
    return {"recipients": string_list(recipients)}


# ─── Users ───────────────────────────────────────────────────────────────────


@router.get("/users")
async def users_page(
    request: Request,
    viewer: CurrentViewer,
    admin: WebAdmin,
    db: SessionDep,
    error: Annotated[str | None, Query()] = None,
    cursor: Annotated[str | None, Query()] = None,
) -> Response:
    """Who has an account, and what they may do."""
    page = await list_users(admin=admin, db=db, limit=DEFAULT_LIMIT, cursor=cursor)
    return render_page(
        request,
        "admin/users.html",
        viewer,
        {
            "users": page.items,
            "next_cursor": page.next_cursor,
            "roles": list(UserRole),
            "error": error,
        },
    )


@router.post("/users/{user_id}", dependencies=[CsrfProtected])
async def change_user(
    user_id: uuid.UUID,
    admin: WebAdmin,
    db: SessionDep,
    role: Annotated[str, Form()],
    disabled: Annotated[str | None, Form()] = None,
    csrf_token: Annotated[str, Form()] = "",
) -> Response:
    """Assign a role or disable an account. Always audited by the API.

    Nobody may change their own account, and the API refuses to leave the
    instance without an enabled admin — both are checks worth having on the
    server, and both surface here as the message they came back with.
    """
    try:
        changes = UserUpdate(role=UserRole(role), disabled=checkbox(disabled))
        await update_user(user_id=user_id, changes=changes, admin=admin, db=db)
    except (HTTPException, ValidationError, ValueError) as exc:
        return hx_redirect(f"/users?error={_quote(error_text(exc))}")
    return hx_redirect("/users")


__all__ = ["id_or_none", "router"]
