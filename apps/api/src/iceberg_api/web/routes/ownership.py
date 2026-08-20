"""The ownership screen: groups, routing rules, and response targets (#146).

One screen rather than three. The three things only mean something together — a
group with no rule owns nothing, a rule with no target produces no deadline — and
an operator setting this up for the first time is answering one question ("who
looks after what, and how fast?") rather than visiting three pages.

Admin-only, like every other policy screen, and a client of the ownership API the
same way (docs/web.md): each route resolves ``WebAdmin`` itself, because calling a
handler as a function does not run its own ``Depends``.
"""

import uuid
from typing import Annotated

from fastapi import APIRouter, Form, HTTPException, Query, Request, Response
from iceberg_core.enums import Severity
from pydantic import ValidationError

from iceberg_api.auth.dependencies import CsrfProtected, SessionDep, SettingsDep
from iceberg_api.auth.session import read_flash
from iceberg_api.ownership import routes as api
from iceberg_api.ownership.schemas import (
    OwnerGroupCreate,
    OwnerGroupUpdate,
    ResponseTargetUpdate,
    RoutingRuleCreate,
    RoutingRuleUpdate,
)
from iceberg_api.pagination import DEFAULT_LIMIT
from iceberg_api.sources.routes import list_sources
from iceberg_api.web.dependencies import CurrentViewer, WebAdmin
from iceberg_api.web.forms import optional, redirect_with_error, string_list
from iceberg_api.web.templating import hx_redirect, id_or_none, render_page

router = APIRouter(include_in_schema=False)


@router.get("/ownership")
async def ownership_page(
    request: Request,
    viewer: CurrentViewer,
    admin: WebAdmin,
    db: SessionDep,
    settings: SettingsDep,
    error: Annotated[str | None, Query()] = None,
) -> Response:
    """Who owns what, what routes it there, and how long they have.

    Disabled groups are included: they still own findings, and this is the screen
    where an operator goes looking for work stranded on a team that no longer
    exists.
    """
    groups = await api.list_owner_groups(user=admin, db=db, include_disabled=True)
    rules = await api.list_routing_rules(user=admin, db=db)
    targets = await api.list_response_targets(user=admin, db=db)
    sources = await list_sources(user=admin, db=db, limit=DEFAULT_LIMIT, cursor=None)

    return render_page(
        request,
        "admin/ownership.html",
        viewer,
        {
            "groups": groups,
            "rules": rules,
            "targets": targets,
            "sources": sources.items,
            "group_names": {group.id: group.name for group in groups},
            "source_names": {source.id: source.name for source in sources.items},
            "severities": list(Severity),
            "error": read_flash(error, settings),
        },
    )


# ─── Groups ───────────────────────────────────────────────────────────────────


@router.post("/ownership/groups", dependencies=[CsrfProtected])
async def create_group(
    admin: WebAdmin,
    db: SessionDep,
    settings: SettingsDep,
    name: Annotated[str, Form()],
    description: Annotated[str, Form()] = "",
    csrf_token: Annotated[str, Form()] = "",
) -> Response:
    try:
        await api.create_owner_group(
            body=OwnerGroupCreate(name=name.strip(), description=optional(description)),
            admin=admin,
            db=db,
        )
    except (HTTPException, ValidationError, ValueError) as exc:
        return redirect_with_error("/ownership", exc, settings)
    return hx_redirect("/ownership")


@router.post("/ownership/groups/{group_id}/state", dependencies=[CsrfProtected])
async def set_group_state(
    group_id: uuid.UUID,
    admin: WebAdmin,
    db: SessionDep,
    settings: SettingsDep,
    disabled: Annotated[str, Form()] = "",
    csrf_token: Annotated[str, Form()] = "",
) -> Response:
    """Disband a team, or bring one back.

    A separate action from delete, and the one the screen leads with: a group that
    owns findings cannot be deleted at all, so this is what "we do not use that
    team any more" actually does — routing stops choosing it, and every finding it
    owns keeps saying so.
    """
    try:
        await api.update_owner_group(
            group_id=group_id,
            changes=OwnerGroupUpdate(disabled=disabled == "true"),
            admin=admin,
            db=db,
        )
    except (HTTPException, ValidationError, ValueError) as exc:
        return redirect_with_error("/ownership", exc, settings)
    return hx_redirect("/ownership")


@router.delete("/ownership/groups/{group_id}", dependencies=[CsrfProtected])
async def delete_group(
    group_id: uuid.UUID, admin: WebAdmin, db: SessionDep, settings: SettingsDep
) -> Response:
    """Delete a group. A 409 (it still owns findings) is shown, not swallowed."""
    try:
        await api.delete_owner_group(group_id=group_id, admin=admin, db=db)
    except (HTTPException, ValidationError, ValueError) as exc:
        return redirect_with_error("/ownership", exc, settings)
    return hx_redirect("/ownership")


# ─── Rules ────────────────────────────────────────────────────────────────────


@router.post("/ownership/rules", dependencies=[CsrfProtected])
async def create_rule(  # one parameter per form field
    admin: WebAdmin,
    db: SessionDep,
    settings: SettingsDep,
    name: Annotated[str, Form()],
    owner_group_id: Annotated[str, Form()],
    priority: Annotated[str, Form()] = "100",
    source_id: Annotated[str, Form()] = "",
    rule_id: Annotated[str, Form()] = "",
    min_severity: Annotated[str, Form()] = "",
    source_tags: Annotated[str, Form()] = "",
    csrf_token: Annotated[str, Form()] = "",
) -> Response:
    """Add a rule. Every matcher left blank is one the rule does not narrow on,
    so an otherwise empty form creates the catch-all."""
    try:
        await api.create_routing_rule(
            body=RoutingRuleCreate(
                name=name.strip(),
                owner_group_id=uuid.UUID(owner_group_id),
                priority=int(priority or 100),
                source_id=id_or_none(source_id),
                rule_id=optional(rule_id),
                min_severity=Severity(min_severity) if min_severity else None,
                # A comma-separated field rather than a scripted tag editor: the
                # console has no build step, and a rule takes a handful of tags.
                source_tags=string_list(source_tags.split(",")),
            ),
            admin=admin,
            db=db,
        )
    except (HTTPException, ValidationError, ValueError) as exc:
        return redirect_with_error("/ownership", exc, settings)
    return hx_redirect("/ownership")


@router.post("/ownership/rules/{rule_id}/state", dependencies=[CsrfProtected])
async def set_rule_state(
    rule_id: uuid.UUID,
    admin: WebAdmin,
    db: SessionDep,
    settings: SettingsDep,
    enabled: Annotated[str, Form()] = "",
    csrf_token: Annotated[str, Form()] = "",
) -> Response:
    """Turn a rule off without losing its place in the order."""
    try:
        await api.update_routing_rule(
            rule_id=rule_id,
            changes=RoutingRuleUpdate(enabled=enabled == "true"),
            admin=admin,
            db=db,
        )
    except (HTTPException, ValidationError, ValueError) as exc:
        return redirect_with_error("/ownership", exc, settings)
    return hx_redirect("/ownership")


@router.delete("/ownership/rules/{rule_id}", dependencies=[CsrfProtected])
async def delete_rule(
    rule_id: uuid.UUID, admin: WebAdmin, db: SessionDep, settings: SettingsDep
) -> Response:
    try:
        await api.delete_routing_rule(rule_id=rule_id, admin=admin, db=db)
    except (HTTPException, ValidationError, ValueError) as exc:
        return redirect_with_error("/ownership", exc, settings)
    return hx_redirect("/ownership")


# ─── Response targets ─────────────────────────────────────────────────────────


@router.post("/ownership/targets", dependencies=[CsrfProtected])
async def set_targets(  # one parameter per severity
    admin: WebAdmin,
    db: SessionDep,
    settings: SettingsDep,
    critical: Annotated[str, Form()] = "",
    high: Annotated[str, Form()] = "",
    medium: Annotated[str, Form()] = "",
    low: Annotated[str, Form()] = "",
    csrf_token: Annotated[str, Form()] = "",
) -> Response:
    """Save all four targets at once, because that is how an operator thinks
    about them — critical relative to high, not each in isolation.

    Each is a separate ``PUT``, and the API records nothing for one that did not
    change, so saving the form after editing one number leaves one audit row
    rather than four.
    """
    submitted = {
        Severity.CRITICAL: critical,
        Severity.HIGH: high,
        Severity.MEDIUM: medium,
        Severity.LOW: low,
    }
    try:
        for severity, hours in submitted.items():
            if not hours.strip():
                continue
            await api.set_response_target(
                severity=severity,
                body=ResponseTargetUpdate(hours=int(hours)),
                admin=admin,
                db=db,
            )
    except (HTTPException, ValidationError, ValueError) as exc:
        return redirect_with_error("/ownership", exc, settings)
    return hx_redirect("/ownership")
