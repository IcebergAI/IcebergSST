"""Managing who owns findings: groups, routing rules, response targets (#146).

**Reads are viewer+, writes are admin.** The split is the same one sources and
channels make. Seeing which team owns what is how anybody answers "is this mine?",
while changing the rules moves work between teams and rewrites what "overdue"
means — an administrative act, and audited as one.

Nothing here touches an existing finding. Changing a rule changes what happens to
findings *from now on*: ownership already established is never re-decided
(`iceberg_api.findings.ownership`), so an edit here cannot silently reassign a
queue somebody is working. That is a deliberate limit, not an oversight — the way
to move work that already exists is to move it, by hand, with a name attached.
"""

import uuid
from datetime import UTC, datetime
from typing import Annotated

import structlog
from fastapi import APIRouter, HTTPException, Query, Response, status
from iceberg_core.enums import Severity
from iceberg_core.models import (
    AUDIT_OWNER_GROUP_CREATED,
    AUDIT_OWNER_GROUP_DELETED,
    AUDIT_OWNER_GROUP_UPDATED,
    AUDIT_RESPONSE_TARGET_UPDATED,
    AUDIT_ROUTING_RULE_CREATED,
    AUDIT_ROUTING_RULE_DELETED,
    AUDIT_ROUTING_RULE_UPDATED,
    AUDIT_TARGET_OWNER_GROUP,
    AUDIT_TARGET_RESPONSE_TARGET,
    AUDIT_TARGET_ROUTING_RULE,
    Finding,
    NotificationChannel,
    OwnerGroup,
    ResponseTarget,
    RoutingRule,
    Source,
    routing_matchers,
)
from sqlalchemy import func
from sqlmodel import col, select

from iceberg_api import audit
from iceberg_api.auth.dependencies import CsrfProtected, SessionDep
from iceberg_api.auth.rbac import AdminUser, ViewerUser
from iceberg_api.findings import ownership
from iceberg_api.ownership.schemas import (
    OwnerGroupCreate,
    OwnerGroupRead,
    OwnerGroupUpdate,
    ResponseTargetRead,
    ResponseTargetUpdate,
    RoutingRuleCreate,
    RoutingRuleRead,
    RoutingRuleUpdate,
)

router = APIRouter(tags=["ownership"])
logger = structlog.get_logger()


# ─── Owner groups ─────────────────────────────────────────────────────────────


def _load_group(db: SessionDep, group_id: uuid.UUID) -> OwnerGroup:
    group = db.get(OwnerGroup, group_id)
    if group is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "owner group not found")
    return group


def _name_is_free(db: SessionDep, name: str, *, exclude: uuid.UUID | None = None) -> None:
    clash = db.exec(select(OwnerGroup).where(col(OwnerGroup.name) == name)).first()
    if clash is not None and clash.id != exclude:
        raise HTTPException(status.HTTP_409_CONFLICT, "a group with that name already exists")


def _check_channel(db: SessionDep, channel_id: uuid.UUID | None) -> None:
    if channel_id is not None and db.get(NotificationChannel, channel_id) is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "notification channel not found")


@router.get("/owner-groups")
async def list_owner_groups(
    user: ViewerUser,
    db: SessionDep,
    include_disabled: Annotated[bool, Query()] = False,
) -> list[OwnerGroupRead]:
    """Every group, by name, with what it currently owes.

    Not paginated: a deployment has teams, not thousands of them, and an operator
    reading "who owns what" should see all of them rather than discover a second
    page exists — the same call the channel list makes.

    Disabled groups are hidden by default and never silently: they still own
    findings, so ``?include_disabled=true`` is how you find work stranded on a
    disbanded team.
    """
    statement = select(OwnerGroup).order_by(col(OwnerGroup.name))
    if not include_disabled:
        statement = statement.where(col(OwnerGroup.disabled).is_(False))
    groups = list(db.exec(statement))
    # One grouped query for every group's counts rather than two per group.
    counts = ownership.owned_counts(db, at=datetime.now(UTC))
    return [
        OwnerGroupRead(
            **OwnerGroupRead.model_validate(group).model_dump(
                exclude={"open_findings", "overdue_findings"}
            ),
            open_findings=counts.open_for(group.id),
            overdue_findings=counts.overdue_for(group.id),
        )
        for group in groups
    ]


@router.post("/owner-groups", status_code=status.HTTP_201_CREATED, dependencies=[CsrfProtected])
async def create_owner_group(
    body: OwnerGroupCreate, admin: AdminUser, db: SessionDep
) -> OwnerGroupRead:
    _name_is_free(db, body.name)
    _check_channel(db, body.notification_channel_id)

    group = OwnerGroup(
        name=body.name,
        description=body.description,
        notification_channel_id=body.notification_channel_id,
    )
    db.add(group)
    db.flush()
    audit.record(
        db,
        actor_id=admin.id,
        action=AUDIT_OWNER_GROUP_CREATED,
        target_type=AUDIT_TARGET_OWNER_GROUP,
        target_id=group.id,
        to_value=group.name,
    )
    db.commit()
    db.refresh(group)
    return OwnerGroupRead.model_validate(group)


@router.patch("/owner-groups/{group_id}", dependencies=[CsrfProtected])
async def update_owner_group(
    group_id: uuid.UUID, changes: OwnerGroupUpdate, admin: AdminUser, db: SessionDep
) -> OwnerGroupRead:
    group = _load_group(db, group_id)
    supplied = changes.model_fields_set
    changed: list[str] = []

    if changes.name is not None and changes.name != group.name:
        _name_is_free(db, changes.name, exclude=group.id)
        group.name = changes.name
        changed.append("name")
    if "description" in supplied and changes.description != group.description:
        group.description = changes.description
        changed.append("description")
    if (
        "notification_channel_id" in supplied
        and changes.notification_channel_id != group.notification_channel_id
    ):
        _check_channel(db, changes.notification_channel_id)
        group.notification_channel_id = changes.notification_channel_id
        changed.append("notification_channel_id")
    if changes.disabled is not None and changes.disabled != group.disabled:
        group.disabled = changes.disabled
        changed.append("disabled")

    if not changed:
        # Nothing to record. An audit log full of "renamed to the same name" is
        # one nobody reads (`iceberg_api.audit`).
        return OwnerGroupRead.model_validate(group)

    db.add(group)
    audit.record(
        db,
        actor_id=admin.id,
        action=AUDIT_OWNER_GROUP_UPDATED,
        target_type=AUDIT_TARGET_OWNER_GROUP,
        target_id=group.id,
        to_value=group.name,
        detail={"changed": ",".join(changed)},
    )
    db.commit()
    db.refresh(group)
    return OwnerGroupRead.model_validate(group)


@router.delete(
    "/owner-groups/{group_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[CsrfProtected],
)
async def delete_owner_group(group_id: uuid.UUID, admin: AdminUser, db: SessionDep) -> Response:
    """Delete a group that owns nothing. Otherwise, disable it instead.

    Findings reference the group with ``ON DELETE SET NULL``, so a delete would
    succeed and quietly drop a whole team's findings into the unowned queue with
    no record of where they came from — the audit row would say the group was
    deleted, and nothing would say which findings lost their owner. Disabling
    keeps the history and stops routing choosing it, which is what "we disbanded
    that team" actually means.
    """
    group = _load_group(db, group_id)
    owned = db.exec(
        select(func.count(col(Finding.id))).where(col(Finding.owner_group_id) == group.id)
    ).one()
    if int(owned):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"{int(owned)} findings are owned by this group; disable it instead",
        )

    name = group.name
    db.delete(group)
    audit.record(
        db,
        actor_id=admin.id,
        action=AUDIT_OWNER_GROUP_DELETED,
        target_type=AUDIT_TARGET_OWNER_GROUP,
        target_id=group_id,
        from_value=name,
    )
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ─── Routing rules ────────────────────────────────────────────────────────────


def _load_rule(db: SessionDep, rule_id: uuid.UUID) -> RoutingRule:
    rule = db.get(RoutingRule, rule_id)
    if rule is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "routing rule not found")
    return rule


def _check_targets(db: SessionDep, group_id: uuid.UUID | None, source_id: uuid.UUID | None) -> None:
    if group_id is not None and db.get(OwnerGroup, group_id) is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "owner group not found")
    if source_id is not None and db.get(Source, source_id) is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "source not found")


@router.get("/routing-rules")
async def list_routing_rules(user: ViewerUser, db: SessionDep) -> list[RoutingRuleRead]:
    """The rule set **in evaluation order**, disabled rules included.

    Order is the whole meaning of a rule set, so this returns the order routing
    actually uses — `(priority, created_at, id)` — rather than a friendlier one a
    console would then have to re-derive and could get wrong. Disabled rules are
    listed because their position is what an operator is reasoning about when
    they turn one back on.
    """
    rules = db.exec(
        select(RoutingRule).order_by(
            col(RoutingRule.priority), col(RoutingRule.created_at), col(RoutingRule.id)
        )
    )
    return [RoutingRuleRead.model_validate(rule) for rule in rules]


@router.post("/routing-rules", status_code=status.HTTP_201_CREATED, dependencies=[CsrfProtected])
async def create_routing_rule(
    body: RoutingRuleCreate, admin: AdminUser, db: SessionDep
) -> RoutingRuleRead:
    if db.exec(select(RoutingRule).where(col(RoutingRule.name) == body.name)).first() is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "a rule with that name already exists")
    _check_targets(db, body.owner_group_id, body.source_id)

    rule = RoutingRule(
        name=body.name,
        owner_group_id=body.owner_group_id,
        priority=body.priority,
        source_id=body.source_id,
        rule_id=body.rule_id,
        min_severity=body.min_severity,
        source_tags=body.source_tags,
        enabled=body.enabled,
    )
    db.add(rule)
    db.flush()
    audit.record(
        db,
        actor_id=admin.id,
        action=AUDIT_ROUTING_RULE_CREATED,
        target_type=AUDIT_TARGET_ROUTING_RULE,
        target_id=rule.id,
        to_value=rule.name,
        # The matchers, because "why did this go to that team" is answered by
        # what the rule matched on, not by its name.
        detail={"priority": str(rule.priority), "matchers": _matchers(rule)},
    )
    db.commit()
    db.refresh(rule)
    return RoutingRuleRead.model_validate(rule)


@router.patch("/routing-rules/{rule_id}", dependencies=[CsrfProtected])
async def update_routing_rule(
    rule_id: uuid.UUID, changes: RoutingRuleUpdate, admin: AdminUser, db: SessionDep
) -> RoutingRuleRead:
    """Edit a rule. A matcher sent as ``null`` is dropped; an omitted one stays."""
    rule = _load_rule(db, rule_id)
    supplied = changes.model_fields_set
    changed: list[str] = []

    if changes.name is not None and changes.name != rule.name:
        clash = db.exec(select(RoutingRule).where(col(RoutingRule.name) == changes.name)).first()
        if clash is not None and clash.id != rule.id:
            raise HTTPException(status.HTTP_409_CONFLICT, "a rule with that name already exists")
        rule.name = changes.name
        changed.append("name")
    if changes.owner_group_id is not None and changes.owner_group_id != rule.owner_group_id:
        _check_targets(db, changes.owner_group_id, None)
        rule.owner_group_id = changes.owner_group_id
        changed.append("owner_group_id")
    if changes.priority is not None and changes.priority != rule.priority:
        rule.priority = changes.priority
        changed.append("priority")
    if "source_id" in supplied and changes.source_id != rule.source_id:
        _check_targets(db, None, changes.source_id)
        rule.source_id = changes.source_id
        changed.append("source_id")
    if "rule_id" in supplied and changes.rule_id != rule.rule_id:
        rule.rule_id = changes.rule_id
        changed.append("rule_id")
    if "min_severity" in supplied and changes.min_severity != rule.min_severity:
        rule.min_severity = changes.min_severity
        changed.append("min_severity")
    if changes.source_tags is not None and changes.source_tags != rule.source_tags:
        rule.source_tags = changes.source_tags
        changed.append("source_tags")
    if changes.enabled is not None and changes.enabled != rule.enabled:
        rule.enabled = changes.enabled
        changed.append("enabled")

    if not changed:
        return RoutingRuleRead.model_validate(rule)

    db.add(rule)
    audit.record(
        db,
        actor_id=admin.id,
        action=AUDIT_ROUTING_RULE_UPDATED,
        target_type=AUDIT_TARGET_ROUTING_RULE,
        target_id=rule.id,
        to_value=rule.name,
        detail={"changed": ",".join(changed), "matchers": _matchers(rule)},
    )
    db.commit()
    db.refresh(rule)
    return RoutingRuleRead.model_validate(rule)


@router.delete(
    "/routing-rules/{rule_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[CsrfProtected],
)
async def delete_routing_rule(rule_id: uuid.UUID, admin: AdminUser, db: SessionDep) -> Response:
    """Delete a rule. Findings it already routed keep their owner.

    Safe to delete, unlike a group: a rule is consulted, never referenced. What it
    decided lives on the finding and in that finding's event trail, which names
    the rule — so the history survives the rule that made it.
    """
    rule = _load_rule(db, rule_id)
    name = rule.name
    db.delete(rule)
    audit.record(
        db,
        actor_id=admin.id,
        action=AUDIT_ROUTING_RULE_DELETED,
        target_type=AUDIT_TARGET_ROUTING_RULE,
        target_id=rule_id,
        from_value=name,
    )
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


def _matchers(rule: RoutingRule) -> str:
    """The rule's matchers as one audit-safe string. Never a secret; all of these
    are identifiers an operator typed."""
    parts = routing_matchers(rule)
    return " ".join(
        f"{key}={value}"
        for key, value in parts.items()
        if value not in (None, [], "")  # a matcher that is not set is not a matcher
    )


# ─── Response targets ─────────────────────────────────────────────────────────


@router.get("/response-targets")
async def list_response_targets(user: ViewerUser, db: SessionDep) -> list[ResponseTargetRead]:
    """The four targets, worst first — the order an operator reads them in."""
    from iceberg_core.enums import SEVERITY_RANK

    rows = list(db.exec(select(ResponseTarget)))
    rows.sort(key=lambda row: SEVERITY_RANK[row.severity], reverse=True)
    return [ResponseTargetRead.model_validate(row) for row in rows]


@router.put("/response-targets/{severity}", dependencies=[CsrfProtected])
async def set_response_target(
    severity: Severity, body: ResponseTargetUpdate, admin: AdminUser, db: SessionDep
) -> ResponseTargetRead:
    """Change how long one severity may sit.

    Edited, never created or deleted: there is one row per severity, seeded by
    migration 0014, and a severity with no target would mean findings of that
    severity silently stop getting due dates.

    The new value applies to findings that open **from now on**. Due dates already
    set are not recomputed — see `iceberg_api.findings.ownership.start_clock`;
    tightening a target must not reach backwards and declare closed work to have
    been late.
    """
    row = db.exec(select(ResponseTarget).where(col(ResponseTarget.severity) == severity)).first()
    if row is None:
        # Only reachable on a database that lost the seeded row. Recreating it
        # here is better than 404-ing an operator out of a setting they can see.
        row = ResponseTarget(severity=severity, hours=body.hours)
        db.add(row)
        db.flush()
        previous: int | None = None
    else:
        previous = row.hours
        if previous == body.hours:
            return ResponseTargetRead.model_validate(row)
        row.hours = body.hours
        db.add(row)

    audit.record(
        db,
        actor_id=admin.id,
        action=AUDIT_RESPONSE_TARGET_UPDATED,
        target_type=AUDIT_TARGET_RESPONSE_TARGET,
        target_id=row.id,
        from_value=str(previous) if previous is not None else None,
        to_value=str(row.hours),
        detail={"severity": severity.value},
    )
    db.commit()
    db.refresh(row)
    logger.info(
        "response_target_updated",
        severity=severity.value,
        hours=row.hours,
        actor_id=str(admin.id),
    )
    return ResponseTargetRead.model_validate(row)
