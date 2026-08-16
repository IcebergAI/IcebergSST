"""Managing ownership through the API (#146).

The rules read here are the rules ingest runs. That is the property worth
protecting: a console that showed a rule set in a different order from the one
routing evaluates would be a console you could not use to reason about routing.
"""

import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from iceberg_api.findings import ownership
from iceberg_core.enums import FindingState, ScanStatus, ScanTrigger, Severity, UserRole
from iceberg_core.models import (
    AUDIT_TARGET_OWNER_GROUP,
    AUDIT_TARGET_RESPONSE_TARGET,
    AUDIT_TARGET_ROUTING_RULE,
    AuditEvent,
    Finding,
    NotificationChannel,
    OwnerGroup,
    ResponseTarget,
    RoutingRule,
    Scan,
    Source,
    User,
)
from sqlmodel import Session, col, select

NOW = datetime(2026, 8, 16, 9, 0, tzinfo=UTC)


@pytest.fixture(name="admin_headers")
def admin_headers_fixture(
    make_user: Callable[..., User], login_as: Callable[[User], dict[str, str]]
) -> dict[str, str]:
    return login_as(make_user(UserRole.ADMIN))


def _actions(session: Session, target_type: str) -> list[str]:
    return [
        event.action
        for event in session.exec(
            select(AuditEvent).where(col(AuditEvent.target_type) == target_type)
        )
    ]


def _group(client: TestClient, api: str, headers: dict[str, str], name: str, **body: Any) -> Any:
    response = client.post(f"{api}/owner-groups", json={"name": name} | body, headers=headers)
    assert response.status_code == 201, response.text
    return response.json()


def _rule(
    client: TestClient, api: str, headers: dict[str, str], name: str, group_id: str, **body: Any
) -> Any:
    response = client.post(
        f"{api}/routing-rules",
        json={"name": name, "owner_group_id": group_id} | body,
        headers=headers,
    )
    assert response.status_code == 201, response.text
    return response.json()


# ─── Owner groups ─────────────────────────────────────────────────────────────


def test_a_group_is_created_and_audited(
    client: TestClient, api: str, session: Session, admin_headers: dict[str, str]
) -> None:
    created = _group(client, api, admin_headers, "payments", description="runs the payments API")

    assert created["disabled"] is False
    assert created["open_findings"] == 0
    assert _actions(session, AUDIT_TARGET_OWNER_GROUP) == ["owner_group.created"]


def test_two_groups_cannot_share_a_name(
    client: TestClient, api: str, admin_headers: dict[str, str]
) -> None:
    """The name is how a rule and an audit row refer to a team in prose."""
    _group(client, api, admin_headers, "payments")

    clash = client.post(f"{api}/owner-groups", json={"name": "payments"}, headers=admin_headers)

    assert clash.status_code == 409


def test_the_group_list_carries_what_each_team_owes(
    client: TestClient,
    api: str,
    session: Session,
    admin_headers: dict[str, str],
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
) -> None:
    """Counted server-side, in one grouped query: the alternative is a console
    issuing two findings queries per group to render one list."""
    group = _group(client, api, admin_headers, "payments")
    source = make_source()
    late = NOW - timedelta(days=1)
    make_finding(source, owner_group_id=uuid.UUID(group["id"]), due_at=late)
    make_finding(source, owner_group_id=uuid.UUID(group["id"]), due_at=NOW + timedelta(days=365))
    # Resolved: keeps its date, is nobody's work.
    make_finding(
        source,
        owner_group_id=uuid.UUID(group["id"]),
        due_at=late,
        state=FindingState.RESOLVED,
    )

    body = client.get(f"{api}/owner-groups", headers=admin_headers).json()

    assert body[0]["open_findings"] == 2
    assert body[0]["overdue_findings"] == 1


def test_a_disbanded_group_is_hidden_but_findable(
    client: TestClient, api: str, admin_headers: dict[str, str]
) -> None:
    """It still owns findings, so it must not simply vanish from the console —
    `?include_disabled=true` is how you find work stranded on a dead team."""
    group = _group(client, api, admin_headers, "payments")
    client.patch(
        f"{api}/owner-groups/{group['id']}", json={"disabled": True}, headers=admin_headers
    )

    hidden = client.get(f"{api}/owner-groups", headers=admin_headers).json()
    shown = client.get(f"{api}/owner-groups?include_disabled=true", headers=admin_headers).json()

    assert hidden == []
    assert [row["name"] for row in shown] == ["payments"]


def test_a_group_that_owns_findings_cannot_be_deleted(
    client: TestClient,
    api: str,
    admin_headers: dict[str, str],
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
) -> None:
    """The FK is SET NULL, so the delete would *succeed* and quietly drop a whole
    team's findings into the unowned queue with no record of where they came
    from. The audit row would say a group was deleted and nothing would say which
    findings lost their owner."""
    group = _group(client, api, admin_headers, "payments")
    make_finding(make_source(), owner_group_id=uuid.UUID(group["id"]))

    response = client.delete(f"{api}/owner-groups/{group['id']}", headers=admin_headers)

    assert response.status_code == 409
    assert "disable it instead" in response.json()["detail"]


def test_an_empty_group_can_be_deleted_and_the_delete_is_audited(
    client: TestClient, api: str, session: Session, admin_headers: dict[str, str]
) -> None:
    group = _group(client, api, admin_headers, "typo-team")

    response = client.delete(f"{api}/owner-groups/{group['id']}", headers=admin_headers)

    assert response.status_code == 204
    assert session.get(OwnerGroup, uuid.UUID(group["id"])) is None
    assert "owner_group.deleted" in _actions(session, AUDIT_TARGET_OWNER_GROUP)


def test_a_group_cannot_point_at_a_channel_that_does_not_exist(
    client: TestClient, api: str, admin_headers: dict[str, str]
) -> None:
    response = client.post(
        f"{api}/owner-groups",
        json={"name": "payments", "notification_channel_id": str(uuid.uuid4())},
        headers=admin_headers,
    )

    assert response.status_code == 422


def test_a_group_may_carry_an_escalation_channel(
    client: TestClient, api: str, session: Session, admin_headers: dict[str, str]
) -> None:
    from iceberg_core.enums import NotificationChannelType

    channel = NotificationChannel(
        name="payments-oncall",
        type=NotificationChannelType.WEBHOOK,
        config={"url": "https://hooks.example.test/payments"},
    )
    session.add(channel)
    session.commit()

    created = _group(
        client, api, admin_headers, "payments", notification_channel_id=str(channel.id)
    )

    assert created["notification_channel_id"] == str(channel.id)


def test_an_edit_that_changes_nothing_writes_no_audit_row(
    client: TestClient, api: str, session: Session, admin_headers: dict[str, str]
) -> None:
    """An audit log full of "renamed to the same name" is one nobody reads."""
    group = _group(client, api, admin_headers, "payments")

    client.patch(
        f"{api}/owner-groups/{group['id']}", json={"name": "payments"}, headers=admin_headers
    )

    assert _actions(session, AUDIT_TARGET_OWNER_GROUP) == ["owner_group.created"]


# ─── Routing rules ────────────────────────────────────────────────────────────


def test_rules_are_listed_in_the_order_routing_evaluates_them(
    client: TestClient, api: str, admin_headers: dict[str, str]
) -> None:
    """Order *is* the meaning of a rule set. Returning a friendlier one would
    make the console re-derive the real order, and it could get it wrong."""
    group = _group(client, api, admin_headers, "payments")
    _rule(client, api, admin_headers, "catch-all", group["id"], priority=900)
    _rule(client, api, admin_headers, "critical", group["id"], priority=10)
    _rule(client, api, admin_headers, "tie", group["id"], priority=10)

    listed = client.get(f"{api}/routing-rules", headers=admin_headers).json()

    # priority, then creation order for the tie.
    assert [rule["name"] for rule in listed] == ["critical", "tie", "catch-all"]


def test_a_disabled_rule_still_appears_in_the_list(
    client: TestClient, api: str, admin_headers: dict[str, str]
) -> None:
    """Its position is what an operator is reasoning about when they consider
    turning it back on."""
    group = _group(client, api, admin_headers, "payments")
    _rule(client, api, admin_headers, "off", group["id"], enabled=False)

    listed = client.get(f"{api}/routing-rules", headers=admin_headers).json()

    assert [rule["name"] for rule in listed] == ["off"]


def test_a_rule_created_here_is_the_rule_ingest_runs(
    client: TestClient,
    api: str,
    session: Session,
    admin_headers: dict[str, str],
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
) -> None:
    """The whole point of the surface. A rule the console can create but routing
    does not consult is a form, not a feature."""
    group = _group(client, api, admin_headers, "payments")
    _rule(client, api, admin_headers, "critical-only", group["id"], min_severity="critical")
    source = make_source()
    finding = make_finding(source, severity=Severity.CRITICAL)
    scan = Scan(source_id=source.id, trigger=ScanTrigger.MANUAL, status=ScanStatus.COMPLETED)
    session.add(scan)
    session.commit()

    ownership.route(session, finding, ownership.load(session, source.id), scan_id=scan.id)
    session.commit()

    assert str(finding.owner_group_id) == group["id"]


def test_source_tags_match_whatever_case_they_were_typed_in(
    client: TestClient,
    api: str,
    session: Session,
    admin_headers: dict[str, str],
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
) -> None:
    """ "PCI" on the source and "pci" on the rule is a rule that silently routes
    nothing — the hardest misconfiguration to notice, because the symptom is an
    empty queue rather than an error."""
    group = _group(client, api, admin_headers, "payments")
    _rule(client, api, admin_headers, "pci", group["id"], source_tags=["pci"])
    source = make_source()
    source.tags = ["PCI"]
    session.add(source)
    session.commit()
    finding = make_finding(source)
    scan = Scan(source_id=source.id, trigger=ScanTrigger.MANUAL, status=ScanStatus.COMPLETED)
    session.add(scan)
    session.commit()

    ownership.route(session, finding, ownership.load(session, source.id), scan_id=scan.id)

    assert str(finding.owner_group_id) == group["id"]


def test_tags_are_trimmed_and_de_duplicated_but_keep_their_case(
    client: TestClient, api: str, admin_headers: dict[str, str]
) -> None:
    """Folding on the way in would silently rewrite what an operator typed; the
    comparison folds instead."""
    group = _group(client, api, admin_headers, "payments")

    created = _rule(
        client, api, admin_headers, "tags", group["id"], source_tags=[" PCI ", "pci", "eu", ""]
    )

    assert created["source_tags"] == ["PCI", "eu"]


def test_a_rule_cannot_point_at_a_group_or_source_that_does_not_exist(
    client: TestClient, api: str, admin_headers: dict[str, str]
) -> None:
    group = _group(client, api, admin_headers, "payments")

    no_group = client.post(
        f"{api}/routing-rules",
        json={"name": "a", "owner_group_id": str(uuid.uuid4())},
        headers=admin_headers,
    )
    no_source = client.post(
        f"{api}/routing-rules",
        json={"name": "b", "owner_group_id": group["id"], "source_id": str(uuid.uuid4())},
        headers=admin_headers,
    )

    assert no_group.status_code == 422
    assert no_source.status_code == 422


def test_a_rule_cannot_be_pointed_at_a_disbanded_team(
    client: TestClient, api: str, admin_headers: dict[str, str]
) -> None:
    """Routing already skips a disabled group's rules, so accepting the rule would
    let an admin build a rule set that silently routes nothing — the rule appears
    in the list, holds a place in the evaluation order, and never matches."""
    group = _group(client, api, admin_headers, "payments")
    client.patch(
        f"{api}/owner-groups/{group['id']}", json={"disabled": True}, headers=admin_headers
    )

    response = client.post(
        f"{api}/routing-rules",
        json={"name": "doomed", "owner_group_id": group["id"]},
        headers=admin_headers,
    )

    assert response.status_code == 422
    assert "disbanded" in response.text


def test_an_existing_rule_cannot_be_moved_to_a_disbanded_team(
    client: TestClient, api: str, admin_headers: dict[str, str]
) -> None:
    """The same door, through PATCH."""
    live = _group(client, api, admin_headers, "payments")
    gone = _group(client, api, admin_headers, "platform")
    client.patch(f"{api}/owner-groups/{gone['id']}", json={"disabled": True}, headers=admin_headers)
    rule = _rule(client, api, admin_headers, "catch-all", live["id"])

    response = client.patch(
        f"{api}/routing-rules/{rule['id']}",
        json={"owner_group_id": gone["id"]},
        headers=admin_headers,
    )

    assert response.status_code == 422


def test_sending_null_tags_widens_the_rule(
    client: TestClient, api: str, session: Session, admin_headers: dict[str, str]
) -> None:
    """`null` drops the restriction; an omitted field leaves it alone. It is the
    only way to widen a rule through the API, and the symptom of not having it is
    a rule that keeps routing nothing for a reason nobody can remove."""
    group = _group(client, api, admin_headers, "payments")
    rule = _rule(client, api, admin_headers, "tagged", group["id"], source_tags=["pci"])

    widened = client.patch(
        f"{api}/routing-rules/{rule['id']}", json={"source_tags": None}, headers=admin_headers
    ).json()

    assert widened["source_tags"] == []
    stored = session.get(RoutingRule, uuid.UUID(rule["id"]))
    assert stored is not None
    assert stored.source_tags == []


def test_omitting_tags_leaves_them_alone(
    client: TestClient, api: str, admin_headers: dict[str, str]
) -> None:
    """The other half of the distinction — otherwise every unrelated edit would
    silently widen the rule."""
    group = _group(client, api, admin_headers, "payments")
    rule = _rule(client, api, admin_headers, "tagged", group["id"], source_tags=["pci"])

    unchanged = client.patch(
        f"{api}/routing-rules/{rule['id']}", json={"priority": 5}, headers=admin_headers
    ).json()

    assert unchanged["source_tags"] == ["pci"]


def test_a_matcher_sent_as_null_is_dropped_and_an_omitted_one_stays(
    client: TestClient, api: str, session: Session, admin_headers: dict[str, str]
) -> None:
    """Nullable *and* optional are different things — the same distinction finding
    triage makes for `assignee_id`, read the same way."""
    group = _group(client, api, admin_headers, "payments")
    rule = _rule(
        client,
        api,
        admin_headers,
        "narrow",
        group["id"],
        rule_id="aws-access-key",
        min_severity="high",
    )

    updated = client.patch(
        f"{api}/routing-rules/{rule['id']}", json={"rule_id": None}, headers=admin_headers
    ).json()

    assert updated["rule_id"] is None
    assert updated["min_severity"] == "high"


def test_deleting_a_rule_leaves_the_findings_it_routed_alone(
    client: TestClient,
    api: str,
    session: Session,
    admin_headers: dict[str, str],
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
) -> None:
    """Safe to delete, unlike a group: a rule is consulted, never referenced. What
    it decided lives on the finding and in that finding's event trail."""
    group = _group(client, api, admin_headers, "payments")
    rule = _rule(client, api, admin_headers, "catch-all", group["id"])
    source = make_source()
    finding = make_finding(source)
    scan = Scan(source_id=source.id, trigger=ScanTrigger.MANUAL, status=ScanStatus.COMPLETED)
    session.add(scan)
    session.commit()
    ownership.route(session, finding, ownership.load(session, source.id), scan_id=scan.id)
    session.commit()

    response = client.delete(f"{api}/routing-rules/{rule['id']}", headers=admin_headers)

    assert response.status_code == 204
    session.refresh(finding)
    assert str(finding.owner_group_id) == group["id"]
    assert session.get(RoutingRule, uuid.UUID(rule["id"])) is None


def test_the_rule_lifecycle_is_audited(
    client: TestClient, api: str, session: Session, admin_headers: dict[str, str]
) -> None:
    """ "Why did this go to that team" is answered by what the rule matched on."""
    group = _group(client, api, admin_headers, "payments")
    rule = _rule(client, api, admin_headers, "critical", group["id"], min_severity="critical")
    client.patch(f"{api}/routing-rules/{rule['id']}", json={"priority": 5}, headers=admin_headers)
    client.delete(f"{api}/routing-rules/{rule['id']}", headers=admin_headers)

    recorded = _actions(session, AUDIT_TARGET_ROUTING_RULE)
    assert recorded == ["routing_rule.created", "routing_rule.updated", "routing_rule.deleted"]
    created = session.exec(
        select(AuditEvent).where(col(AuditEvent.action) == "routing_rule.created")
    ).one()
    assert "min_severity=critical" in created.detail["matchers"]


# ─── Response targets ─────────────────────────────────────────────────────────


def test_the_seeded_targets_are_served_worst_first(
    client: TestClient, api: str, admin_headers: dict[str, str]
) -> None:
    body = client.get(f"{api}/response-targets", headers=admin_headers).json()

    assert [row["severity"] for row in body] == ["critical", "high", "medium", "low"]
    assert body[0]["hours"] == 24


def test_changing_a_target_applies_to_new_findings_and_leaves_old_dates_alone(
    client: TestClient,
    api: str,
    session: Session,
    admin_headers: dict[str, str],
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
) -> None:
    """Tightening a target must not reach backwards and declare closed work to
    have been late."""
    source = make_source()
    existing = make_finding(source, severity=Severity.HIGH)
    ownership.start_clock(session, existing, ownership.load(session, source.id), at=NOW)
    session.commit()
    before = existing.due_at

    response = client.put(f"{api}/response-targets/high", json={"hours": 1}, headers=admin_headers)

    assert response.status_code == 200
    assert response.json()["hours"] == 1
    session.refresh(existing)
    assert existing.due_at == before
    fresh = make_finding(source, severity=Severity.HIGH)
    ownership.start_clock(session, fresh, ownership.load(session, source.id), at=NOW)
    assert fresh.due_at == NOW + timedelta(hours=1)


def test_a_target_change_is_audited_with_what_it_was(
    client: TestClient, api: str, session: Session, admin_headers: dict[str, str]
) -> None:
    client.put(f"{api}/response-targets/critical", json={"hours": 4}, headers=admin_headers)

    recorded = session.exec(
        select(AuditEvent).where(col(AuditEvent.target_type) == AUDIT_TARGET_RESPONSE_TARGET)
    ).one()
    assert recorded.action == "response_target.updated"
    assert (recorded.from_value, recorded.to_value) == ("24", "4")
    assert recorded.detail["severity"] == "critical"


def test_setting_a_target_to_what_it_already_is_records_nothing(
    client: TestClient, api: str, session: Session, admin_headers: dict[str, str]
) -> None:
    client.put(f"{api}/response-targets/critical", json={"hours": 24}, headers=admin_headers)

    assert _actions(session, AUDIT_TARGET_RESPONSE_TARGET) == []


@pytest.mark.parametrize("hours", [0, -1, 87_601])
def test_an_unusable_target_is_refused(
    client: TestClient, api: str, admin_headers: dict[str, str], hours: int
) -> None:
    """A target nobody will live to see is a configuration mistake, not a policy."""
    response = client.put(
        f"{api}/response-targets/critical", json={"hours": hours}, headers=admin_headers
    )

    assert response.status_code == 422


def test_there_is_no_way_to_leave_a_severity_without_a_target(
    client: TestClient, api: str, session: Session, admin_headers: dict[str, str]
) -> None:
    """Findings of that severity would silently stop getting due dates, so the
    resource is edited and never created or deleted."""
    schema = client.get("/openapi.json").json()

    assert sorted(schema["paths"]["/api/v1/response-targets/{severity}"]) == ["put"]
    assert len(session.exec(select(ResponseTarget)).all()) == 4


# ─── Who may do any of this ───────────────────────────────────────────────────


@pytest.mark.parametrize("role", [UserRole.VIEWER, UserRole.ANALYST])
def test_only_an_admin_may_change_the_policy(
    client: TestClient,
    api: str,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
    admin_headers: dict[str, str],
    role: UserRole,
) -> None:
    """Changing a rule moves work between teams and rewrites what overdue means.
    Triaging one finding is analyst work; rewriting the policy above it is not."""
    group = _group(client, api, admin_headers, "payments")
    headers = login_as(make_user(role))

    refused = [
        client.post(f"{api}/owner-groups", json={"name": "other"}, headers=headers),
        client.patch(f"{api}/owner-groups/{group['id']}", json={"disabled": True}, headers=headers),
        client.delete(f"{api}/owner-groups/{group['id']}", headers=headers),
        client.post(
            f"{api}/routing-rules",
            json={"name": "r", "owner_group_id": group["id"]},
            headers=headers,
        ),
        client.put(f"{api}/response-targets/high", json={"hours": 1}, headers=headers),
    ]

    assert [response.status_code for response in refused] == [403] * 5


@pytest.mark.parametrize("role", [UserRole.VIEWER, UserRole.ANALYST])
def test_anyone_signed_in_may_read_who_owns_what(
    client: TestClient,
    api: str,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
    admin_headers: dict[str, str],
    role: UserRole,
) -> None:
    """ "Is this mine?" is the question the queue exists to answer, and it is not
    an administrative one."""
    _group(client, api, admin_headers, "payments")
    headers = login_as(make_user(role))

    allowed = [
        client.get(f"{api}/owner-groups", headers=headers),
        client.get(f"{api}/routing-rules", headers=headers),
        client.get(f"{api}/response-targets", headers=headers),
    ]

    assert [response.status_code for response in allowed] == [200] * 3


def test_a_write_without_a_csrf_token_is_refused(
    client: TestClient,
    api: str,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """These are cookie-authenticated browser routes like every other mutation."""
    login_as(make_user(UserRole.ADMIN))

    response = client.post(f"{api}/owner-groups", json={"name": "payments"})

    assert response.status_code == 403


# ─── The queues the whole feature exists for ──────────────────────────────────


def test_the_unowned_queue_is_a_filter_on_the_findings_list(
    client: TestClient,
    api: str,
    session: Session,
    admin_headers: dict[str, str],
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
) -> None:
    group = _group(client, api, admin_headers, "payments")
    source = make_source()
    orphan = make_finding(source)
    make_finding(source, owner_group_id=uuid.UUID(group["id"]))

    body = client.get(f"{api}/findings?unowned=true", headers=admin_headers).json()

    assert [row["id"] for row in body["items"]] == [str(orphan.id)]


def test_the_overdue_queue_counts_only_actionable_work(
    client: TestClient,
    api: str,
    session: Session,
    admin_headers: dict[str, str],
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
) -> None:
    """The same definition `ownership.overdue` applies to a single row, so the
    queue and the badge on a finding cannot disagree."""
    source = make_source()
    past = datetime.now(UTC) - timedelta(days=1)
    late = make_finding(source, due_at=past)
    make_finding(source, due_at=datetime.now(UTC) + timedelta(days=1))
    make_finding(source, due_at=past, state=FindingState.RESOLVED)
    make_finding(source, due_at=past, suppressed_at=past)

    body = client.get(f"{api}/findings?overdue=true", headers=admin_headers).json()

    assert [row["id"] for row in body["items"]] == [str(late.id)]


def test_the_owner_filter_narrows_to_one_team(
    client: TestClient,
    api: str,
    admin_headers: dict[str, str],
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
) -> None:
    payments = _group(client, api, admin_headers, "payments")
    platform = _group(client, api, admin_headers, "platform")
    source = make_source()
    mine = make_finding(source, owner_group_id=uuid.UUID(payments["id"]))
    make_finding(source, owner_group_id=uuid.UUID(platform["id"]))

    body = client.get(
        f"{api}/findings?owner_group_id={payments['id']}", headers=admin_headers
    ).json()

    assert [row["id"] for row in body["items"]] == [str(mine.id)]
