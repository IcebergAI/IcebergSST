"""The ownership screens (#146).

Each test meets the acceptance criterion the way an operator would: the screen
renders, the form drives the API route it is supposed to drive, the change lands
in the database, and the queue the whole feature exists to produce is reachable
from the console rather than only from a URL somebody had to know to type.
"""

import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from iceberg_core.enums import FindingState, Severity, UserRole
from iceberg_core.models import Finding, OwnerGroup, ResponseTarget, RoutingRule, Source, User
from sqlmodel import Session, col, select


@pytest.fixture(name="admin_headers")
def admin_headers_fixture(
    make_user: Callable[..., User], login_as: Callable[[User], dict[str, str]]
) -> dict[str, str]:
    return login_as(make_user(UserRole.ADMIN))


def _make_group(client: TestClient, headers: dict[str, str], name: str) -> None:
    response = client.post(
        "/ownership/groups",
        data={"csrf_token": headers["X-CSRF-Token"], "name": name},
        headers=headers,
    )
    assert response.status_code in (200, 204), response.text


# ─── The ownership screen ─────────────────────────────────────────────────────


def test_the_screen_creates_a_team_through_the_api(
    client: TestClient, session: Session, admin_headers: dict[str, str]
) -> None:
    _make_group(client, admin_headers, "payments")

    group = session.exec(select(OwnerGroup)).one()
    assert group.name == "payments"
    assert "payments" in client.get("/ownership").text


def test_the_screen_creates_a_rule_that_routing_will_actually_use(
    client: TestClient, session: Session, admin_headers: dict[str, str]
) -> None:
    """A form that can create a rule the engine does not consult is a form, not a
    feature — so this asserts the stored rule, matchers included."""
    _make_group(client, admin_headers, "payments")
    group = session.exec(select(OwnerGroup)).one()

    client.post(
        "/ownership/rules",
        data={
            "csrf_token": admin_headers["X-CSRF-Token"],
            "name": "critical-to-payments",
            "owner_group_id": str(group.id),
            "priority": "10",
            "min_severity": "critical",
            "source_tags": " PCI , eu ",
        },
        headers=admin_headers,
    )

    rule = session.exec(select(RoutingRule)).one()
    assert rule.owner_group_id == group.id
    assert rule.priority == 10
    assert rule.min_severity is Severity.CRITICAL
    # Trimmed, and the case an operator typed is kept — the comparison folds, the
    # storage does not.
    assert rule.source_tags == ["PCI", "eu"]


def test_a_rule_form_left_blank_creates_the_catch_all(
    client: TestClient, session: Session, admin_headers: dict[str, str]
) -> None:
    """Blank means "do not narrow on this", so an otherwise empty form is how a
    default owner is expressed."""
    _make_group(client, admin_headers, "triage")
    group = session.exec(select(OwnerGroup)).one()

    client.post(
        "/ownership/rules",
        data={
            "csrf_token": admin_headers["X-CSRF-Token"],
            "name": "catch-all",
            "owner_group_id": str(group.id),
            "priority": "900",
            "source_id": "",
            "rule_id": "",
            "min_severity": "",
            "source_tags": "",
        },
        headers=admin_headers,
    )

    rule = session.exec(select(RoutingRule)).one()
    assert (rule.source_id, rule.rule_id, rule.min_severity, rule.source_tags) == (
        None,
        None,
        None,
        [],
    )


def test_rules_are_shown_in_the_order_routing_evaluates_them(
    client: TestClient, session: Session, admin_headers: dict[str, str]
) -> None:
    """Order is the meaning of a rule set. A screen that showed a different one
    would be a screen you could not use to reason about routing."""
    _make_group(client, admin_headers, "payments")
    group = session.exec(select(OwnerGroup)).one()
    # Names that appear nowhere else on the page: "critical" is also a severity
    # option in the rule form above the table, so matching on it would compare a
    # dropdown against a row.
    for name, priority in (("zz-last-rule", 900), ("aa-first-rule", 10)):
        client.post(
            "/ownership/rules",
            data={
                "csrf_token": admin_headers["X-CSRF-Token"],
                "name": name,
                "owner_group_id": str(group.id),
                "priority": str(priority),
            },
            headers=admin_headers,
        )

    body = client.get("/ownership").text

    assert body.index("aa-first-rule") < body.index("zz-last-rule")


def test_a_team_is_disbanded_rather_than_deleted_when_it_owns_work(
    client: TestClient,
    session: Session,
    admin_headers: dict[str, str],
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
) -> None:
    """Deleting would succeed at the database and silently orphan the findings
    (the FK is SET NULL), so the screen offers disbanding first and hides delete
    for a team that owns anything."""
    _make_group(client, admin_headers, "payments")
    group = session.exec(select(OwnerGroup)).one()
    make_finding(make_source(), owner_group_id=group.id)

    body = client.get("/ownership").text
    client.post(
        f"/ownership/groups/{group.id}/state",
        data={"csrf_token": admin_headers["X-CSRF-Token"], "disabled": "true"},
        headers=admin_headers,
    )

    assert f'hx-delete="/ownership/groups/{group.id}"' not in body
    session.refresh(group)
    assert group.disabled is True


def test_a_disbanded_team_is_still_listed_with_what_it_owes(
    client: TestClient,
    session: Session,
    admin_headers: dict[str, str],
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
) -> None:
    """This is the screen an operator comes to when looking for work stranded on
    a team that no longer exists, so hiding it here would hide the problem."""
    _make_group(client, admin_headers, "payments")
    group = session.exec(select(OwnerGroup)).one()
    group.disabled = True
    session.add(group)
    make_finding(make_source(), owner_group_id=group.id)
    session.commit()

    body = client.get("/ownership").text

    assert "payments" in body
    assert "disbanded" in body


def test_a_rule_can_be_turned_off_without_losing_its_place(
    client: TestClient, session: Session, admin_headers: dict[str, str]
) -> None:
    _make_group(client, admin_headers, "payments")
    group = session.exec(select(OwnerGroup)).one()
    client.post(
        "/ownership/rules",
        data={
            "csrf_token": admin_headers["X-CSRF-Token"],
            "name": "critical",
            "owner_group_id": str(group.id),
            "priority": "10",
        },
        headers=admin_headers,
    )
    rule = session.exec(select(RoutingRule)).one()

    client.post(
        f"/ownership/rules/{rule.id}/state",
        data={"csrf_token": admin_headers["X-CSRF-Token"], "enabled": "false"},
        headers=admin_headers,
    )

    session.refresh(rule)
    assert (rule.enabled, rule.priority) == (False, 10)
    assert "critical" in client.get("/ownership").text


def test_saving_the_targets_form_changes_only_what_moved(
    client: TestClient, session: Session, admin_headers: dict[str, str]
) -> None:
    """All four are posted every time, because an operator sets critical relative
    to high. The API records nothing for one that did not change, so a one-number
    edit leaves one audit row rather than four."""
    from iceberg_core.models import AUDIT_TARGET_RESPONSE_TARGET, AuditEvent

    client.post(
        "/ownership/targets",
        data={
            "csrf_token": admin_headers["X-CSRF-Token"],
            "critical": "4",
            "high": "72",
            "medium": "336",
            "low": "720",
        },
        headers=admin_headers,
    )

    critical = session.exec(
        select(ResponseTarget).where(col(ResponseTarget.severity) == Severity.CRITICAL)
    ).one()
    assert critical.hours == 4
    recorded = session.exec(
        select(AuditEvent).where(col(AuditEvent.target_type) == AUDIT_TARGET_RESPONSE_TARGET)
    ).all()
    assert len(recorded) == 1


def test_a_refused_change_is_shown_rather_than_swallowed(
    client: TestClient, session: Session, admin_headers: dict[str, str]
) -> None:
    """Two teams cannot share a name; the second attempt must say so."""
    _make_group(client, admin_headers, "payments")

    response = client.post(
        "/ownership/groups",
        data={"csrf_token": admin_headers["X-CSRF-Token"], "name": "payments"},
        headers=admin_headers,
    )

    assert "already exists" in client.get(response.headers["HX-Redirect"]).text
    assert len(session.exec(select(OwnerGroup)).all()) == 1


@pytest.mark.parametrize("role", [UserRole.VIEWER, UserRole.ANALYST])
def test_only_an_admin_reaches_the_ownership_screen(
    client: TestClient,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
    role: UserRole,
) -> None:
    """Calling an API handler as a function does not run its own `Depends`, so
    the web route declares the gate itself (docs/web.md)."""
    login_as(make_user(role))

    assert client.get("/ownership").status_code == 403


def test_the_rail_offers_ownership_only_to_an_admin(
    client: TestClient,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    login_as(make_user(UserRole.ANALYST))
    analyst_rail = client.get("/").text
    login_as(make_user(UserRole.ADMIN))
    admin_rail = client.get("/").text

    assert 'href="/ownership"' not in analyst_rail
    assert 'href="/ownership"' in admin_rail


# ─── Ownership on the findings screens ────────────────────────────────────────


def test_the_queue_can_be_narrowed_to_one_team(
    client: TestClient,
    session: Session,
    admin_headers: dict[str, str],
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
) -> None:
    _make_group(client, admin_headers, "payments")
    group = session.exec(select(OwnerGroup)).one()
    source = make_source()
    mine = make_finding(source, owner_group_id=group.id, rule_id="mine-rule")
    make_finding(source, rule_id="theirs-rule")

    body = client.get(f"/findings?owner={group.id}").text

    assert "mine-rule" in body
    assert "theirs-rule" not in body
    assert f'href="/findings/{mine.id}"' in body


def test_the_unowned_queue_is_one_option_in_the_owner_dropdown(
    client: TestClient,
    session: Session,
    admin_headers: dict[str, str],
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
) -> None:
    """One control for two API parameters. Two controls that must not both be set
    is a state an operator can get wrong and a URL can carry."""
    _make_group(client, admin_headers, "payments")
    group = session.exec(select(OwnerGroup)).one()
    source = make_source()
    make_finding(source, owner_group_id=group.id, rule_id="owned-rule")
    make_finding(source, rule_id="orphan-rule")

    body = client.get("/findings?owner=none").text

    assert "orphan-rule" in body
    assert "owned-rule" not in body


def test_an_overdue_finding_is_marked_on_the_queue(
    client: TestClient,
    admin_headers: dict[str, str],
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
) -> None:
    """Computed once in Python from the same helper the queue filter uses — a
    second definition written in Jinja would be the copy that drifts."""
    past = datetime.now(UTC) - timedelta(days=2)
    make_finding(make_source(), due_at=past, rule_id="late-rule")

    body = client.get("/findings?overdue=true").text

    assert "late-rule" in body
    assert "is-crit" in body


def test_a_resolved_finding_past_its_date_is_not_in_the_overdue_queue(
    client: TestClient,
    admin_headers: dict[str, str],
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
) -> None:
    """It keeps its date — a suppression can lapse, a resolution can be refuted —
    but it is nobody's late work meanwhile."""
    past = datetime.now(UTC) - timedelta(days=2)
    make_finding(make_source(), due_at=past, state=FindingState.RESOLVED, rule_id="done-rule")

    assert "done-rule" not in client.get("/findings?overdue=true").text


def test_the_detail_screen_names_the_team_and_the_deadline(
    client: TestClient,
    session: Session,
    admin_headers: dict[str, str],
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
) -> None:
    _make_group(client, admin_headers, "payments")
    group = session.exec(select(OwnerGroup)).one()
    finding = make_finding(
        make_source(),
        owner_group_id=group.id,
        due_at=datetime.now(UTC) - timedelta(hours=1),
    )

    body = client.get(f"/findings/{finding.id}").text

    assert "payments" in body
    assert "overdue since" in body


def test_an_analyst_can_take_ownership_from_the_triage_panel(
    client: TestClient,
    session: Session,
    admin_headers: dict[str, str],
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
) -> None:
    """The picker is offered to analysts even though the *user* picker is not:
    listing teams is viewer+ at the API, because a team is not a directory."""
    _make_group(client, admin_headers, "payments")
    group = session.exec(select(OwnerGroup)).one()
    finding = make_finding(make_source())
    headers = login_as(make_user(UserRole.ANALYST))

    response = client.post(
        f"/findings/{finding.id}/triage",
        data={
            "csrf_token": headers["X-CSRF-Token"],
            "state": finding.state.value,
            "owner": str(group.id),
        },
        headers=headers,
    )

    assert response.status_code == 200, response.text
    session.refresh(finding)
    assert finding.owner_group_id == group.id
    assert finding.owner_pinned is True


def test_leaving_the_owner_unchanged_does_not_pin_the_finding(
    client: TestClient,
    session: Session,
    admin_headers: dict[str, str],
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
) -> None:
    """Any owner value pins, so "leave unchanged" has to be expressible — or an
    analyst could not add a comment without also taking the decision away from
    the rules."""
    finding = make_finding(make_source())
    headers = login_as(make_user(UserRole.ANALYST))

    client.post(
        f"/findings/{finding.id}/triage",
        data={
            "csrf_token": headers["X-CSRF-Token"],
            "state": finding.state.value,
            "owner": "",
            "comment": "looking at this",
        },
        headers=headers,
    )

    session.refresh(finding)
    assert finding.owner_pinned is False
    assert finding.owner_group_id is None


def test_the_overview_counts_unowned_and_overdue_work(
    client: TestClient,
    session: Session,
    admin_headers: dict[str, str],
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
) -> None:
    """Asked of the API rather than counted from the open-findings page, which is
    capped — deriving them would under-report exactly when the backlog matters."""
    _make_group(client, admin_headers, "payments")
    group = session.exec(select(OwnerGroup)).one()
    source = make_source()
    make_finding(source, due_at=datetime.now(UTC) - timedelta(days=1))
    make_finding(source, owner_group_id=group.id)

    body = client.get("/").text

    assert 'href="/findings?overdue=true"' in body
    assert "owner=none" in body


def test_a_finding_with_no_response_target_says_so(
    client: TestClient,
    admin_headers: dict[str, str],
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
) -> None:
    """No date beats an invented one, and the screen should not render an empty
    cell that reads as "not late"."""
    finding = make_finding(make_source(), due_at=None)

    assert "no response target" in client.get(f"/findings/{finding.id}").text


def test_the_ownership_screen_renders_for_a_deployment_with_nothing_set_up(
    client: TestClient, admin_headers: dict[str, str]
) -> None:
    """The first thing a new operator sees, and the one state every empty-state
    branch has to survive at once."""
    body = client.get("/ownership")

    assert body.status_code == 200
    assert "No teams" in body.text
    assert "No rules" in body.text
    # The seeded targets are there from the migration, so this section is never
    # empty — a deployment has deadlines before anybody configures one.
    assert "Save targets" in body.text


def test_group_ids_are_uuids_the_screen_never_has_to_invent(
    client: TestClient, session: Session, admin_headers: dict[str, str]
) -> None:
    """Guards the delete/disable links: they are built from real ids, so a screen
    rendered before a group exists must not emit an action pointing at nothing."""
    _make_group(client, admin_headers, "payments")
    group = session.exec(select(OwnerGroup)).one()

    body = client.get("/ownership").text

    assert f"/ownership/groups/{group.id}/state" in body
    assert uuid.UUID(str(group.id)).version == 4
