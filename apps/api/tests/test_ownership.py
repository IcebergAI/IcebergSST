"""Accountable owners, routing rules, and response targets (#146).

The property under all of this: **routing decides who owns a finding nobody has
looked at, and stops having an opinion the moment somebody has.** Automatic
ownership is what keeps the queue from being nobody's; the pin is what keeps it
from overruling the person who actually knows.
"""

import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from iceberg_api.engines import ingest
from iceberg_api.findings import ownership
from iceberg_core.enums import (
    FindingEventKind,
    FindingState,
    ScanStatus,
    ScanTrigger,
    Severity,
    UserRole,
)
from iceberg_core.models import (
    DEFAULT_RESPONSE_TARGET_HOURS,
    Finding,
    FindingEvent,
    OwnerGroup,
    ResponseTarget,
    RoutingRule,
    Scan,
    Source,
    User,
)
from sqlmodel import Session, col, select

NOW = datetime(2026, 8, 16, 9, 0, tzinfo=UTC)


def _group(session: Session, name: str, **overrides: Any) -> OwnerGroup:
    group = OwnerGroup(name=name, **overrides)
    session.add(group)
    session.commit()
    return group


def _rule(session: Session, group: OwnerGroup, name: str, **overrides: Any) -> RoutingRule:
    rule = RoutingRule(name=name, owner_group_id=group.id, **overrides)
    session.add(rule)
    session.commit()
    return rule


def _scan(session: Session, source: Source) -> Scan:
    scan = Scan(source_id=source.id, trigger=ScanTrigger.MANUAL, status=ScanStatus.COMPLETED)
    session.add(scan)
    session.commit()
    return scan


def _route(session: Session, finding: Finding, scan: Scan) -> RoutingRule | None:
    """Load the policy and route, the way ingest does."""
    policy = ownership.load(session, finding.source_id)
    matched = ownership.route(session, finding, policy, scan_id=scan.id)
    session.commit()
    return matched


def _due(finding: Finding) -> datetime | None:
    """The stored due date as an aware UTC instant.

    SQLite hands timestamps back without their offset (see
    ``iceberg_api.schemas._assume_utc``), so a test that compared the raw
    attribute would be asserting a property of the *test* database rather than of
    the code. The API contract is offset-aware either way, and that is asserted
    separately below.
    """
    if finding.due_at is None:
        return None
    return finding.due_at if finding.due_at.tzinfo else finding.due_at.replace(tzinfo=UTC)


def _events(session: Session, finding: Finding) -> list[FindingEvent]:
    return list(
        session.exec(
            select(FindingEvent)
            .where(col(FindingEvent.finding_id) == finding.id)
            .where(col(FindingEvent.kind) == FindingEventKind.OWNER)
            .order_by(col(FindingEvent.created_at), col(FindingEvent.id))
        )
    )


# ─── Which rule claims a finding ──────────────────────────────────────────────


def test_the_first_matching_rule_wins_and_a_later_one_does_not_run(
    session: Session,
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
) -> None:
    """Precedence is the whole contract: two rules can match, one owner results."""
    source = make_source()
    urgent, everything = _group(session, "sec-urgent"), _group(session, "sec-triage")
    _rule(session, urgent, "critical-to-urgent", priority=10, min_severity=Severity.CRITICAL)
    _rule(session, everything, "catch-all", priority=900)
    finding = make_finding(source, severity=Severity.CRITICAL)

    _route(session, finding, _scan(session, source))

    assert finding.owner_group_id == urgent.id


def test_a_rule_with_no_matchers_is_a_catch_all(
    session: Session,
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
) -> None:
    """How a default owner is expressed. Null never means "match nothing"."""
    source = make_source()
    group = _group(session, "sec-triage")
    _rule(session, group, "catch-all", priority=900)
    finding = make_finding(source, severity=Severity.LOW)

    _route(session, finding, _scan(session, source))

    assert finding.owner_group_id == group.id


def test_ties_are_broken_by_creation_order_not_by_chance(
    session: Session,
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
) -> None:
    """`priority` is not unique, so the order has to be total some other way — or
    two replicas route the same finding to different teams."""
    source = make_source()
    first, second = _group(session, "team-a"), _group(session, "team-b")
    earlier = _rule(session, first, "a", priority=100)
    _rule(session, second, "b", priority=100)
    # Same priority, and `a` was created first.
    assert earlier.priority == 100
    finding = make_finding(source)

    _route(session, finding, _scan(session, source))

    assert finding.owner_group_id == first.id


@pytest.mark.parametrize(
    ("matcher", "matches"),
    [
        ({"rule_id": "aws-access-key"}, True),
        ({"rule_id": "slack-token"}, False),
        ({"min_severity": Severity.MEDIUM}, True),
        ({"min_severity": Severity.CRITICAL}, False),
        ({"source_tags": ["pci"]}, True),
        ({"source_tags": ["pci", "eu"]}, True),
        ({"source_tags": ["pci", "apac"]}, False),
    ],
)
def test_each_matcher_narrows_and_they_are_anded(
    session: Session,
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
    matcher: dict[str, Any],
    matches: bool,
) -> None:
    """A high-severity `aws-access-key` on a source tagged pci+eu."""
    source = make_source()
    source.tags = ["pci", "eu"]
    session.add(source)
    session.commit()
    group = _group(session, "team-a")
    _rule(session, group, "narrowed", **matcher)
    finding = make_finding(source, severity=Severity.HIGH, rule_id="aws-access-key")

    _route(session, finding, _scan(session, source))

    assert (finding.owner_group_id == group.id) is matches


def test_a_rule_for_another_source_does_not_claim_this_one(
    session: Session,
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
) -> None:
    mine, theirs = make_source(name="mine"), make_source(name="theirs")
    group = _group(session, "team-a")
    _rule(session, group, "theirs-only", source_id=theirs.id)
    finding = make_finding(mine)

    _route(session, finding, _scan(session, mine))

    assert finding.owner_group_id is None


def test_a_disabled_rule_is_not_consulted(
    session: Session,
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
) -> None:
    source = make_source()
    group = _group(session, "team-a")
    _rule(session, group, "off", enabled=False)
    finding = make_finding(source)

    _route(session, finding, _scan(session, source))

    assert finding.owner_group_id is None


def test_a_rule_pointing_at_a_disbanded_group_lets_the_next_rule_have_it(
    session: Session,
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
) -> None:
    """The subtle one. If a disabled group's rule were merely skipped *at match
    time* it would still be first, and "first match wins" would silently mean
    "nobody gets it" — a whole team's findings vanishing into the unowned queue
    because somebody ticked a box."""
    source = make_source()
    gone, live = _group(session, "disbanded", disabled=True), _group(session, "still-here")
    _rule(session, gone, "was-theirs", priority=10)
    _rule(session, live, "fallback", priority=900)
    finding = make_finding(source)

    _route(session, finding, _scan(session, source))

    assert finding.owner_group_id == live.id


# ─── What routing records, and when it declines to act ────────────────────────


def test_routing_records_the_rule_that_decided(
    session: Session,
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
) -> None:
    """ "Why is this ours?" is the first question the owning team asks."""
    source = make_source()
    group = _group(session, "team-a")
    _rule(session, group, "everything-critical", min_severity=Severity.CRITICAL)
    finding = make_finding(source, severity=Severity.CRITICAL)
    scan = _scan(session, source)

    _route(session, finding, scan)

    event = _events(session, finding)[-1]
    assert event.actor_id is None
    assert event.scan_id == scan.id
    assert event.to_value == str(group.id)
    assert "everything-critical" in (event.comment or "")


def test_an_owned_finding_is_not_re_routed_when_the_rules_change(
    session: Session,
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
) -> None:
    """Rules change and teams reorganise. A queue that reshuffles under the people
    working it is worse than one that is occasionally out of date."""
    source = make_source()
    first, second = _group(session, "team-a"), _group(session, "team-b")
    _rule(session, first, "original", priority=100)
    finding = make_finding(source)
    scan = _scan(session, source)
    _route(session, finding, scan)

    _rule(session, second, "newer-and-higher-priority", priority=1)
    _route(session, finding, scan)

    assert finding.owner_group_id == first.id
    assert len(_events(session, finding)) == 1


def test_an_unowned_finding_is_routed_by_a_rule_added_later(
    session: Session,
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
) -> None:
    """The other half of the same rule: the unowned queue has to be able to drain."""
    source = make_source()
    finding = make_finding(source)
    scan = _scan(session, source)
    _route(session, finding, scan)
    assert finding.owner_group_id is None

    group = _group(session, "team-a")
    _rule(session, group, "added-today")
    _route(session, finding, scan)

    assert finding.owner_group_id == group.id


def test_a_pinned_finding_is_never_touched_by_routing(
    session: Session,
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
) -> None:
    """A person decided. That outranks every rule, permanently — including the
    decision to have *no* owner, which is why the pin is checked before the
    owner rather than instead of it."""
    source = make_source()
    group = _group(session, "team-a")
    _rule(session, group, "catch-all")
    finding = make_finding(source, owner_group_id=None, owner_pinned=True)

    matched = _route(session, finding, _scan(session, source))

    assert matched is None
    assert finding.owner_group_id is None


# ─── Response targets ─────────────────────────────────────────────────────────


def test_the_due_date_comes_from_the_severity_target(
    session: Session,
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
) -> None:
    finding = make_finding(make_source(), severity=Severity.CRITICAL)
    policy = ownership.load(session, finding.source_id)

    ownership.start_clock(session, finding, policy, at=NOW)

    hours = DEFAULT_RESPONSE_TARGET_HOURS[Severity.CRITICAL]
    assert _due(finding) == NOW + timedelta(hours=hours)


def test_a_severity_with_no_configured_target_gets_no_due_date(
    session: Session,
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
) -> None:
    """No date beats an invented one: an operator who has not set a target has
    not agreed to anything, and a made-up deadline would show up as overdue work
    nobody promised."""
    row = session.exec(select(ResponseTarget).where(ResponseTarget.severity == Severity.LOW)).one()
    session.delete(row)
    session.commit()
    finding = make_finding(make_source(), severity=Severity.LOW)

    ownership.start_clock(session, finding, ownership.load(session, finding.source_id), at=NOW)

    assert finding.due_at is None


def test_editing_a_target_does_not_move_an_existing_due_date(
    session: Session,
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
) -> None:
    """Tightening "high" from 72 to 24 hours must not reach backwards and declare
    last month's closed work to have been late."""
    finding = make_finding(make_source(), severity=Severity.HIGH)
    ownership.start_clock(session, finding, ownership.load(session, finding.source_id), at=NOW)
    original = _due(finding)

    target = session.exec(
        select(ResponseTarget).where(ResponseTarget.severity == Severity.HIGH)
    ).one()
    target.hours = 1
    session.add(target)
    session.commit()
    ownership.start_clock(session, finding, ownership.load(session, finding.source_id), at=NOW)

    assert _due(finding) == original


def test_a_missing_due_date_is_filled_in_on_the_next_sighting(
    session: Session,
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
) -> None:
    """Rows predating ownership, and rows ingested before anyone configured a
    target, join the scheme rather than staying permanently undated."""
    finding = make_finding(make_source(), severity=Severity.HIGH, due_at=None)

    ownership.start_clock(session, finding, ownership.load(session, finding.source_id), at=NOW)

    assert finding.due_at is not None


def test_a_reopen_restarts_the_clock(
    session: Session,
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
) -> None:
    """The secret came back. The team gets the target again from the sighting that
    refuted the resolution, not a deadline that expired while it was correctly
    resolved."""
    finding = make_finding(make_source(), severity=Severity.HIGH)
    policy = ownership.load(session, finding.source_id)
    ownership.start_clock(session, finding, policy, at=NOW)

    later = NOW + timedelta(days=90)
    ownership.start_clock(session, finding, policy, at=later, restart=True)

    assert _due(finding) == later + timedelta(hours=DEFAULT_RESPONSE_TARGET_HOURS[Severity.HIGH])


@pytest.mark.parametrize(
    ("fields", "expected"),
    [
        ({}, True),
        ({"state": FindingState.RESOLVED}, False),
        ({"state": FindingState.FALSE_POSITIVE}, False),
        ({"suppressed_at": NOW}, False),
    ],
)
def test_only_actionable_findings_can_be_overdue(
    session: Session,
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
    fields: dict[str, Any],
    expected: bool,
) -> None:
    """Overdue is work somebody owes. A resolved or suppressed finding keeps its
    date — a suppression can lapse — but is nobody's late work meanwhile."""
    finding = make_finding(make_source(), due_at=NOW - timedelta(hours=1), **fields)

    assert ownership.overdue(finding, at=NOW) is expected


def test_overdue_does_not_raise_on_a_date_the_database_returned_naive(
    session: Session,
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
) -> None:
    """The portability trap this guards. Postgres returns `TIMESTAMP WITH TIME
    ZONE` offset-aware and SQLite does not, so comparing the stored value with an
    aware `now` raises on one database and not the other — in the single function
    every "is this late?" answer goes through."""
    finding = make_finding(make_source(), severity=Severity.HIGH)
    ownership.start_clock(session, finding, ownership.load(session, finding.source_id), at=NOW)
    session.commit()
    # Expired, so the next read comes back from storage rather than from identity
    # map state that still holds the aware value this test wrote.
    session.expire(finding)
    assert finding.due_at is not None

    assert ownership.overdue(finding, at=NOW + timedelta(days=365)) is True
    assert ownership.overdue(finding, at=NOW) is False


def test_the_api_reports_a_due_date_as_an_offset_aware_instant(
    client: TestClient,
    session: Session,
    api: str,
    make_user: Callable[..., User],
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """Whatever the database hands back, the contract is UTC with an offset — a
    client should not have to know which database is underneath to read a
    deadline (`iceberg_api.schemas.UtcDatetime`)."""
    finding = make_finding(make_source(), severity=Severity.HIGH)
    ownership.start_clock(session, finding, ownership.load(session, finding.source_id), at=NOW)
    session.commit()
    headers = login_as(make_user(UserRole.VIEWER))

    body = client.get(f"{api}/findings/{finding.id}", headers=headers).json()

    assert datetime.fromisoformat(body["due_at"]) == NOW + timedelta(
        hours=DEFAULT_RESPONSE_TARGET_HOURS[Severity.HIGH]
    )


# ─── Wired into ingest ────────────────────────────────────────────────────────


def _payload(**overrides: Any) -> Any:
    from iceberg_api.engines.schemas import FindingPayload

    return FindingPayload.model_validate(
        {
            "fingerprint": uuid.uuid4().hex * 2,
            "rule_id": "aws-access-key",
            "rulepack_version": "2026.07.1",
            "resource_locator": {"page_id": "1"},
            "redacted_snippet": "AKIA****",
            "secret_hash": uuid.uuid4().hex * 2,
            "severity": "high",
        }
        | overrides
    )


def test_ingest_routes_and_dates_a_brand_new_finding(
    session: Session, make_source: Callable[..., Source]
) -> None:
    """The wiring, end to end: a finding arrives owned and dated or the whole
    feature is a table nobody writes to."""
    source = make_source()
    group = _group(session, "team-a")
    _rule(session, group, "catch-all")
    scan = _scan(session, source)

    ingest.ingest_findings(session, scan, [_payload()], now=NOW)
    session.commit()

    finding = session.exec(select(Finding)).one()
    assert finding.owner_group_id == group.id
    assert _due(finding) == NOW + timedelta(hours=DEFAULT_RESPONSE_TARGET_HOURS[Severity.HIGH])


def test_a_finding_that_arrives_suppressed_is_still_owned_and_dated(
    session: Session, make_source: Callable[..., Source]
) -> None:
    """A suppression can lapse. If ownership waited for that, the finding would
    come back into the queue unowned and sit there another whole scan (ADR 0008)."""
    from iceberg_core.enums import SuppressionScope
    from iceberg_core.models import Suppression

    source = make_source()
    group = _group(session, "team-a")
    _rule(session, group, "catch-all")
    session.add(
        Suppression(
            scope=SuppressionScope.RULE,
            pattern="aws-access-key",
            source_id=source.id,
            reason="known fixture",
        )
    )
    session.commit()

    ingest.ingest_findings(session, _scan(session, source), [_payload()], now=NOW)
    session.commit()

    finding = session.exec(select(Finding)).one()
    assert finding.suppressed_at is not None
    assert finding.owner_group_id == group.id
    assert finding.due_at is not None


def test_ingest_restarts_the_clock_when_a_secret_comes_back(
    session: Session, make_source: Callable[..., Source]
) -> None:
    source = make_source()
    scan = _scan(session, source)
    payload = _payload()
    ingest.ingest_findings(session, scan, [payload], now=NOW)
    session.commit()
    finding = session.exec(select(Finding)).one()
    finding.state = FindingState.RESOLVED
    session.add(finding)
    session.commit()

    later = NOW + timedelta(days=30)
    ingest.ingest_findings(session, _scan(session, source), [payload], now=later)
    session.commit()

    session.refresh(finding)
    assert finding.state is FindingState.OPEN
    assert _due(finding) == later + timedelta(hours=DEFAULT_RESPONSE_TARGET_HOURS[Severity.HIGH])


# ─── The manual override, through the API ─────────────────────────────────────


def test_an_analyst_can_take_ownership_and_the_pin_holds(
    client: TestClient,
    session: Session,
    api: str,
    make_user: Callable[..., User],
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    source = make_source()
    routed, chosen = _group(session, "routed-team"), _group(session, "actually-ours")
    _rule(session, routed, "catch-all")
    finding = make_finding(source)
    _route(session, finding, _scan(session, source))
    headers = login_as(make_user(UserRole.ANALYST))

    response = client.patch(
        f"{api}/findings/{finding.id}",
        json={"owner_group_id": str(chosen.id), "comment": "we run this service"},
        headers=headers,
    )

    assert response.status_code == 200, response.text
    assert response.json()["owner_group_id"] == str(chosen.id)
    assert response.json()["owner_pinned"] is True
    session.refresh(finding)
    assert _route(session, finding, _scan(session, source)) is None
    assert finding.owner_group_id == chosen.id


def test_taking_the_owner_off_pins_it_empty_rather_than_re_arming_routing(
    client: TestClient,
    session: Session,
    api: str,
    make_user: Callable[..., User],
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """ "No, this is not ours" is a decision too. Re-routing it would answer the
    person back with the same rule that got it wrong the first time."""
    source = make_source()
    group = _group(session, "routed-team")
    _rule(session, group, "catch-all")
    finding = make_finding(source)
    _route(session, finding, _scan(session, source))
    headers = login_as(make_user(UserRole.ANALYST))

    response = client.patch(
        f"{api}/findings/{finding.id}",
        json={"owner_group_id": None},
        headers=headers,
    )

    assert response.status_code == 200, response.text
    session.refresh(finding)
    assert finding.owner_group_id is None
    assert _route(session, finding, _scan(session, source)) is None


def test_confirming_the_owner_a_rule_chose_still_pins_it(
    client: TestClient,
    session: Session,
    api: str,
    make_user: Callable[..., User],
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """Agreeing with the routing is the common case and has to mean something,
    or "yes, ours" leaves the finding as re-routable as it was."""
    source = make_source()
    group = _group(session, "team-a")
    _rule(session, group, "catch-all")
    finding = make_finding(source)
    _route(session, finding, _scan(session, source))
    headers = login_as(make_user(UserRole.ANALYST))

    response = client.patch(
        f"{api}/findings/{finding.id}",
        json={"owner_group_id": str(group.id)},
        headers=headers,
    )

    assert response.status_code == 200, response.text
    session.refresh(finding)
    assert finding.owner_pinned is True
    assert len(_events(session, finding)) == 2


def test_re_sending_a_decision_already_recorded_writes_nothing(
    client: TestClient,
    session: Session,
    api: str,
    make_user: Callable[..., User],
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """A retried request and an idle Save click are not second decisions."""
    source = make_source()
    group = _group(session, "team-a")
    finding = make_finding(source)
    headers = login_as(make_user(UserRole.ANALYST))
    body = {"owner_group_id": str(group.id)}

    client.patch(f"{api}/findings/{finding.id}", json=body, headers=headers)
    client.patch(f"{api}/findings/{finding.id}", json=body, headers=headers)

    session.refresh(finding)
    assert len(_events(session, finding)) == 1


def test_a_viewer_cannot_change_who_owns_a_finding(
    client: TestClient,
    session: Session,
    api: str,
    make_user: Callable[..., User],
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    group = _group(session, "team-a")
    finding = make_finding(make_source())
    headers = login_as(make_user(UserRole.VIEWER))

    response = client.patch(
        f"{api}/findings/{finding.id}",
        json={"owner_group_id": str(group.id)},
        headers=headers,
    )

    assert response.status_code == 403
    session.refresh(finding)
    assert finding.owner_group_id is None


@pytest.mark.parametrize("disbanded", [True, False])
def test_a_finding_cannot_be_handed_to_a_group_that_cannot_take_it(
    client: TestClient,
    session: Session,
    api: str,
    make_user: Callable[..., User],
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
    login_as: Callable[[User], dict[str, str]],
    disbanded: bool,
) -> None:
    """Disbanded or nonexistent, the result is the same: a finding pinned to
    nobody, which routing is then forbidden from rescuing."""
    target = str(_group(session, "gone", disabled=True).id) if disbanded else str(uuid.uuid4())
    finding = make_finding(make_source())
    headers = login_as(make_user(UserRole.ANALYST))

    response = client.patch(
        f"{api}/findings/{finding.id}",
        json={"owner_group_id": target},
        headers=headers,
    )

    assert response.status_code == 422
    session.refresh(finding)
    assert finding.owner_group_id is None
    assert finding.owner_pinned is False
