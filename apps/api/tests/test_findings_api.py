"""Listing and reading findings (#38).

Filters have to compose and ordering has to be stable, because the queue is what an
analyst works from: a filter that quietly ignores another one, or a page boundary
that repeats a row, is how a real secret gets skipped.
"""

from collections.abc import Callable

from fastapi.testclient import TestClient
from iceberg_core.enums import FindingEventKind, FindingState, Severity, UserRole
from iceberg_core.models import Finding, FindingEvent, Source, User
from sqlmodel import Session

FINDINGS = "/api/v1/findings"


def test_any_role_can_list_findings(
    client: TestClient,
    make_finding: Callable[..., Finding],
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    login_as(make_user(UserRole.VIEWER))
    finding = make_finding()

    response = client.get(FINDINGS)

    assert response.status_code == 200
    assert [item["id"] for item in response.json()["items"]] == [str(finding.id)]


def test_reading_findings_requires_a_session(client: TestClient) -> None:
    assert client.get(FINDINGS).status_code == 401


def test_a_response_never_carries_the_secret_hash(
    client: TestClient,
    make_finding: Callable[..., Finding],
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """The hash is not reversible, but the API still never re-emits it (ADR 0004).

    The correlation id an analyst sees is a different value under a different
    key (ADR 0011) — asserted here so the two can never quietly converge.
    """
    login_as(make_user(UserRole.VIEWER))
    finding = make_finding(correlation_id="c0" * 32)

    listed = client.get(FINDINGS).json()["items"][0]
    detail = client.get(f"{FINDINGS}/{finding.id}").json()

    assert "secret_hash" not in listed
    assert "secret_hash" not in detail
    assert finding.secret_hash not in str(listed) and finding.secret_hash not in str(detail)
    assert detail["redacted_snippet"] == "AKIA****************"

    login_as(make_user(UserRole.ANALYST))
    analyst_detail = client.get(f"{FINDINGS}/{finding.id}").json()
    assert analyst_detail["correlation"]["correlation_id"] != finding.secret_hash


def test_filters_compose(
    client: TestClient,
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """Every filter narrows the same statement; two of them mean both, not either."""
    analyst = make_user(UserRole.ANALYST)
    login_as(analyst)
    source = make_source("prod")
    wanted = make_finding(
        source, rule_id="aws-access-key", severity=Severity.CRITICAL, assignee_id=analyst.id
    )
    make_finding(source, rule_id="aws-access-key", severity=Severity.LOW)
    make_finding(source, rule_id="slack-token", severity=Severity.CRITICAL)
    make_finding(rule_id="aws-access-key", severity=Severity.CRITICAL)  # another source

    matched = client.get(
        FINDINGS,
        params={
            "source_id": str(source.id),
            "rule_id": "aws-access-key",
            "severity": "critical",
            "assignee_id": str(analyst.id),
            "state": "open",
        },
    )

    assert [item["id"] for item in matched.json()["items"]] == [str(wanted.id)]


def test_suppressed_findings_are_filtered_but_not_hidden_by_default(
    client: TestClient,
    session: Session,
    make_finding: Callable[..., Finding],
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """No implicit filter: the active view is a query the client sends."""
    login_as(make_user(UserRole.VIEWER))
    source_finding = make_finding()
    hidden = make_finding(session.get(Source, source_finding.source_id))
    hidden.suppressed_at = hidden.created_at
    session.add(hidden)
    session.commit()

    everything = client.get(FINDINGS).json()
    active = client.get(FINDINGS, params={"suppressed": False}).json()
    silenced = client.get(FINDINGS, params={"suppressed": True}).json()

    assert len(everything["items"]) == 2
    assert [item["id"] for item in active["items"]] == [str(source_finding.id)]
    assert [item["id"] for item in silenced["items"]] == [str(hidden.id)]


def test_pagination_is_stable_across_pages(
    client: TestClient,
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    login_as(make_user(UserRole.VIEWER))
    source = make_source()
    created = [make_finding(source) for _ in range(5)]

    first = client.get(FINDINGS, params={"limit": 2}).json()
    second = client.get(FINDINGS, params={"limit": 2, "cursor": first["next_cursor"]}).json()
    third = client.get(FINDINGS, params={"limit": 2, "cursor": second["next_cursor"]}).json()

    seen = [item["id"] for page in (first, second, third) for item in page["items"]]
    assert seen == [str(finding.id) for finding in created]
    assert third["next_cursor"] is None


def test_a_malformed_cursor_is_a_400(
    client: TestClient,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """A bad cursor is never quietly answered with the first page."""
    login_as(make_user(UserRole.VIEWER))

    assert client.get(FINDINGS, params={"cursor": "not-a-cursor"}).status_code == 400


def test_detail_returns_the_finding_event_history(
    client: TestClient,
    session: Session,
    make_finding: Callable[..., Finding],
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """ "Why is this finding in this state" is what the detail view is for."""
    login_as(make_user(UserRole.VIEWER))
    finding = make_finding(state=FindingState.RESOLVED)
    session.add(
        FindingEvent(
            finding_id=finding.id,
            kind=FindingEventKind.STATE_CHANGE,
            from_value=FindingState.OPEN.value,
            to_value=FindingState.RESOLVED.value,
            comment="not seen by the last scan",
        )
    )
    session.commit()

    body = client.get(f"{FINDINGS}/{finding.id}").json()

    assert body["state"] == "resolved"
    assert [event["kind"] for event in body["events"]] == ["state_change"]
    assert body["events"][0]["comment"] == "not seen by the last scan"


def test_an_unknown_finding_is_a_404(
    client: TestClient,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    login_as(make_user(UserRole.VIEWER))
    missing = "00000000-0000-0000-0000-000000000000"

    assert client.get(f"{FINDINGS}/{missing}").status_code == 404
