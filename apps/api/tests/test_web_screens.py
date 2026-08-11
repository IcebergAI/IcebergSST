"""The operational screens (#55, #56, #57, #58, #72).

Each test asserts the epic's acceptance criterion the way a user would meet it:
the screen renders, the action drives the API route it is supposed to drive, the
change lands in the database, and the things that must never appear on a page —
a credential, a webhook secret, anything derived from a detected secret — do not.
"""

import re
import uuid
from collections.abc import Callable

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from iceberg_api.pagination import DEFAULT_LIMIT
from iceberg_api.sources.routes import get_prober
from iceberg_api.sources.schemas import ConnectivityResult
from iceberg_core.enums import (
    FindingEventKind,
    FindingState,
    NotificationChannelType,
    ScanStatus,
    ScanTaskKind,
    ScanTaskStatus,
    ScanTrigger,
    Severity,
    SourceType,
    SuppressionScope,
    UserRole,
)
from iceberg_core.models import (
    AUDIT_TARGET_CHANNEL,
    AUDIT_TARGET_USER,
    Engine,
    Finding,
    FindingEvent,
    NotificationChannel,
    Scan,
    ScanTask,
    Schedule,
    Source,
    Suppression,
    User,
)
from pydantic import SecretStr
from sqlmodel import Session, select

CONFLUENCE_FORM = {
    "name": "confluence-eng",
    "type": "confluence",
    "base_url": "https://example.atlassian.net/wiki",
    "email": "scanner@example.com",
    "api_prefix": "",
    "credential": "super-secret-api-token",
    "include_comments": "on",
    "include_attachments": "on",
    "enabled": "on",
}


# ─── #55 Sources ─────────────────────────────────────────────────────────────


def test_creating_a_source_from_the_form_drives_the_sources_api(
    client: TestClient,
    session: Session,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    headers = login_as(make_user(UserRole.ADMIN))

    response = client.post(
        "/sources",
        data=CONFLUENCE_FORM | {"csrf_token": headers["X-CSRF-Token"], "spaces": ["ENG", "OPS"]},
        headers=headers,
    )

    assert response.status_code == 204
    assert response.headers["HX-Redirect"].startswith("/sources/")

    source = session.exec(select(Source).where(Source.name == "confluence-eng")).one()
    assert source.type is SourceType.CONFLUENCE
    assert source.connection["base_url"] == "https://example.atlassian.net"
    assert source.connection["spaces"] == ["ENG", "OPS"]
    assert source.connection["email"] == "scanner@example.com"
    # Sealed through the secret store, not stored as typed.
    assert source.credential_ref is not None
    assert "super-secret-api-token" not in str(source.credential_ref)


def test_the_source_form_never_echoes_the_credential_back(
    client: TestClient,
    session: Session,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """#55's acceptance criterion: credential input is never echoed back."""
    headers = login_as(make_user(UserRole.ADMIN))
    client.post(
        "/sources",
        data=CONFLUENCE_FORM | {"csrf_token": headers["X-CSRF-Token"]},
        headers=headers,
    )
    source = session.exec(select(Source).where(Source.name == "confluence-eng")).one()

    list_page = client.get("/sources").text
    detail_page = client.get(f"/sources/{source.id}").text

    for page in (list_page, detail_page):
        assert "super-secret-api-token" not in page
        # Not the sealed ref either: a ref plus a leaked master key is a credential.
        assert str(source.credential_ref) not in page
    assert "stored" in detail_page


def test_a_rejected_source_re_renders_the_form_with_the_reason(
    client: TestClient, make_user: Callable[..., User], login_as: Callable[[User], dict[str, str]]
) -> None:
    """A bad base_url fails on save, and the analyst keeps what they typed."""
    headers = login_as(make_user(UserRole.ADMIN))

    response = client.post(
        "/sources",
        data=CONFLUENCE_FORM | {"csrf_token": headers["X-CSRF-Token"], "base_url": "not-a-url"},
        headers=headers,
    )

    assert response.status_code == 200
    assert "base_url must start with http:// or https://" in response.text
    assert 'id="source-form"' in response.text


def test_a_viewer_cannot_create_a_source_from_the_ui(
    client: TestClient, make_user: Callable[..., User], login_as: Callable[[User], dict[str, str]]
) -> None:
    headers = login_as(make_user(UserRole.VIEWER))

    response = client.post(
        "/sources", data=CONFLUENCE_FORM | {"csrf_token": headers["X-CSRF-Token"]}, headers=headers
    )

    assert response.status_code == 403


def test_editing_a_source_without_a_credential_keeps_the_stored_one(
    client: TestClient,
    session: Session,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    headers = login_as(make_user(UserRole.ADMIN))
    client.post(
        "/sources",
        data=CONFLUENCE_FORM | {"csrf_token": headers["X-CSRF-Token"]},
        headers=headers,
    )
    source = session.exec(select(Source).where(Source.name == "confluence-eng")).one()
    original_ref = source.credential_ref

    response = client.post(
        f"/sources/{source.id}",
        data={
            "csrf_token": headers["X-CSRF-Token"],
            "name": "confluence-eng-renamed",
            "base_url": "https://example.atlassian.net/wiki",
            "email": "scanner@example.com",
            "api_prefix": "",
            "credential": "",
            "enabled": "on",
        },
        headers=headers,
    )

    assert response.status_code == 204
    session.refresh(source)
    assert source.name == "confluence-eng-renamed"
    assert source.credential_ref == original_ref


def test_the_connectivity_check_reports_what_the_probe_said(
    client: TestClient,
    app: FastAPI,
    session: Session,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    headers = login_as(make_user(UserRole.ADMIN))
    client.post(
        "/sources",
        data=CONFLUENCE_FORM | {"csrf_token": headers["X-CSRF-Token"]},
        headers=headers,
    )
    source = session.exec(select(Source).where(Source.name == "confluence-eng")).one()

    async def _reachable(_source: Source, _credential: SecretStr) -> ConnectivityResult:
        return ConnectivityResult(reachable=True, status_code=200, detail="answered as scanner")

    app.dependency_overrides[get_prober] = lambda: _reachable

    response = client.post(f"/sources/{source.id}/test", headers=headers)

    assert response.status_code == 200
    assert "Reachable" in response.text
    assert "answered as scanner" in response.text
    assert "super-secret-api-token" not in response.text


def test_testing_a_source_with_no_credential_says_so_rather_than_500ing(
    client: TestClient,
    make_source: Callable[..., Source],
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    headers = login_as(make_user(UserRole.ADMIN))
    source = make_source()

    response = client.post(f"/sources/{source.id}/test", headers=headers)

    assert response.status_code == 200
    assert "Could not test" in response.text
    assert "no stored credential" in response.text


# ─── #56 Scans ───────────────────────────────────────────────────────────────


@pytest.fixture(name="scan_with_tasks")
def scan_with_tasks_fixture(
    session: Session, make_source: Callable[..., Source]
) -> Callable[..., Scan]:
    """A scan plus two tasks, so the progress bar has something to count."""

    def factory(status: ScanStatus = ScanStatus.RUNNING, finished: int = 1) -> Scan:
        source = make_source()
        scan = Scan(source_id=source.id, trigger=ScanTrigger.MANUAL, status=status)
        session.add(scan)
        session.commit()
        for index in range(2):
            session.add(
                ScanTask(
                    scan_id=scan.id,
                    kind=ScanTaskKind.FETCH,
                    status=(
                        ScanTaskStatus.COMPLETED if index < finished else ScanTaskStatus.RUNNING
                    ),
                    spec={"page_id": f"page-{index}"},
                )
            )
        session.commit()
        return scan

    return factory


def test_launching_a_scan_drives_the_sources_scan_route(
    client: TestClient,
    session: Session,
    make_source: Callable[..., Source],
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
    dispatcher: object,
) -> None:
    """#56's acceptance criterion: launching drives POST /sources/{id}/scan."""
    headers = login_as(make_user(UserRole.ANALYST))
    source = make_source()

    response = client.post(f"/sources/{source.id}/scan", headers=headers)

    assert response.status_code == 204
    scan = session.exec(select(Scan).where(Scan.source_id == source.id)).one()
    assert response.headers["HX-Redirect"] == f"/scans/{scan.id}"
    # One scan, one discovery task, one dispatch (ADR 0009).
    assert len(dispatcher.enqueued) == 1  # type: ignore[attr-defined]


def test_launching_a_scan_on_a_disabled_source_says_so_instead_of_nothing(
    client: TestClient,
    session: Session,
    make_source: Callable[..., Source],
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """The 409 the route deliberately leaves to the error handler has to land.

    Another admin disabling the source between page load and click is the whole
    reason this conflict exists; htmx swaps nothing on a 4xx, so the retargeted
    fragment is what turns it from a dead button into an answer.
    """
    headers = login_as(make_user(UserRole.ANALYST))
    source = make_source()
    source.enabled = False
    session.add(source)
    session.commit()

    response = client.post(f"/sources/{source.id}/scan", headers=headers | {"HX-Request": "true"})

    assert response.status_code == 200
    assert response.headers["HX-Retarget"] == "#hx-error"
    assert "conflicts with the current state" in response.text
    assert "source is disabled" in response.text


def test_a_viewer_cannot_launch_a_scan(
    client: TestClient,
    make_source: Callable[..., Source],
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    headers = login_as(make_user(UserRole.VIEWER))

    response = client.post(f"/sources/{make_source().id}/scan", headers=headers)

    assert response.status_code == 403


def test_a_running_scan_polls_and_shows_task_progress(
    client: TestClient,
    scan_with_tasks: Callable[..., Scan],
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    login_as(make_user(UserRole.VIEWER))
    scan = scan_with_tasks(ScanStatus.RUNNING, finished=1)

    response = client.get(f"/scans/{scan.id}")

    assert response.status_code == 200
    assert f'hx-get="/scans/{scan.id}/status"' in response.text
    assert 'hx-trigger="every 3s"' in response.text
    assert 'aria-valuenow="50"' in response.text
    assert "1 of 2 task(s) finished" in response.text


def test_a_finished_scan_stops_polling(
    client: TestClient,
    scan_with_tasks: Callable[..., Scan],
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """The terminal fragment carries no trigger, so the browser stops asking."""
    login_as(make_user(UserRole.VIEWER))
    scan = scan_with_tasks(ScanStatus.COMPLETED, finished=2)

    response = client.get(f"/scans/{scan.id}/status")

    assert response.status_code == 200
    assert "hx-trigger" not in response.text
    assert 'aria-valuenow="100"' in response.text


def test_cancelling_a_scan_drives_the_cancel_route(
    client: TestClient,
    session: Session,
    scan_with_tasks: Callable[..., Scan],
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    headers = login_as(make_user(UserRole.ANALYST))
    scan = scan_with_tasks(ScanStatus.RUNNING, finished=0)

    response = client.post(f"/scans/{scan.id}/cancel", headers=headers)

    assert response.status_code == 200
    session.refresh(scan)
    assert scan.status is ScanStatus.CANCELLED
    assert "cancelled" in response.text


def test_cancelling_a_finished_scan_says_so_instead_of_erroring(
    client: TestClient,
    scan_with_tasks: Callable[..., Scan],
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    headers = login_as(make_user(UserRole.ANALYST))
    scan = scan_with_tasks(ScanStatus.COMPLETED, finished=2)

    response = client.post(f"/scans/{scan.id}/cancel", headers=headers)

    assert response.status_code == 200
    assert "Nothing to cancel" in response.text


# ─── #57 Findings ────────────────────────────────────────────────────────────


def test_the_findings_table_applies_only_the_filters_in_the_url(
    client: TestClient,
    make_finding: Callable[..., Finding],
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    login_as(make_user(UserRole.VIEWER))
    critical = make_finding(severity=Severity.CRITICAL, rule_id="aws-access-key")
    low = make_finding(severity=Severity.LOW, rule_id="generic-password")

    filtered = client.get("/findings?severity=critical").text
    unfiltered = client.get("/findings").text

    assert str(critical.id) in filtered
    assert str(low.id) not in filtered
    assert str(critical.id) in unfiltered and str(low.id) in unfiltered


def test_the_finding_detail_shows_the_redacted_snippet_and_no_hash(
    client: TestClient,
    make_finding: Callable[..., Finding],
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """#57: no plaintext shown — and nothing derived from the secret either."""
    login_as(make_user(UserRole.VIEWER))
    finding = make_finding(redacted_snippet="AKIA****************WXYZ", secret_hash="a" * 64)

    response = client.get(f"/findings/{finding.id}")

    assert response.status_code == 200
    assert "AKIA****************WXYZ" in response.text
    assert "a" * 64 not in response.text


def test_a_hostile_snippet_is_escaped_not_executed(
    client: TestClient,
    make_finding: Callable[..., Finding],
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """The snippet came out of somebody else's Confluence. Autoescaping is the
    reason this page is not a stored-XSS delivery mechanism."""
    login_as(make_user(UserRole.VIEWER))
    finding = make_finding(
        redacted_snippet="<img src=x onerror=alert(1)>",
        resource_locator={"path": "<script>alert('locator')</script>"},
    )

    body = client.get(f"/findings/{finding.id}").text

    assert "<img src=x onerror=alert(1)>" not in body
    assert "&lt;img src=x onerror=alert(1)&gt;" in body
    assert "<script>alert('locator')</script>" not in body


def test_triage_updates_the_finding_and_renders_its_new_history(
    client: TestClient,
    session: Session,
    make_finding: Callable[..., Finding],
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """#57's acceptance criterion, end to end."""
    analyst = make_user(UserRole.ANALYST)
    headers = login_as(analyst)
    finding = make_finding()

    response = client.post(
        f"/findings/{finding.id}/triage",
        data={
            "csrf_token": headers["X-CSRF-Token"],
            "state": FindingState.FALSE_POSITIVE.value,
            "comment": "Example credential in the onboarding guide",
            "assignee": "none",
        },
        headers=headers,
    )

    assert response.status_code == 200
    session.refresh(finding)
    assert finding.state is FindingState.FALSE_POSITIVE

    events = session.exec(select(FindingEvent).where(FindingEvent.finding_id == finding.id)).all()
    kinds = {event.kind for event in events}
    assert FindingEventKind.STATE_CHANGE in kinds
    # The history is rendered with the change that produced it.
    assert "Example credential in the onboarding guide" in response.text
    assert analyst.display_name in response.text
    assert "False positive" in response.text


def test_an_illegal_transition_is_refused_with_its_reason_and_changes_nothing(
    client: TestClient,
    session: Session,
    make_finding: Callable[..., Finding],
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """Judgement → judgement is a 409, and the assignee must not move either."""
    analyst = make_user(UserRole.ANALYST)
    headers = login_as(analyst)
    finding = make_finding(state=FindingState.FALSE_POSITIVE)

    response = client.post(
        f"/findings/{finding.id}/triage",
        data={
            "csrf_token": headers["X-CSRF-Token"],
            "state": FindingState.ACCEPTED_RISK.value,
            "assignee": str(analyst.id),
        },
        headers=headers,
    )

    assert response.status_code == 200
    assert "Not applied" in response.text
    session.refresh(finding)
    assert finding.state is FindingState.FALSE_POSITIVE
    assert finding.assignee_id is None


def test_an_unrecognised_state_re_renders_the_panel_rather_than_500ing(
    client: TestClient,
    session: Session,
    make_finding: Callable[..., Finding],
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """A stale form or a crafted post is a refused decision, not a crash."""
    headers = login_as(make_user(UserRole.ANALYST))
    finding = make_finding()

    response = client.post(
        f"/findings/{finding.id}/triage",
        data={"csrf_token": headers["X-CSRF-Token"], "state": "not-a-state"},
        headers=headers,
    )

    assert response.status_code == 200
    assert "Not applied" in response.text
    assert 'id="triage"' in response.text
    session.refresh(finding)
    assert finding.state is FindingState.OPEN


def test_a_viewer_sees_the_history_but_is_offered_no_triage_form(
    client: TestClient,
    make_finding: Callable[..., Finding],
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    login_as(make_user(UserRole.VIEWER))
    finding = make_finding()

    body = client.get(f"/findings/{finding.id}").text

    assert "History" in body
    assert 'hx-post="/findings/' not in body
    assert "has to have a name attached to it" in body


def test_a_viewer_cannot_triage(
    client: TestClient,
    make_finding: Callable[..., Finding],
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    headers = login_as(make_user(UserRole.VIEWER))
    finding = make_finding()

    response = client.post(
        f"/findings/{finding.id}/triage",
        data={"csrf_token": headers["X-CSRF-Token"], "state": FindingState.RESOLVED.value},
        headers=headers,
    )

    assert response.status_code == 403


# ─── #58 Suppressions, schedules, engines ────────────────────────────────────


def test_creating_a_suppression_hides_the_findings_it_already_covers(
    client: TestClient,
    session: Session,
    make_finding: Callable[..., Finding],
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    headers = login_as(make_user(UserRole.ANALYST))
    finding = make_finding(rule_id="generic-password")

    response = client.post(
        "/suppressions",
        data={
            "csrf_token": headers["X-CSRF-Token"],
            "scope": "rule",
            "pattern": "generic-password",
            "reason": "Placeholder values in the onboarding guide",
            "source_id": "",
        },
        headers=headers,
    )

    assert response.status_code == 204
    session.refresh(finding)
    assert finding.suppressed_at is not None
    assert session.exec(select(Suppression)).one().reason.startswith("Placeholder")


def test_a_suppression_without_a_reason_is_refused_with_the_reason_why(
    client: TestClient, make_user: Callable[..., User], login_as: Callable[[User], dict[str, str]]
) -> None:
    headers = login_as(make_user(UserRole.ANALYST))

    response = client.post(
        "/suppressions",
        data={
            "csrf_token": headers["X-CSRF-Token"],
            "scope": "rule",
            "pattern": "generic-password",
            "reason": "   ",
        },
        headers=headers,
    )

    assert response.status_code == 204
    assert "error=" in response.headers["HX-Redirect"]


def test_an_unparseable_expiry_comes_back_as_the_sentence_the_route_wrote(
    client: TestClient, make_user: Callable[..., User], login_as: Callable[[User], dict[str, str]]
) -> None:
    """`_expiry` authors its own copy; a generic fallback would discard it."""
    headers = login_as(make_user(UserRole.ANALYST))

    response = client.post(
        "/suppressions",
        data={
            "csrf_token": headers["X-CSRF-Token"],
            "scope": "rule",
            "pattern": "generic-password",
            "reason": "Placeholder values",
            "expires_at": "next tuesday",
        },
        headers=headers,
    )

    assert response.status_code == 204
    assert "expires_at%20must%20be%20a%20date%20and%20time" in response.headers["HX-Redirect"]


def test_the_suppressions_pager_carries_the_filters_that_built_the_page(
    client: TestClient,
    session: Session,
    make_source: Callable[..., Source],
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """The cursor is a position in the *filtered* keyset.

    Resuming it against the unfiltered listing is not "the same list, page two" —
    it skips rows and silently drops the filter the analyst is reading by.
    """
    login_as(make_user(UserRole.ANALYST))
    source = make_source()
    for index in range(DEFAULT_LIMIT + 1):
        session.add(
            Suppression(
                scope=SuppressionScope.RULE,
                pattern=f"rule-{index}",
                source_id=source.id,
                reason="Placeholder values",
            )
        )
    session.commit()

    body = client.get(f"/suppressions?source_id={source.id}&scope=rule&active=true").text

    pager = re.search(r'href="(/suppressions\?cursor=[^"]*)"', body)
    assert pager is not None, "no next-page link rendered"
    assert f"source_id={source.id}" in pager.group(1)
    assert "scope=rule" in pager.group(1)
    assert "active=true" in pager.group(1)


def test_deleting_a_suppression_releases_what_it_was_hiding(
    client: TestClient,
    session: Session,
    make_finding: Callable[..., Finding],
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    headers = login_as(make_user(UserRole.ANALYST))
    finding = make_finding(rule_id="generic-password")
    client.post(
        "/suppressions",
        data={
            "csrf_token": headers["X-CSRF-Token"],
            "scope": "rule",
            "pattern": "generic-password",
            "reason": "Placeholder values",
        },
        headers=headers,
    )
    suppression = session.exec(select(Suppression)).one()

    response = client.request("DELETE", f"/suppressions/{suppression.id}", headers=headers)

    assert response.status_code == 204
    session.refresh(finding)
    assert finding.suppressed_at is None


def test_a_viewer_cannot_create_a_suppression(
    client: TestClient, make_user: Callable[..., User], login_as: Callable[[User], dict[str, str]]
) -> None:
    headers = login_as(make_user(UserRole.VIEWER))

    response = client.post(
        "/suppressions",
        data={
            "csrf_token": headers["X-CSRF-Token"],
            "scope": "rule",
            "pattern": "x",
            "reason": "y",
        },
        headers=headers,
    )

    assert response.status_code == 403


def test_creating_a_schedule_computes_its_next_run(
    client: TestClient,
    session: Session,
    make_source: Callable[..., Source],
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    headers = login_as(make_user(UserRole.ADMIN))
    source = make_source()

    response = client.post(
        "/schedules",
        data={
            "csrf_token": headers["X-CSRF-Token"],
            "source_id": str(source.id),
            "cron": "0 3 * * *",
            "enabled": "on",
        },
        headers=headers,
    )

    assert response.status_code == 204
    from iceberg_core.models import Schedule

    schedule = session.exec(select(Schedule)).one()
    assert schedule.cron == "0 3 * * *"
    assert schedule.next_run_at is not None


def test_an_invalid_cron_is_refused_with_an_explanation(
    client: TestClient,
    make_source: Callable[..., Source],
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    headers = login_as(make_user(UserRole.ADMIN))

    response = client.post(
        "/schedules",
        data={
            "csrf_token": headers["X-CSRF-Token"],
            "source_id": str(make_source().id),
            "cron": "not a cron",
        },
        headers=headers,
    )

    assert response.status_code == 204
    assert "cron" in response.headers["HX-Redirect"]


@pytest.mark.parametrize("source_id", ["", "not-a-uuid"])
def test_a_schedule_with_no_source_says_which_choice_is_missing(
    client: TestClient,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
    source_id: str,
) -> None:
    """`create_schedule` raises a bare ValueError with copy meant to be read."""
    headers = login_as(make_user(UserRole.ADMIN))

    response = client.post(
        "/schedules",
        data={"csrf_token": headers["X-CSRF-Token"], "source_id": source_id, "cron": "0 3 * * *"},
        headers=headers,
    )

    assert response.status_code == 204, response.text
    assert "choose%20a%20source" in response.headers["HX-Redirect"]


def test_the_schedules_pager_carries_the_source_filter(
    client: TestClient,
    session: Session,
    make_source: Callable[..., Source],
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    login_as(make_user(UserRole.VIEWER))
    source = make_source()
    for _ in range(DEFAULT_LIMIT + 1):
        session.add(Schedule(source_id=source.id, cron="0 3 * * *"))
    session.commit()

    body = client.get(f"/schedules?source_id={source.id}").text

    pager = re.search(r'href="(/schedules\?cursor=[^"]*)"', body)
    assert pager is not None, "no next-page link rendered"
    assert f"source_id={source.id}" in pager.group(1)


def test_the_engine_dashboard_shows_heartbeat_and_status(
    client: TestClient,
    session: Session,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """#58's acceptance criterion for the fleet view."""
    login_as(make_user(UserRole.ADMIN))
    session.add(Engine(name="engine-1", token_hash="hashed", version="0.2.0"))
    session.commit()

    body = client.get("/engines").text

    assert "engine-1" in body
    assert "0.2.0" in body
    # No heartbeat yet, and the page says so rather than showing a blank.
    assert "never" in body
    assert "offline" in body or "active" in body


def test_enrolling_an_engine_shows_the_token_exactly_once(
    client: TestClient,
    session: Session,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    headers = login_as(make_user(UserRole.ADMIN))

    response = client.post(
        "/engines/register",
        data={"csrf_token": headers["X-CSRF-Token"], "name": "engine-7"},
        headers=headers,
    )

    assert response.status_code == 200
    assert "it is not shown again" in response.text

    engine = session.exec(select(Engine).where(Engine.name == "engine-7")).one()
    # Only a hash is stored, and reloading the page cannot show the token again.
    assert engine.token_hash
    assert engine.token_hash not in response.text
    assert "not shown again" not in client.get("/engines").text


def test_the_engine_screen_never_renders_token_material(
    client: TestClient,
    session: Session,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    login_as(make_user(UserRole.ADMIN))
    engine = Engine(name="engine-2", token_hash="a-stored-hash", version="0.1.0")
    session.add(engine)
    session.commit()

    body = client.get("/engines").text

    assert "a-stored-hash" not in body


# ─── #72 Notification channels & users ───────────────────────────────────────


def test_creating_a_webhook_channel_seals_its_secret(
    client: TestClient,
    session: Session,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    headers = login_as(make_user(UserRole.ADMIN))

    response = client.post(
        "/channels",
        data={
            "csrf_token": headers["X-CSRF-Token"],
            "name": "security-alerts",
            "type": "webhook",
            "url": "https://chat.example.com/hooks/abc",
            "secret": "webhook-signing-secret",
            "min_severity": "high",
            "enabled": "on",
        },
        headers=headers,
    )

    assert response.status_code == 204
    channel = session.exec(select(NotificationChannel)).one()
    assert channel.type is NotificationChannelType.WEBHOOK
    assert channel.config["url"] == "https://chat.example.com/hooks/abc"
    assert channel.event_filter["min_severity"] == "high"
    assert channel.config["secret_ref"]
    assert "webhook-signing-secret" not in str(channel.config)


def test_the_channels_screen_never_renders_the_secret_or_its_ref(
    client: TestClient,
    session: Session,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """#72's acceptance criterion: webhook config is never echoed."""
    headers = login_as(make_user(UserRole.ADMIN))
    client.post(
        "/channels",
        data={
            "csrf_token": headers["X-CSRF-Token"],
            "name": "security-alerts",
            "type": "webhook",
            "url": "https://chat.example.com/hooks/abc",
            "secret": "webhook-signing-secret",
        },
        headers=headers,
    )
    channel = session.exec(select(NotificationChannel)).one()

    body = client.get("/channels").text

    assert "webhook-signing-secret" not in body
    assert str(channel.config["secret_ref"]) not in body
    assert "sealed" in body


@pytest.mark.parametrize("role", [UserRole.VIEWER, UserRole.ANALYST])
def test_only_an_admin_reaches_the_channels_screen(
    client: TestClient,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
    role: UserRole,
) -> None:
    headers = login_as(make_user(role))

    assert client.get("/channels").status_code == 403
    assert (
        client.post(
            "/channels",
            data={
                "csrf_token": headers["X-CSRF-Token"],
                "name": "x",
                "type": "webhook",
                "url": "https://example.com/hook",
            },
            headers=headers,
        ).status_code
        == 403
    )


def test_a_channel_is_created_and_deleted_but_never_edited(
    client: TestClient,
    session: Session,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """The screen offers no edit, so no route answers one.

    An unreachable handler is untested behaviour that rots — the "blank secret
    keeps the sealed one" rule in particular, which nothing on this page exercises.
    """
    headers = login_as(make_user(UserRole.ADMIN))
    client.post(
        "/channels",
        data={
            "csrf_token": headers["X-CSRF-Token"],
            "name": "security-alerts",
            "type": "webhook",
            "url": "https://chat.example.com/hooks/abc",
        },
        headers=headers,
    )
    channel = session.exec(select(NotificationChannel)).one()

    response = client.post(
        f"/channels/{channel.id}",
        data={"csrf_token": headers["X-CSRF-Token"], "name": "renamed", "type": "webhook"},
        headers=headers,
    )

    assert response.status_code == 405
    assert "edit it after saving" not in client.get("/channels").text


def test_deleting_a_channel_is_audited(
    client: TestClient,
    session: Session,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    from iceberg_core.models import AuditEvent

    headers = login_as(make_user(UserRole.ADMIN))
    client.post(
        "/channels",
        data={
            "csrf_token": headers["X-CSRF-Token"],
            "name": "security-alerts",
            "type": "webhook",
            "url": "https://chat.example.com/hooks/abc",
        },
        headers=headers,
    )
    channel = session.exec(select(NotificationChannel)).one()

    response = client.request("DELETE", f"/channels/{channel.id}", headers=headers)

    assert response.status_code == 204
    actions = {
        event.action
        for event in session.exec(
            select(AuditEvent).where(AuditEvent.target_type == AUDIT_TARGET_CHANNEL)
        )
    }
    assert actions == {"channel.created", "channel.deleted"}


def test_assigning_a_role_from_the_ui_lands_and_is_audited(
    client: TestClient,
    session: Session,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """#72's acceptance criterion for user management."""
    from iceberg_core.models import AuditEvent

    headers = login_as(make_user(UserRole.ADMIN))
    target = make_user(UserRole.VIEWER)

    response = client.post(
        f"/users/{target.id}",
        data={"csrf_token": headers["X-CSRF-Token"], "role": "analyst"},
        headers=headers,
    )

    assert response.status_code == 204
    session.refresh(target)
    assert target.role is UserRole.ANALYST

    events = session.exec(
        select(AuditEvent)
        .where(AuditEvent.target_type == AUDIT_TARGET_USER)
        .where(AuditEvent.target_id == target.id)
    ).all()
    assert [event.action for event in events] == ["user.role_changed"]
    assert events[0].from_value == "viewer"
    assert events[0].to_value == "analyst"


def test_an_admin_cannot_change_their_own_account_from_the_ui(
    client: TestClient, make_user: Callable[..., User], login_as: Callable[[User], dict[str, str]]
) -> None:
    admin = make_user(UserRole.ADMIN)
    headers = login_as(admin)

    listing = client.get("/users").text
    response = client.post(
        f"/users/{admin.id}",
        data={"csrf_token": headers["X-CSRF-Token"], "role": "viewer"},
        headers=headers,
    )

    assert "that is you" in listing
    assert response.status_code == 204
    assert "error=" in response.headers["HX-Redirect"]


def test_the_last_admin_cannot_be_demoted_from_the_ui(
    client: TestClient,
    session: Session,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """Two admins demoting each other must not end with zero."""
    first = make_user(UserRole.ADMIN)
    second = make_user(UserRole.ADMIN)
    headers = login_as(first)

    client.post(
        f"/users/{second.id}",
        data={"csrf_token": headers["X-CSRF-Token"], "role": "viewer"},
        headers=headers,
    )
    session.refresh(second)
    assert second.role is UserRole.VIEWER

    # `first` is now the only admin, and nobody else can demote them.
    headers = login_as(second)
    response = client.post(
        f"/users/{first.id}",
        data={"csrf_token": headers["X-CSRF-Token"], "role": "viewer"},
        headers=headers,
    )
    assert response.status_code == 403


def test_a_mutation_without_a_csrf_token_is_refused(
    client: TestClient,
    make_source: Callable[..., Source],
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """Cookie auth means the browser attaches credentials cross-site by itself."""
    login_as(make_user(UserRole.ANALYST))

    response = client.post(f"/sources/{make_source().id}/scan")

    assert response.status_code == 403


def test_an_unknown_record_renders_a_page_not_a_json_body(
    client: TestClient, make_user: Callable[..., User], login_as: Callable[[User], dict[str, str]]
) -> None:
    login_as(make_user(UserRole.VIEWER))

    response = client.get(f"/findings/{uuid.uuid4()}")

    assert response.status_code == 404
    assert response.headers["content-type"].startswith("text/html")
    assert "Not found" in response.text
