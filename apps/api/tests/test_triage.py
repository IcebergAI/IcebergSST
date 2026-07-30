"""The triage state machine and its audit trail (#39).

Two properties carry the epic: an illegal transition is refused, and every legal
change leaves a `FindingEvent` behind. A triage decision nobody can trace back to a
person is the failure mode this whole surface exists to prevent.
"""

from collections.abc import Callable

import pytest
from fastapi.testclient import TestClient
from iceberg_api.scans.reconcile import reconcile_scan
from iceberg_core.enums import (
    FindingResolution,
    FindingState,
    ScanStatus,
    ScanTaskKind,
    ScanTaskStatus,
    ScanTrigger,
    UserRole,
)
from iceberg_core.models import Finding, FindingEvent, Scan, ScanTask, Source, User
from sqlmodel import Session, col, select

FINDINGS = "/api/v1/findings"


def _events(session: Session, finding: Finding) -> list[FindingEvent]:
    return list(
        session.exec(
            select(FindingEvent)
            .where(col(FindingEvent.finding_id) == finding.id)
            .order_by(col(FindingEvent.created_at), col(FindingEvent.id))
        )
    )


@pytest.mark.parametrize("target", ["false_positive", "accepted_risk", "resolved"])
def test_an_open_finding_can_be_moved_to_any_judgement(
    target: str,
    client: TestClient,
    session: Session,
    make_finding: Callable[..., Finding],
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    analyst = make_user(UserRole.ANALYST)
    headers = login_as(analyst)
    finding = make_finding()

    response = client.patch(
        f"{FINDINGS}/{finding.id}",
        json={"state": target, "comment": "rotated in Vault"},
        headers=headers,
    )

    assert response.status_code == 200
    assert response.json()["state"] == target
    session.refresh(finding)
    assert finding.state.value == target

    event = _events(session, finding)[-1]
    assert (event.kind.value, event.from_value, event.to_value) == (
        "state_change",
        "open",
        target,
    )
    assert event.actor_id == analyst.id
    assert event.comment == "rotated in Vault"


def test_a_judgement_cannot_be_relabelled_in_place(
    client: TestClient,
    session: Session,
    make_finding: Callable[..., Finding],
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """All roads back through `open`: false_positive → resolved is refused."""
    headers = login_as(make_user(UserRole.ANALYST))
    finding = make_finding(state=FindingState.FALSE_POSITIVE)

    response = client.patch(f"{FINDINGS}/{finding.id}", json={"state": "resolved"}, headers=headers)

    assert response.status_code == 409
    assert "reopen it first" in response.json()["detail"]
    session.refresh(finding)
    assert finding.state is FindingState.FALSE_POSITIVE
    assert _events(session, finding) == []


def test_a_rejected_transition_applies_nothing_else_either(
    client: TestClient,
    session: Session,
    make_finding: Callable[..., Finding],
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """A PATCH is one change: the assignee must not survive a refused transition."""
    analyst = make_user(UserRole.ANALYST)
    headers = login_as(analyst)
    finding = make_finding(state=FindingState.ACCEPTED_RISK)

    response = client.patch(
        f"{FINDINGS}/{finding.id}",
        json={"state": "resolved", "assignee_id": str(analyst.id)},
        headers=headers,
    )

    assert response.status_code == 409
    session.refresh(finding)
    assert finding.assignee_id is None


def test_reopening_clears_an_automatic_resolution(
    client: TestClient,
    session: Session,
    make_finding: Callable[..., Finding],
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """`resolution` says who resolved it, so an open finding must not keep one."""
    headers = login_as(make_user(UserRole.ANALYST))
    finding = make_finding(state=FindingState.RESOLVED, resolution=FindingResolution.AUTO)

    body = client.patch(f"{FINDINGS}/{finding.id}", json={"state": "open"}, headers=headers).json()

    assert body["state"] == "open"
    assert body["resolution"] is None
    session.refresh(finding)
    assert finding.resolution is None
    assert _events(session, finding)[-1].kind.value == "reopened"


def test_resolving_by_hand_records_a_manual_resolution(
    client: TestClient,
    session: Session,
    make_finding: Callable[..., Finding],
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    headers = login_as(make_user(UserRole.ANALYST))
    finding = make_finding()

    client.patch(f"{FINDINGS}/{finding.id}", json={"state": "resolved"}, headers=headers)

    session.refresh(finding)
    assert finding.resolution is FindingResolution.MANUAL


def test_restating_the_current_state_is_a_no_op(
    client: TestClient,
    session: Session,
    make_finding: Callable[..., Finding],
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """A retried request is not an error, and "open → open" is not an audit entry."""
    headers = login_as(make_user(UserRole.ANALYST))
    finding = make_finding()

    response = client.patch(f"{FINDINGS}/{finding.id}", json={"state": "open"}, headers=headers)

    assert response.status_code == 200
    assert _events(session, finding) == []


def test_assigning_and_unassigning_are_both_audited(
    client: TestClient,
    session: Session,
    make_finding: Callable[..., Finding],
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """`null` unassigns; an omitted field leaves the assignee alone."""
    analyst = make_user(UserRole.ANALYST)
    owner = make_user(UserRole.ANALYST)
    headers = login_as(analyst)
    finding = make_finding()

    client.patch(f"{FINDINGS}/{finding.id}", json={"assignee_id": str(owner.id)}, headers=headers)
    client.patch(f"{FINDINGS}/{finding.id}", json={"notes": "chasing"}, headers=headers)
    client.patch(f"{FINDINGS}/{finding.id}", json={"assignee_id": None}, headers=headers)

    session.refresh(finding)
    assert finding.assignee_id is None
    assert finding.notes == "chasing"

    assigns = [event for event in _events(session, finding) if event.kind.value == "assign"]
    assert [(event.from_value, event.to_value) for event in assigns] == [
        (None, str(owner.id)),
        (str(owner.id), None),
    ]


def test_a_note_is_kept_in_the_trail_not_just_overwritten(
    client: TestClient,
    session: Session,
    make_finding: Callable[..., Finding],
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """`notes` is edited in place, so the previous text only survives as an event."""
    headers = login_as(make_user(UserRole.ANALYST))
    finding = make_finding()

    client.patch(f"{FINDINGS}/{finding.id}", json={"notes": "asked the owner"}, headers=headers)
    body = client.patch(
        f"{FINDINGS}/{finding.id}", json={"notes": "owner rotated it"}, headers=headers
    ).json()

    assert body["notes"] == "owner rotated it"
    comments = [event["comment"] for event in body["events"] if event["kind"] == "comment"]
    assert comments == ["asked the owner", "owner rotated it"]


def test_an_unknown_or_disabled_assignee_is_refused(
    client: TestClient,
    make_finding: Callable[..., Finding],
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """Assigning work to a disabled account is a quiet way to lose a finding."""
    headers = login_as(make_user(UserRole.ANALYST))
    finding = make_finding()
    disabled = make_user(UserRole.ANALYST, disabled=True)

    unknown = client.patch(
        f"{FINDINGS}/{finding.id}",
        json={"assignee_id": "00000000-0000-0000-0000-000000000000"},
        headers=headers,
    )
    inactive = client.patch(
        f"{FINDINGS}/{finding.id}", json={"assignee_id": str(disabled.id)}, headers=headers
    )

    assert unknown.status_code == 422
    assert inactive.status_code == 422


def test_a_viewer_may_not_triage(
    client: TestClient,
    make_finding: Callable[..., Finding],
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """Reading the queue and deciding a secret is benign are different privileges."""
    headers = login_as(make_user(UserRole.VIEWER))
    finding = make_finding()

    response = client.patch(
        f"{FINDINGS}/{finding.id}", json={"state": "false_positive"}, headers=headers
    )

    assert response.status_code == 403


def test_triage_requires_a_csrf_token(
    client: TestClient,
    make_finding: Callable[..., Finding],
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    login_as(make_user(UserRole.ANALYST))
    finding = make_finding()

    response = client.patch(f"{FINDINGS}/{finding.id}", json={"state": "resolved"})

    assert response.status_code == 403


def test_triage_survives_a_rescan(
    client: TestClient,
    session: Session,
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """An analyst's judgement outlives the scan that found the secret.

    Reconciliation auto-resolves only findings still ``open``, which is what makes
    "this is a false positive" a decision rather than a note that lasts a week.
    """
    headers = login_as(make_user(UserRole.ANALYST))
    source = make_source()
    judged = make_finding(source)
    accepted = make_finding(source)
    untouched = make_finding(source)
    client.patch(f"{FINDINGS}/{judged.id}", json={"state": "false_positive"}, headers=headers)
    client.patch(f"{FINDINGS}/{accepted.id}", json={"state": "accepted_risk"}, headers=headers)

    # A later scan of the same source that saw none of them.
    later = Scan(source_id=source.id, trigger=ScanTrigger.MANUAL, status=ScanStatus.COMPLETED)
    session.add(later)
    session.commit()
    session.add(
        ScanTask(
            scan_id=later.id,
            kind=ScanTaskKind.FETCH,
            status=ScanTaskStatus.COMPLETED,
            spec={},
        )
    )
    session.commit()

    reconcile_scan(session, later)

    for finding in (judged, accepted, untouched):
        session.refresh(finding)
    assert judged.state is FindingState.FALSE_POSITIVE
    assert accepted.state is FindingState.ACCEPTED_RISK
    # The one still open was fair game, and its resolution says a scan did it.
    assert untouched.state is FindingState.RESOLVED
    assert untouched.resolution is FindingResolution.AUTO
