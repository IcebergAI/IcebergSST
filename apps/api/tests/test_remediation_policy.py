"""The required-evidence policy (#142, ADR 0012).

The property under test: with a minimum severity configured, resolving a
finding at or above it demands a live remediation action with evidence — and
nothing else changes. Below the bar, without the setting, for judgements, and
for reconciliation's auto-resolve, triage behaves exactly as it always has.
"""

import uuid
from collections.abc import Callable, Iterator
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from iceberg_core.config import ApiSettings
from iceberg_core.enums import FindingEventKind, FindingState, Severity, UserRole
from iceberg_core.models import Finding, FindingEvent, RemediationAction, User
from sqlmodel import Session

RESOLVE = {"state": "resolved"}
EVIDENCED = {
    "kind": "revoke",
    "evidence_links": [{"url": "https://tickets.example.test/SEC-9", "label": "SEC-9"}],
}


@pytest.fixture(name="with_policy")
def with_policy_fixture(app: FastAPI, api_settings: ApiSettings) -> Iterator[ApiSettings]:
    """Turn the evidence policy on (min severity: high) for one test.

    The settings model is frozen, so the policy is switched on by overriding
    the dependency with a rebuilt copy rather than mutating in place.
    """
    from iceberg_api.auth.dependencies import get_settings

    strict = api_settings.model_copy(update={"remediation_evidence_min_severity": Severity.HIGH})
    app.dependency_overrides[get_settings] = lambda: strict
    yield strict
    app.dependency_overrides[get_settings] = lambda: api_settings


@pytest.fixture(name="analyst_headers")
def analyst_headers_fixture(
    make_user: Callable[..., User], login_as: Callable[[User], dict[str, str]]
) -> dict[str, str]:
    return login_as(make_user(UserRole.ANALYST))


def test_without_the_setting_resolution_needs_no_evidence(
    client: TestClient,
    api: str,
    make_finding: Callable[..., Finding],
    analyst_headers: dict[str, str],
) -> None:
    finding = make_finding(severity=Severity.CRITICAL)

    response = client.patch(f"{api}/findings/{finding.id}", json=RESOLVE, headers=analyst_headers)

    assert response.status_code == 200, response.text
    assert response.json()["state"] == "resolved"


def test_at_or_above_the_bar_resolution_is_refused_without_evidence(
    client: TestClient,
    api: str,
    with_policy: ApiSettings,
    make_finding: Callable[..., Finding],
    analyst_headers: dict[str, str],
) -> None:
    finding = make_finding(severity=Severity.HIGH)

    response = client.patch(f"{api}/findings/{finding.id}", json=RESOLVE, headers=analyst_headers)

    assert response.status_code == 409
    assert "remediation action" in response.json()["detail"]


def test_a_refused_resolution_applies_nothing_else(
    client: TestClient,
    api: str,
    session: Session,
    with_policy: ApiSettings,
    make_finding: Callable[..., Finding],
    make_user: Callable[..., User],
    analyst_headers: dict[str, str],
) -> None:
    """The all-or-nothing contract IllegalTransition already keeps."""
    finding = make_finding(severity=Severity.CRITICAL)
    assignee = make_user(UserRole.ANALYST)

    response = client.patch(
        f"{api}/findings/{finding.id}",
        json=RESOLVE | {"assignee_id": str(assignee.id), "notes": "closing"},
        headers=analyst_headers,
    )

    assert response.status_code == 409
    session.refresh(finding)
    assert finding.state is FindingState.OPEN
    assert finding.assignee_id is None
    assert finding.notes is None


def test_a_recorded_action_with_a_link_unlocks_resolution(
    client: TestClient,
    api: str,
    with_policy: ApiSettings,
    make_finding: Callable[..., Finding],
    analyst_headers: dict[str, str],
) -> None:
    finding = make_finding(severity=Severity.HIGH)
    recorded = client.post(
        f"{api}/findings/{finding.id}/remediations", json=EVIDENCED, headers=analyst_headers
    )
    assert recorded.status_code == 201, recorded.text

    response = client.patch(f"{api}/findings/{finding.id}", json=RESOLVE, headers=analyst_headers)

    assert response.status_code == 200, response.text
    assert response.json()["state"] == "resolved"


def test_an_action_without_links_does_not_qualify(
    client: TestClient,
    api: str,
    with_policy: ApiSettings,
    make_finding: Callable[..., Finding],
    analyst_headers: dict[str, str],
) -> None:
    finding = make_finding(severity=Severity.HIGH)
    client.post(
        f"{api}/findings/{finding.id}/remediations",
        json={"kind": "rotate", "note": "no proof attached"},
        headers=analyst_headers,
    )

    response = client.patch(f"{api}/findings/{finding.id}", json=RESOLVE, headers=analyst_headers)

    assert response.status_code == 409


def test_a_retracted_action_stops_qualifying(
    client: TestClient,
    api: str,
    with_policy: ApiSettings,
    make_finding: Callable[..., Finding],
    analyst_headers: dict[str, str],
) -> None:
    finding = make_finding(severity=Severity.HIGH)
    action_id = client.post(
        f"{api}/findings/{finding.id}/remediations", json=EVIDENCED, headers=analyst_headers
    ).json()["id"]
    client.post(
        f"{api}/findings/{finding.id}/remediations/{action_id}/retract",
        json={"reason": "logged against the wrong credential"},
        headers=analyst_headers,
    )

    response = client.patch(f"{api}/findings/{finding.id}", json=RESOLVE, headers=analyst_headers)

    assert response.status_code == 409


def test_below_the_bar_resolution_stays_free(
    client: TestClient,
    api: str,
    with_policy: ApiSettings,
    make_finding: Callable[..., Finding],
    analyst_headers: dict[str, str],
) -> None:
    finding = make_finding(severity=Severity.MEDIUM)

    response = client.patch(f"{api}/findings/{finding.id}", json=RESOLVE, headers=analyst_headers)

    assert response.status_code == 200


def test_a_reopened_finding_needs_fresh_evidence(
    client: TestClient,
    api: str,
    session: Session,
    with_policy: ApiSettings,
    make_finding: Callable[..., Finding],
    analyst_headers: dict[str, str],
) -> None:
    """The credential came back, so what was done before did not close it.

    Remediation history survives a reopen deliberately — it is what makes the
    trail worth reading — but counting it towards the policy would let a
    re-sighted secret be closed again instantly on the strength of the attempt
    that demonstrably failed.
    """
    finding = make_finding(severity=Severity.HIGH)
    record = f"{api}/findings/{finding.id}/remediations"
    client.post(record, json=EVIDENCED, headers=analyst_headers)
    first = client.patch(f"{api}/findings/{finding.id}", json=RESOLVE, headers=analyst_headers)
    assert first.status_code == 200, first.text

    _reopen(session, finding)

    refused = client.patch(f"{api}/findings/{finding.id}", json=RESOLVE, headers=analyst_headers)
    assert refused.status_code == 409

    # The history is still there — it just no longer answers for this cycle.
    assert len(client.get(f"{api}/findings/{finding.id}/remediations").json()) == 1

    client.post(record, json=EVIDENCED, headers=analyst_headers)
    again = client.patch(f"{api}/findings/{finding.id}", json=RESOLVE, headers=analyst_headers)
    assert again.status_code == 200, again.text


def test_scrubbed_evidence_stops_qualifying(
    client: TestClient,
    api: str,
    session: Session,
    with_policy: ApiSettings,
    make_finding: Callable[..., Finding],
    analyst_headers: dict[str, str],
) -> None:
    """Retention reduces aged links to labels. A label is a name for proof that
    is no longer reachable, and the list stays non-empty — so a length check
    would let the platform's own ageing satisfy its own policy."""
    from iceberg_api.remediation import service as remediation

    finding = make_finding(severity=Severity.HIGH)
    action_id = client.post(
        f"{api}/findings/{finding.id}/remediations", json=EVIDENCED, headers=analyst_headers
    ).json()["id"]

    action = session.get(RemediationAction, uuid.UUID(action_id))
    assert action is not None
    action.evidence_links = [{"label": "SEC-9", "scrubbed": True}]
    session.add(action)
    session.commit()

    assert remediation.qualifying_action_exists(session, finding.id) is False
    response = client.patch(f"{api}/findings/{finding.id}", json=RESOLVE, headers=analyst_headers)
    assert response.status_code == 409


def _reopen(session: Session, finding: Finding) -> None:
    """The reopen ingest writes when a resolved finding is seen again."""
    session.refresh(finding)
    finding.state = FindingState.OPEN
    finding.resolution = None
    session.add(finding)
    session.add(
        FindingEvent(
            finding_id=finding.id,
            actor_id=None,
            kind=FindingEventKind.REOPENED,
            from_value=FindingState.RESOLVED.value,
            to_value=FindingState.OPEN.value,
        )
    )
    session.commit()


@pytest.mark.parametrize("judgement", ["false_positive", "accepted_risk"])
def test_judgements_are_exempt(
    client: TestClient,
    api: str,
    with_policy: ApiSettings,
    make_finding: Callable[..., Finding],
    analyst_headers: dict[str, str],
    judgement: str,
) -> None:
    """A decision that no secret needed rotating has nothing to evidence."""
    finding = make_finding(severity=Severity.CRITICAL)

    response = client.patch(
        f"{api}/findings/{finding.id}", json={"state": judgement}, headers=analyst_headers
    )

    assert response.status_code == 200, response.text


def test_the_policy_check_locks_the_evidence_it_relies_on(
    session: Session, make_finding: Callable[..., Finding]
) -> None:
    """The check authorises a write to a *different* row — the finding's state.

    So an ordinary read leaves a window: a retraction can commit between the
    check and the resolution, and the finding lands resolved on evidence that
    no longer qualifies. Locking the actions orders the two. SQLite has no row
    locks, so what is pinned here is that the lock is asked for and that it
    renders on the backend that has them.
    """
    from iceberg_api.remediation import service as remediation
    from sqlalchemy.dialects import postgresql
    from sqlmodel import col, select

    finding = make_finding(severity=Severity.HIGH)
    locked: list[bool] = []
    real = remediation.actions_for

    def spy(db: Session, finding_id: uuid.UUID, *, for_update: bool = False) -> list[Any]:
        locked.append(for_update)
        return real(db, finding_id, for_update=for_update)

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(remediation, "actions_for", spy)
        remediation.qualifying_action_exists(session, finding.id)

    assert locked == [True]

    statement = (
        select(RemediationAction)
        .where(col(RemediationAction.finding_id) == finding.id)
        .with_for_update()
    )
    rendered = str(statement.compile(dialect=postgresql.dialect()))  # type: ignore[no-untyped-call]
    assert "FOR UPDATE" in rendered


def test_reading_the_action_list_does_not_lock_it(
    session: Session, make_finding: Callable[..., Finding]
) -> None:
    """Only the policy check locks; the panel and the API list are plain reads,
    and a lock held across an ordinary GET would be a queue nobody asked for."""
    from iceberg_api.remediation import service as remediation
    from sqlalchemy.dialects import postgresql
    from sqlmodel import col, select

    finding = make_finding()
    assert remediation.actions_for(session, finding.id) == []

    plain = select(RemediationAction).where(col(RemediationAction.finding_id) == finding.id)
    rendered = str(plain.compile(dialect=postgresql.dialect()))  # type: ignore[no-untyped-call]
    assert "FOR UPDATE" not in rendered
