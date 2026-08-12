"""The required-evidence policy (#142, ADR 0011).

The property under test: with a minimum severity configured, resolving a
finding at or above it demands a live remediation action with evidence — and
nothing else changes. Below the bar, without the setting, for judgements, and
for reconciliation's auto-resolve, triage behaves exactly as it always has.
"""

from collections.abc import Callable, Iterator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from iceberg_core.config import ApiSettings
from iceberg_core.enums import FindingState, Severity, UserRole
from iceberg_core.models import Finding, User
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
