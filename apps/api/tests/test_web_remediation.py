"""The remediation panel on the finding detail (#142, ADR 0012).

The shared suites already assert the invariants (CSRF on every mutating web
route, no ORM in `iceberg_api.web`, no inline script); this file covers what
the panel itself promises: guidance rendered per rule, the analyst round-trip
through the fragment, rejected forms answering 200 with the reason, viewer
redaction, and the evidence-policy 409 surfacing on the triage panel.
"""

from collections.abc import Callable

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from iceberg_core.config import ApiSettings
from iceberg_core.enums import Severity, UserRole
from iceberg_core.models import Finding, User


@pytest.fixture(name="as_analyst")
def as_analyst_fixture(
    make_user: Callable[..., User], login_as: Callable[[User], dict[str, str]]
) -> dict[str, str]:
    return login_as(make_user(UserRole.ANALYST))


RECORD_FORM = {
    "kind": "rotate",
    "note": "rotated in the console",
    "link_url_1": "https://tickets.example.test/SEC-7",
    "link_label_1": "SEC-7",
}


def test_the_detail_page_shows_guidance_for_the_rule(
    client: TestClient, make_finding: Callable[..., Finding], as_analyst: dict[str, str]
) -> None:
    finding = make_finding(rule_id="aws-access-key-id")

    body = client.get(f"/findings/{finding.id}").text

    assert "Rotation guidance" in body
    assert "for this rule" in body  # the specific entry, not the fallback
    assert "Revoke" in body and "Rotate" in body


def test_an_unknown_rule_gets_the_generic_advice_and_says_so(
    client: TestClient, make_finding: Callable[..., Finding], as_analyst: dict[str, str]
) -> None:
    finding = make_finding(rule_id="some-custom-rule")

    body = client.get(f"/findings/{finding.id}").text

    assert "generic advice" in body


def test_an_analyst_records_an_action_through_the_fragment(
    client: TestClient,
    make_finding: Callable[..., Finding],
    as_analyst: dict[str, str],
) -> None:
    finding = make_finding()

    response = client.post(
        f"/findings/{finding.id}/remediations",
        data=RECORD_FORM | {"csrf_token": as_analyst["X-CSRF-Token"]},
        headers=as_analyst,
    )

    assert response.status_code == 200, response.text[:400]
    assert 'id="remediation-panel"' in response.text
    assert "SEC-7" in response.text
    assert "unverified" in response.text


def test_a_rejected_form_answers_200_with_the_reason(
    client: TestClient,
    make_finding: Callable[..., Finding],
    as_analyst: dict[str, str],
) -> None:
    """HTMX only swaps 2xx: the error must come back on the fragment."""
    finding = make_finding()

    response = client.post(
        f"/findings/{finding.id}/remediations",
        data=RECORD_FORM
        | {
            "link_url_1": "https://token@internal.example.test/x",
            "csrf_token": as_analyst["X-CSRF-Token"],
        },
        headers=as_analyst,
    )

    assert response.status_code == 200
    assert "Not recorded." in response.text
    assert "embed credentials" in response.text


def test_verify_and_retract_round_trip_on_the_panel(
    client: TestClient,
    make_finding: Callable[..., Finding],
    as_analyst: dict[str, str],
) -> None:
    finding = make_finding()
    token = {"csrf_token": as_analyst["X-CSRF-Token"]}
    recorded = client.post(
        f"/findings/{finding.id}/remediations", data=RECORD_FORM | token, headers=as_analyst
    )
    assert recorded.status_code == 200

    # The panel carries the verify form; drive it via the API-listed action id.
    api_list = client.get(f"/api/v1/findings/{finding.id}/remediations").json()
    action_id = api_list[0]["id"]

    verified = client.post(
        f"/findings/{finding.id}/remediations/{action_id}/verify",
        data=token,
        headers=as_analyst,
    )
    assert verified.status_code == 200
    assert ">verified<" in verified.text or "state-resolved" in verified.text

    retracted = client.post(
        f"/findings/{finding.id}/remediations/{action_id}/retract",
        data={"reason": "wrong credential"} | token,
        headers=as_analyst,
    )
    assert retracted.status_code == 200
    assert "retracted" in retracted.text


def test_a_viewer_sees_the_record_without_forms_or_urls(
    client: TestClient,
    make_finding: Callable[..., Finding],
    as_analyst: dict[str, str],
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    finding = make_finding()
    client.post(
        f"/findings/{finding.id}/remediations",
        data=RECORD_FORM | {"csrf_token": as_analyst["X-CSRF-Token"]},
        headers=as_analyst,
    )

    login_as(make_user(UserRole.VIEWER))
    body = client.get(f"/findings/{finding.id}").text

    assert "Remediation record" in body
    assert "SEC-7" in body  # the label survives…
    assert "tickets.example.test" not in body  # …the URL does not
    assert "rotated in the console" not in body  # nor the note
    assert "Record an action" not in body  # no form for a read-only role


def test_the_evidence_policy_409_surfaces_on_the_triage_panel(
    app: FastAPI,
    client: TestClient,
    api_settings: ApiSettings,
    make_finding: Callable[..., Finding],
    as_analyst: dict[str, str],
) -> None:
    from iceberg_api.auth.dependencies import get_settings

    strict = api_settings.model_copy(update={"remediation_evidence_min_severity": Severity.HIGH})
    app.dependency_overrides[get_settings] = lambda: strict
    try:
        finding = make_finding(severity=Severity.CRITICAL)

        response = client.post(
            f"/findings/{finding.id}/triage",
            data={"state": "resolved", "csrf_token": as_analyst["X-CSRF-Token"]},
            headers=as_analyst,
        )
    finally:
        app.dependency_overrides[get_settings] = lambda: api_settings

    assert response.status_code == 200  # the fragment, not a dead end
    assert "Not applied." in response.text
    assert "remediation action" in response.text


def test_a_blank_label_defaults_to_the_host_not_the_url(
    client: TestClient,
    make_finding: Callable[..., Finding],
    as_analyst: dict[str, str],
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """Labels are the one part of an evidence link a viewer sees, so the
    blank-label default must not smuggle the URL through as a label."""
    finding = make_finding()

    recorded = client.post(
        f"/findings/{finding.id}/remediations",
        data={
            "kind": "revoke",
            "link_url_1": "https://tickets.example.test/SEC-7/secret-path?token=abc",
            "link_label_1": "",
            "csrf_token": as_analyst["X-CSRF-Token"],
        },
        headers=as_analyst,
    )
    assert recorded.status_code == 200, recorded.text[:400]

    (action,) = client.get(f"/api/v1/findings/{finding.id}/remediations").json()
    assert action["evidence_links"][0]["label"] == "tickets.example.test"

    login_as(make_user(UserRole.VIEWER))
    body = client.get(f"/findings/{finding.id}").text
    assert "tickets.example.test" in body  # the host is the label, deliberately
    assert "secret-path" not in body  # …but never the path
    assert "token=abc" not in body  # …nor the query
