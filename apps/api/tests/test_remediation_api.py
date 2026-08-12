"""Remediation actions over the API (#142, ADR 0011).

Pinned here: recording is analyst-only and stamps the guidance version;
verification is one-way and retraction set-once, each leaving trail rows;
viewers see the fact of an action but never its note or link URLs; and link
validation refuses exactly the strings this product exists to find.
"""

from collections.abc import Callable
from typing import Any

import pytest
from fastapi.testclient import TestClient
from iceberg_core.enums import UserRole
from iceberg_core.models import (
    AuditEvent,
    Finding,
    FindingEvent,
    User,
)
from sqlmodel import Session, col, select

VALID = {
    "kind": "rotate",
    "note": "rotated in the provider console, old key disabled",
    "evidence_links": [{"url": "https://tickets.example.test/SEC-123", "label": "SEC-123"}],
}


@pytest.fixture(name="finding")
def finding_fixture(make_finding: Callable[..., Finding]) -> Finding:
    return make_finding()


@pytest.fixture(name="analyst")
def analyst_fixture(
    make_user: Callable[..., User], login_as: Callable[[User], dict[str, str]]
) -> tuple[User, dict[str, str]]:
    user = make_user(UserRole.ANALYST)
    return user, login_as(user)


def _record(
    client: TestClient, api: str, finding: Finding, headers: dict[str, str], **overrides: Any
) -> Any:
    return client.post(
        f"{api}/findings/{finding.id}/remediations",
        json=VALID | overrides,
        headers=headers,
    )


def test_recording_returns_the_action_with_the_guidance_version(
    client: TestClient, api: str, finding: Finding, analyst: tuple[User, dict[str, str]]
) -> None:
    user, headers = analyst

    response = _record(client, api, finding, headers)

    assert response.status_code == 201, response.text
    action = response.json()
    assert action["kind"] == "rotate"
    assert action["actor_id"] == str(user.id)
    assert action["guidance_version"]  # stamped from the packaged catalog
    assert action["verification"] == "unverified"
    assert action["evidence_links"] == VALID["evidence_links"]


def test_recording_writes_a_finding_event_and_an_audit_row(
    client: TestClient,
    api: str,
    session: Session,
    finding: Finding,
    analyst: tuple[User, dict[str, str]],
) -> None:
    _, headers = analyst

    _record(client, api, finding, headers)

    event = session.exec(
        select(FindingEvent).where(col(FindingEvent.finding_id) == finding.id)
    ).one()
    assert event.kind.value == "remediation"
    assert event.to_value == "rotate"
    audit_row = session.exec(
        select(AuditEvent).where(col(AuditEvent.action) == "remediation.recorded")
    ).one()
    assert audit_row.detail["finding_id"] == str(finding.id)


def test_a_viewer_cannot_record_and_sees_a_redacted_list(
    client: TestClient,
    api: str,
    finding: Finding,
    analyst: tuple[User, dict[str, str]],
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    _, headers = analyst
    _record(client, api, finding, headers)

    viewer_headers = login_as(make_user(UserRole.VIEWER))
    refused = client.post(
        f"{api}/findings/{finding.id}/remediations", json=VALID, headers=viewer_headers
    )
    listed = client.get(f"{api}/findings/{finding.id}/remediations").json()

    assert refused.status_code == 403
    (action,) = listed
    # The fact of the action, not its internals: labels survive, URLs and the
    # note do not.
    assert action["kind"] == "rotate"
    assert action["evidence_labels"] == ["SEC-123"]
    assert "evidence_links" not in action
    assert "note" not in action
    assert "tickets.example.test" not in str(listed)


def test_an_analyst_sees_full_links(
    client: TestClient, api: str, finding: Finding, analyst: tuple[User, dict[str, str]]
) -> None:
    _, headers = analyst
    _record(client, api, finding, headers)

    (action,) = client.get(f"{api}/findings/{finding.id}/remediations").json()

    assert action["evidence_links"][0]["url"] == "https://tickets.example.test/SEC-123"
    assert action["note"] is not None


@pytest.mark.parametrize(
    "bad_link",
    [
        {"url": "ftp://files.example.test/proof.txt", "label": "ftp"},
        {"url": "javascript:alert(1)", "label": "xss"},
        {"url": "https://token@internal.example.test/", "label": "credential-bearing"},
        {"url": "not-a-url", "label": "junk"},
    ],
)
def test_link_validation_refuses_dangerous_urls(
    client: TestClient,
    api: str,
    finding: Finding,
    analyst: tuple[User, dict[str, str]],
    bad_link: dict[str, str],
) -> None:
    _, headers = analyst

    response = _record(client, api, finding, headers, evidence_links=[bad_link])

    assert response.status_code == 422, bad_link


def test_occurred_at_must_not_be_in_the_future(
    client: TestClient, api: str, finding: Finding, analyst: tuple[User, dict[str, str]]
) -> None:
    _, headers = analyst

    response = _record(client, api, finding, headers, occurred_at="2099-01-01T00:00:00Z")

    assert response.status_code == 422


def test_verification_is_one_way(
    client: TestClient,
    api: str,
    session: Session,
    finding: Finding,
    analyst: tuple[User, dict[str, str]],
) -> None:
    user, headers = analyst
    action_id = _record(client, api, finding, headers).json()["id"]
    verify_url = f"{api}/findings/{finding.id}/remediations/{action_id}/verify"

    first = client.post(verify_url, json={"comment": "confirmed revoked"}, headers=headers)
    second = client.post(verify_url, json={}, headers=headers)

    assert first.status_code == 200, first.text
    assert first.json()["verification"] == "verified"
    assert first.json()["verified_by_id"] == str(user.id)
    assert second.status_code == 409
    kinds = [
        event.kind.value
        for event in session.exec(
            select(FindingEvent).where(col(FindingEvent.finding_id) == finding.id)
        )
    ]
    assert kinds.count("remediation_verified") == 1


def test_retraction_requires_a_reason_and_is_set_once(
    client: TestClient, api: str, finding: Finding, analyst: tuple[User, dict[str, str]]
) -> None:
    _, headers = analyst
    action_id = _record(client, api, finding, headers).json()["id"]
    retract_url = f"{api}/findings/{finding.id}/remediations/{action_id}/retract"

    unreasoned = client.post(retract_url, json={}, headers=headers)
    retracted = client.post(retract_url, json={"reason": "wrong finding"}, headers=headers)
    again = client.post(retract_url, json={"reason": "twice"}, headers=headers)

    assert unreasoned.status_code == 422
    assert retracted.status_code == 200
    assert retracted.json()["retracted_reason"] == "wrong finding"
    assert again.status_code == 409


def test_a_retracted_action_cannot_be_verified(
    client: TestClient, api: str, finding: Finding, analyst: tuple[User, dict[str, str]]
) -> None:
    _, headers = analyst
    action_id = _record(client, api, finding, headers).json()["id"]
    base = f"{api}/findings/{finding.id}/remediations/{action_id}"
    client.post(
        f"{base}/retract", json={"reason": "recorded on the wrong finding"}, headers=headers
    )

    response = client.post(f"{base}/verify", json={}, headers=headers)

    assert response.status_code == 409


def test_the_finding_detail_carries_the_actions(
    client: TestClient, api: str, finding: Finding, analyst: tuple[User, dict[str, str]]
) -> None:
    _, headers = analyst
    _record(client, api, finding, headers)

    detail = client.get(f"{api}/findings/{finding.id}").json()

    (action,) = detail["remediations"]
    assert action["kind"] == "rotate"
    assert action["evidence_links"]  # analyst shape on the detail too


def test_guidance_serves_the_rule_entry_or_the_default(
    client: TestClient, api: str, analyst: tuple[User, dict[str, str]]
) -> None:
    specific = client.get(f"{api}/remediation/guidance/aws-access-key-id").json()
    fallback = client.get(f"{api}/remediation/guidance/some-unknown-rule").json()

    assert specific["matched"] == "rule"
    assert specific["entry"]["revoke"]
    assert fallback["matched"] == "default"
    assert specific["version"] == fallback["version"]


def test_a_mismatched_finding_action_pair_is_a_404(
    client: TestClient,
    api: str,
    make_finding: Callable[..., Finding],
    analyst: tuple[User, dict[str, str]],
) -> None:
    _, headers = analyst
    first = make_finding()
    other = make_finding()
    action_id = _record(client, api, first, headers).json()["id"]

    response = client.post(
        f"{api}/findings/{other.id}/remediations/{action_id}/verify", json={}, headers=headers
    )

    assert response.status_code == 404


def test_reappearance_reopens_with_remediation_history_intact(
    client: TestClient,
    api: str,
    session: Session,
    make_finding: Callable[..., Finding],
    analyst: tuple[User, dict[str, str]],
) -> None:
    """#142's last acceptance criterion: the reopen (which ingest already does)
    must not cost the record of what was done the first time around."""
    from iceberg_api.engines.ingest import ingest_findings
    from iceberg_api.engines.schemas import FindingPayload
    from iceberg_core.enums import FindingState, ScanStatus, ScanTrigger
    from iceberg_core.models import Scan

    _, headers = analyst
    finding = make_finding(state=FindingState.RESOLVED)
    _record(client, api, finding, headers)

    scan = Scan(source_id=finding.source_id, trigger=ScanTrigger.MANUAL, status=ScanStatus.RUNNING)
    session.add(scan)
    session.commit()
    ingest_findings(
        session,
        scan,
        [
            FindingPayload(
                fingerprint=finding.fingerprint,
                rule_id=finding.rule_id,
                rulepack_version=finding.rulepack_version,
                resource_locator=finding.resource_locator,
                redacted_snippet=finding.redacted_snippet,
                secret_hash=finding.secret_hash,
                severity=finding.severity,
            )
        ],
    )
    session.commit()

    session.refresh(finding)
    assert finding.state is FindingState.OPEN  # reopened by the sighting

    detail = client.get(f"{api}/findings/{finding.id}").json()
    assert len(detail["remediations"]) == 1  # the history survived
    kinds = [event["kind"] for event in detail["events"]]
    assert "remediation" in kinds
    assert "reopened" in kinds
