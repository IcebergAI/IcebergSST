"""Opt-in credential validation policy and persistence boundaries (#151)."""

from collections.abc import Callable

import pytest
from fastapi.testclient import TestClient
from iceberg_api.engines.ingest import ingest_findings
from iceberg_api.engines.schemas import FindingPayload
from iceberg_api.validation.service import UnauthorizedValidation, require_authorized_results
from iceberg_core.enums import ScanStatus, ScanTrigger, SourceType, UserRole, ValidationStatus
from iceberg_core.models import (
    AuditEvent,
    Finding,
    FindingEvent,
    Scan,
    Source,
    User,
    ValidationPolicy,
)
from sqlmodel import Session, select


def _policy_body(**overrides: object) -> dict[str, object]:
    return {
        "rule_id": "github-token",
        "provider": "github",
        "validator_id": "github-token-v1",
        "contract_version": "1",
        "rationale": "Authorized read-only identity check for incident prioritization",
        "timeout_seconds": 2.0,
        "requests_per_minute": 10,
        "max_attempts_per_task": 1,
    } | overrides


def _finding(validation: dict[str, str] | None = None) -> FindingPayload:
    return FindingPayload.model_validate(
        {
            "fingerprint": "a" * 64,
            "rule_id": "github-token",
            "rulepack_version": "1",
            "resource_locator": {"page_id": "safe"},
            "redacted_snippet": "github_pat_****",
            "secret_hash": "b" * 64,
            "severity": "high",
            "validation": validation,
        }
    )


def test_policy_crud_is_admin_only_disabled_by_default_and_audited(
    client: TestClient,
    session: Session,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    viewer_headers = login_as(make_user(UserRole.VIEWER))
    denied = client.post("/api/v1/validation-policies", json=_policy_body(), headers=viewer_headers)
    assert denied.status_code == 403

    admin = make_user(UserRole.ADMIN)
    headers = login_as(admin)
    created = client.post("/api/v1/validation-policies", json=_policy_body(), headers=headers)
    assert created.status_code == 201, created.text
    assert created.json()["enabled"] is False
    policy_id = created.json()["id"]

    updated = client.patch(
        f"/api/v1/validation-policies/{policy_id}", json={"enabled": True}, headers=headers
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["enabled"] is True
    assert [event.action for event in session.exec(select(AuditEvent)).all()] == [
        "validation_policy.created",
        "validation_policy.updated",
    ]
    # Audit carries bounded identifiers, never any credential-shaped input.
    assert all("credential" not in str(event.detail) for event in session.exec(select(AuditEvent)))


def test_unreviewed_detector_validator_pair_is_rejected(
    client: TestClient,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    headers = login_as(make_user(UserRole.ADMIN))
    response = client.post(
        "/api/v1/validation-policies",
        json=_policy_body(rule_id="aws-access-key-id"),
        headers=headers,
    )
    assert response.status_code == 422

    wrong_origin = client.post(
        "/api/v1/validation-policies",
        json=_policy_body(provider="caller-controlled"),
        headers=headers,
    )
    assert wrong_origin.status_code == 422

    wrong_contract = client.post(
        "/api/v1/validation-policies",
        json=_policy_body(contract_version="2"),
        headers=headers,
    )
    assert wrong_contract.status_code == 422


def test_validation_payload_has_no_plaintext_field_and_reason_is_closed_vocabulary() -> None:
    base = {
        "provider": "github",
        "validator_id": "github-token-v1",
        "contract_version": "1",
        "status": "live",
        "reason": "credential_accepted",
    }
    assert _finding(base).validation is not None
    for unsafe in ({**base, "secret": "canary"}, {**base, "reason": "canary-secret"}):
        try:
            _finding(unsafe)
        except ValueError:
            pass
        else:  # pragma: no cover - explicit canary assertion
            raise AssertionError("content-bearing validation data crossed the payload boundary")


def test_ingest_requires_current_policy_and_persists_only_structured_result(
    session: Session,
) -> None:
    result = {
        "provider": "github",
        "validator_id": "github-token-v1",
        "contract_version": "1",
        "status": "live",
        "reason": "credential_accepted",
    }
    payload = _finding(result)
    with pytest.raises(UnauthorizedValidation):
        require_authorized_results(session, [payload], deployment_enabled=False)

    source = Source(name="github-wiki", type=SourceType.CONFLUENCE)
    session.add(source)
    session.flush()
    scan = Scan(
        source_id=source.id,
        trigger=ScanTrigger.MANUAL,
        status=ScanStatus.RUNNING,
    )
    session.add(scan)
    session.add(ValidationPolicy(**_policy_body(enabled=True)))
    session.commit()

    require_authorized_results(session, [payload], deployment_enabled=True)
    ingest_findings(session, scan, [payload])
    session.commit()

    finding = session.exec(select(Finding)).one()
    assert finding.validation_status is ValidationStatus.LIVE
    assert finding.validation_provider == "github"
    assert finding.validation_reason == "credential_accepted"
    event = session.exec(select(FindingEvent)).one()
    assert event.kind.value == "validation"
    assert event.to_value == "live"
    assert "github_pat" not in (event.comment or "")


def test_finding_screen_surfaces_status_without_provider_content(
    client: TestClient,
    session: Session,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    result = {
        "provider": "github",
        "validator_id": "github-token-v1",
        "contract_version": "1",
        "status": "live",
        "reason": "credential_accepted",
    }
    source = Source(name="screen-source", type=SourceType.CONFLUENCE)
    session.add(source)
    session.flush()
    scan = Scan(source_id=source.id, trigger=ScanTrigger.MANUAL, status=ScanStatus.RUNNING)
    session.add(scan)
    session.flush()
    ingest_findings(session, scan, [_finding(result)])
    session.commit()
    finding = session.exec(select(Finding)).one()

    response = client.get(f"/findings/{finding.id}", headers=login_as(make_user(UserRole.VIEWER)))

    assert response.status_code == 200
    assert "Credential liveness" in response.text
    assert "Credential accepted" in response.text
    assert "github-token-v1" in response.text
    assert "canary-secret" not in response.text
