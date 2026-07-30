"""``GET /rules`` and the confidence threshold (#70).

Rule packs ship inside engine images, so the fleet is the source of truth about
what is being detected. The interesting case is therefore not the happy one but
the rolling deploy, where two versions are simultaneously correct and an answer
that picked one would be wrong about half the fleet.
"""

import uuid
from collections.abc import Callable
from typing import Any

from fastapi.testclient import TestClient
from iceberg_core.config import ApiSettings
from iceberg_core.enums import EngineStatus, UserRole
from iceberg_core.models import Engine, User
from sqlmodel import Session

RULES = "/api/v1/rules"

PACK_A: dict[str, Any] = {
    "version": "2026.07.1",
    "rules": [
        {"id": "aws-access-key-id", "description": "AWS Access Key ID", "severity": "high"},
        {"id": "github-token", "description": "GitHub token", "severity": "critical"},
    ],
}
PACK_B: dict[str, Any] = {
    "version": "2026.08.1",
    "rules": [
        {"id": "aws-access-key-id", "description": "AWS Access Key ID", "severity": "high"},
        {"id": "github-token", "description": "GitHub token", "severity": "critical"},
        {"id": "stripe-api-key", "description": "Stripe API key", "severity": "critical"},
    ],
}


def _engine(
    session: Session,
    name: str,
    *,
    rulepack: dict[str, Any] | None = None,
    status: EngineStatus = EngineStatus.ACTIVE,
) -> Engine:
    engine = Engine(
        name=name,
        token_hash=uuid.uuid4().hex,
        version="0.1.0",
        status=status,
        rulepack=rulepack or {},
    )
    session.add(engine)
    session.commit()
    return engine


def test_rules_are_listed_from_what_the_fleet_reports(
    client: TestClient,
    session: Session,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    login_as(make_user(UserRole.VIEWER))
    _engine(session, "engine-1", rulepack=PACK_A)

    body = client.get(RULES).json()

    assert body["fleet_consistent"] is True
    assert [rule["id"] for rule in body["rules"]] == ["aws-access-key-id", "github-token"]
    assert body["rules"][1]["severity"] == "critical"
    assert body["rulepack_versions"] == [
        {
            "version": "2026.07.1",
            "engine_count": 1,
            "engines": ["engine-1"],
            "rule_count": 2,
        }
    ]


def test_a_rolling_deploy_reports_both_versions(
    client: TestClient,
    session: Session,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """Two versions are both in force; picking one would be wrong about half the fleet."""
    login_as(make_user(UserRole.VIEWER))
    _engine(session, "engine-old", rulepack=PACK_A)
    _engine(session, "engine-new-1", rulepack=PACK_B)
    _engine(session, "engine-new-2", rulepack=PACK_B)

    body = client.get(RULES).json()

    assert body["fleet_consistent"] is False
    assert [(v["version"], v["engine_count"]) for v in body["rulepack_versions"]] == [
        ("2026.07.1", 1),
        ("2026.08.1", 2),
    ]
    assert body["rulepack_versions"][1]["engines"] == ["engine-new-1", "engine-new-2"]

    by_id = {rule["id"]: rule for rule in body["rules"]}
    # In both packs, so both versions are listed against it...
    assert by_id["aws-access-key-id"]["rulepack_versions"] == ["2026.07.1", "2026.08.1"]
    # ...and the new rule names only the version that has it.
    assert by_id["stripe-api-key"]["rulepack_versions"] == ["2026.08.1"]


def test_an_offline_engine_does_not_contribute_rules(
    client: TestClient,
    session: Session,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """It is not running anything, so its pack is history, not the current surface."""
    login_as(make_user(UserRole.VIEWER))
    _engine(session, "engine-live", rulepack=PACK_A)
    _engine(session, "engine-gone", rulepack=PACK_B, status=EngineStatus.OFFLINE)

    body = client.get(RULES).json()

    assert [v["version"] for v in body["rulepack_versions"]] == ["2026.07.1"]
    assert "stripe-api-key" not in {rule["id"] for rule in body["rules"]}


def test_a_draining_engine_still_counts(
    client: TestClient,
    session: Session,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """Draining means finishing its current work, which it is doing with these rules."""
    login_as(make_user(UserRole.VIEWER))
    _engine(session, "engine-draining", rulepack=PACK_A, status=EngineStatus.DRAINING)

    assert [v["version"] for v in client.get(RULES).json()["rulepack_versions"]] == ["2026.07.1"]


def test_an_engine_that_has_reported_nothing_is_named(
    client: TestClient,
    session: Session,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """Registered but never heartbeat, or too old an image — either way, say which."""
    login_as(make_user(UserRole.VIEWER))
    _engine(session, "engine-quiet")

    body = client.get(RULES).json()

    assert body["engines_without_a_rulepack"] == ["engine-quiet"]
    assert body["rules"] == []


def test_an_empty_fleet_is_consistent_and_empty(
    client: TestClient,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    login_as(make_user(UserRole.VIEWER))

    body = client.get(RULES).json()

    assert body["fleet_consistent"] is True
    assert body["rules"] == []
    assert body["rulepack_versions"] == []


def test_the_listing_never_carries_a_regex(
    client: TestClient,
    session: Session,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """Patterns stay in the image (ADR 0008); serving them invites a client to
    re-implement detection against them."""
    login_as(make_user(UserRole.VIEWER))
    _engine(session, "engine-1", rulepack=PACK_A)

    assert "regex" not in client.get(RULES).text


def test_the_configured_threshold_is_served(
    client: TestClient,
    api_settings: ApiSettings,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """It is as much a part of "what gets detected" as the rules are."""
    login_as(make_user(UserRole.VIEWER))

    assert client.get(RULES).json()["confidence_threshold"] == api_settings.confidence_threshold


def test_reading_rules_requires_a_session(client: TestClient) -> None:
    assert client.get(RULES).status_code == 401


def test_a_malformed_stored_severity_does_not_break_the_listing(
    client: TestClient,
    session: Session,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """Registration validates severities, so this means a row that predates it.
    A read-only view should degrade, not 500."""
    login_as(make_user(UserRole.VIEWER))
    _engine(
        session,
        "engine-legacy",
        rulepack={
            "version": "2025.01.1",
            "rules": [{"id": "odd-rule", "description": "Odd", "severity": "apocalyptic"}],
        },
    )

    body = client.get(RULES).json()

    assert body["rules"][0]["severity"] == "medium"
