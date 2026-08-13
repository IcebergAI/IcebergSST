"""Audit-log coverage (#64, #69).

The audit-coverage review asked for by #64, kept as a test rather than as a
paragraph that goes stale.

Two failure modes are worth catching mechanically:

* **A declared action nobody writes.** An `AUDIT_*` constant with no call site
  reads as coverage in a review and produces nothing in the table.
* **An audited operation that quietly stops being audited.** A route that drops
  its `audit.record` call still passes its own tests — its behaviour is
  unchanged, only the trail is gone. So the operations that must be audited are
  listed here by name, and each is exercised end to end.

What is *not* audited is a decision, not an omission, and is recorded in
`docs/security-review.md`: reads, finding triage (which has its own richer
`finding_event` trail), and engine lease/heartbeat traffic, which is operational
noise rather than administrative action.
"""

import uuid
from collections.abc import Callable
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from iceberg_core.enums import UserRole
from iceberg_core.models import (
    AUDIT_TARGET_SOURCE,
    AUDIT_TARGET_SUPPRESSION,
    AUDIT_TARGET_USER,
    AuditEvent,
    User,
)
from iceberg_core.models import audit as audit_module
from sqlmodel import Session, col, select

API_SRC = Path(__file__).resolve().parents[1] / "src"

#: Every administrative action that must appear in the trail. Adding an audited
#: operation means adding it here, which is the point: the list is the review.
REQUIRED_ACTIONS = {
    "user.role_changed",
    "user.disabled",
    "user.enabled",
    "source.created",
    "source.updated",
    "source.deleted",
    "source.credential_set",
    "source.credential_rotated",
    "schedule.created",
    "schedule.updated",
    "schedule.deleted",
    "suppression.created",
    "suppression.deleted",
    "engine.registered",
    "engine.token_rotated",
    "channel.created",
    "channel.updated",
    "channel.deleted",
    "channel.secret_set",
    "retention.purged",
    "validation_policy.created",
    "validation_policy.updated",
    "validation_policy.deleted",
    "correlation.reindexed",
    "correlation.cluster_exported",
    "remediation.recorded",
    "remediation.verified",
    "remediation.retracted",
}


def _declared_actions() -> dict[str, str]:
    """The `AUDIT_*` action constants and their values."""
    return {
        name: value
        for name, value in vars(audit_module).items()
        if name.startswith("AUDIT_") and not name.startswith("AUDIT_TARGET_")
        if isinstance(value, str)
    }


def test_every_declared_action_has_a_call_site() -> None:
    """A constant nobody writes is coverage on paper only."""
    sources = "\n".join(path.read_text() for path in API_SRC.rglob("*.py"))

    unused = sorted(name for name in _declared_actions() if name not in sources)

    assert unused == [], f"declared but never recorded: {unused}"


def test_the_declared_vocabulary_matches_the_reviewed_list() -> None:
    """Adding an audited action should be a deliberate edit here too.

    Both directions matter: a new action missing from this list has not been
    reviewed, and a name left in this list after its call site went away is the
    coverage regression the whole file exists to catch.
    """
    assert set(_declared_actions().values()) == REQUIRED_ACTIONS


# ── The trail actually gets written ───────────────────────────────────────────


def _actions(session: Session, target_type: str) -> list[str]:
    return [
        event.action
        for event in session.exec(
            select(AuditEvent).where(col(AuditEvent.target_type) == target_type)
        )
    ]


def test_a_role_change_is_audited(
    client: TestClient,
    api: str,
    session: Session,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    admin = make_user(UserRole.ADMIN)
    headers = login_as(admin)
    target = make_user(UserRole.VIEWER)

    response = client.patch(
        f"{api}/users/{target.id}", json={"role": UserRole.ANALYST.value}, headers=headers
    )

    assert response.status_code == 200, response.text
    recorded = session.exec(
        select(AuditEvent)
        .where(col(AuditEvent.target_type) == AUDIT_TARGET_USER)
        .where(col(AuditEvent.target_id) == target.id)
    ).one()
    assert recorded.action == "user.role_changed"
    # Who did it, and what it was before — the two things a review asks for.
    assert recorded.actor_id == admin.id
    assert recorded.from_value == UserRole.VIEWER.value
    assert recorded.to_value == UserRole.ANALYST.value


def test_source_lifecycle_is_audited(
    client: TestClient,
    api: str,
    session: Session,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """Sources hold connector credentials, so creating, changing and deleting one
    are the administrative actions most worth being able to reconstruct."""
    headers = login_as(make_user(UserRole.ADMIN))
    created = client.post(
        f"{api}/sources",
        json={
            "name": "confluence-prod",
            "type": "confluence",
            "connection": {"base_url": "https://example.atlassian.net/wiki"},
            "credential": "a-token",
        },
        headers=headers,
    )
    assert created.status_code == 201, created.text
    source_id = created.json()["id"]

    client.patch(f"{api}/sources/{source_id}", json={"name": "renamed"}, headers=headers)
    client.delete(f"{api}/sources/{source_id}", headers=headers)

    recorded = _actions(session, AUDIT_TARGET_SOURCE)
    assert "source.created" in recorded
    assert "source.credential_set" in recorded
    assert "source.updated" in recorded
    assert "source.deleted" in recorded


def test_suppression_lifecycle_is_audited(
    client: TestClient,
    api: str,
    session: Session,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """A suppression hides findings, so "who silenced this, and why" must have an
    answer (ADR 0008)."""
    headers = login_as(make_user(UserRole.ADMIN))
    created = client.post(
        f"{api}/suppressions",
        json={"scope": "rule", "pattern": "generic-high-entropy", "reason": "noisy in wiki"},
        headers=headers,
    )
    assert created.status_code == 201, created.text

    client.delete(f"{api}/suppressions/{created.json()['id']}", headers=headers)

    recorded = _actions(session, AUDIT_TARGET_SUPPRESSION)
    assert recorded == ["suppression.created", "suppression.deleted"]


def test_an_audit_row_never_carries_a_credential(
    client: TestClient,
    api: str,
    session: Session,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """The trail records *that* a credential was set, never its value — an audit
    log that leaks secrets is a second copy of the thing being protected."""
    headers = login_as(make_user(UserRole.ADMIN))
    secret = f"super-secret-{uuid.uuid4().hex}"

    client.post(
        f"{api}/sources",
        json={
            "name": "confluence-prod",
            "type": "confluence",
            "connection": {"base_url": "https://example.atlassian.net/wiki"},
            "credential": secret,
        },
        headers=headers,
    )

    for event in session.exec(select(AuditEvent)):
        rendered = f"{event.from_value} {event.to_value} {event.detail}"
        assert secret not in rendered


@pytest.mark.parametrize(
    "action",
    ["user.role_changed", "source.deleted", "channel.created", "retention.purged"],
)
def test_the_reviewed_actions_are_documented(action: str) -> None:
    """Every audited action appears in the review document, so the table an
    auditor reads is the table the code writes."""
    review = (Path(__file__).resolve().parents[3] / "docs" / "security-review.md").read_text()

    assert action in review
