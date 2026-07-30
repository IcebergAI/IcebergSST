"""Suppression CRUD and its effect on findings (#40 — ADR 0008).

The row is the easy half. What the epic asks for is the behaviour around it: a
suppression hides matching findings from the active view *and records them*, its
expiry is respected, and removing it gives the findings back.
"""

import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from iceberg_api import suppressions
from iceberg_core.enums import SuppressionScope, UserRole
from iceberg_core.models import (
    AUDIT_TARGET_SUPPRESSION,
    AuditEvent,
    Finding,
    FindingEvent,
    Source,
    Suppression,
    User,
)
from sqlmodel import Session, col, select

SUPPRESSIONS = "/api/v1/suppressions"
FINDINGS = "/api/v1/findings"


def _is_hidden(session: Session, finding: Finding) -> bool:
    """Whether a finding is currently out of the active view, re-read from the DB."""
    session.refresh(finding)
    return finding.suppressed_at is not None


def _events(session: Session, finding: Finding) -> list[str]:
    return [
        f"{event.kind.value}:{event.comment}"
        for event in session.exec(
            select(FindingEvent)
            .where(col(FindingEvent.finding_id) == finding.id)
            .order_by(col(FindingEvent.created_at), col(FindingEvent.id))
        )
    ]


def test_creating_a_suppression_hides_matching_findings_but_records_them(
    client: TestClient,
    session: Session,
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """The noise goes now, not after the next scan — and it is still on record."""
    analyst = make_user(UserRole.ANALYST)
    headers = login_as(analyst)
    source = make_source()
    noisy = make_finding(source, rule_id="generic-high-entropy")
    real = make_finding(source, rule_id="aws-access-key")

    created = client.post(
        SUPPRESSIONS,
        json={
            "scope": "rule",
            "pattern": "generic-high-entropy",
            "source_id": str(source.id),
            "reason": "test fixtures in the QA space",
        },
        headers=headers,
    )

    assert created.status_code == 201
    assert created.json()["created_by_id"] == str(analyst.id)

    session.refresh(noisy)
    session.refresh(real)
    assert noisy.suppressed_at is not None
    assert str(noisy.suppressed_by_id) == created.json()["id"]
    assert real.suppressed_at is None

    # Recorded, not discarded: it is out of the active view, still in the table.
    active = client.get(FINDINGS, params={"suppressed": False}).json()
    assert [item["id"] for item in active["items"]] == [str(real.id)]
    assert any(entry.startswith("suppressed:") for entry in _events(session, noisy))


def test_a_path_glob_matches_the_locator(
    client: TestClient,
    session: Session,
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """Globs cannot be pushed into SQL, so this is the path that filters in Python."""
    headers = login_as(make_user(UserRole.ANALYST))
    source = make_source()
    in_sandbox = make_finding(source, resource_locator={"path": "/space/SANDBOX/page-9"})
    in_prod = make_finding(source, resource_locator={"path": "/space/DOCS/page-1"})

    client.post(
        SUPPRESSIONS,
        json={
            "scope": "path_glob",
            "pattern": "/space/SANDBOX/*",
            "reason": "throwaway space",
        },
        headers=headers,
    )

    session.refresh(in_sandbox)
    session.refresh(in_prod)
    assert in_sandbox.suppressed_at is not None
    assert in_prod.suppressed_at is None


def test_a_global_suppression_covers_every_source(
    client: TestClient,
    session: Session,
    make_finding: Callable[..., Finding],
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    headers = login_as(make_user(UserRole.ANALYST))
    first = make_finding(rule_id="example-docs-key")
    second = make_finding(rule_id="example-docs-key")

    client.post(
        SUPPRESSIONS,
        json={"scope": "rule", "pattern": "example-docs-key", "reason": "documented example key"},
        headers=headers,
    )

    session.refresh(first)
    session.refresh(second)
    assert first.suppressed_at is not None
    assert second.suppressed_at is not None


def test_deleting_a_suppression_returns_its_findings_with_an_explanation(
    client: TestClient,
    session: Session,
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """A finding reappearing with no explanation is one analysts learn to distrust."""
    headers = login_as(make_user(UserRole.ANALYST))
    source = make_source()
    finding = make_finding(source, rule_id="generic-high-entropy")
    created = client.post(
        SUPPRESSIONS,
        json={"scope": "rule", "pattern": "generic-high-entropy", "reason": "noise"},
        headers=headers,
    ).json()

    deleted = client.delete(f"{SUPPRESSIONS}/{created['id']}", headers=headers)

    assert deleted.status_code == 204
    session.refresh(finding)
    assert finding.suppressed_at is None
    assert finding.suppressed_by_id is None
    assert _events(session, finding)[-1] == f"comment:suppression {created['id']} deleted"


def test_an_expired_suppression_releases_its_findings_on_the_maintenance_beat(
    client: TestClient,
    session: Session,
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """Expiry is a property of the clock, not of when the source is next scanned."""
    headers = login_as(make_user(UserRole.ANALYST))
    source = make_source()
    finding = make_finding(source, rule_id="generic-high-entropy")
    client.post(
        SUPPRESSIONS,
        json={
            "scope": "rule",
            "pattern": "generic-high-entropy",
            "reason": "silence for a sprint",
            "expires_at": (datetime.now(UTC) + timedelta(days=14)).isoformat(),
        },
        headers=headers,
    )
    assert _is_hidden(session, finding)

    released = suppressions.release_lapsed(session, now=datetime.now(UTC) + timedelta(days=15))
    session.commit()

    assert released == 1
    assert not _is_hidden(session, finding)
    assert _events(session, finding)[-1].endswith("expired")


def test_a_lapse_sweep_leaves_live_suppressions_alone(
    client: TestClient,
    session: Session,
    make_finding: Callable[..., Finding],
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    headers = login_as(make_user(UserRole.ANALYST))
    finding = make_finding(rule_id="generic-high-entropy")
    client.post(
        SUPPRESSIONS,
        json={"scope": "rule", "pattern": "generic-high-entropy", "reason": "noise"},
        headers=headers,
    )

    assert suppressions.release_lapsed(session) == 0
    assert _is_hidden(session, finding)


def test_an_expiry_in_the_past_is_refused(
    client: TestClient,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """A suppression that is dead on arrival is a mistake, not a request."""
    headers = login_as(make_user(UserRole.ANALYST))

    response = client.post(
        SUPPRESSIONS,
        json={
            "scope": "rule",
            "pattern": "generic-high-entropy",
            "reason": "oops",
            "expires_at": (datetime.now(UTC) - timedelta(days=1)).isoformat(),
        },
        headers=headers,
    )

    assert response.status_code == 422


def test_a_blank_reason_is_refused(
    client: TestClient,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """Six months later, an unexplained suppression is indistinguishable from a bug."""
    headers = login_as(make_user(UserRole.ANALYST))

    response = client.post(
        SUPPRESSIONS,
        json={"scope": "rule", "pattern": "generic-high-entropy", "reason": "   "},
        headers=headers,
    )

    assert response.status_code == 422


def test_an_unknown_source_is_refused(
    client: TestClient,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    headers = login_as(make_user(UserRole.ANALYST))

    response = client.post(
        SUPPRESSIONS,
        json={
            "scope": "rule",
            "pattern": "generic-high-entropy",
            "reason": "noise",
            "source_id": "00000000-0000-0000-0000-000000000000",
        },
        headers=headers,
    )

    assert response.status_code == 422


def test_listing_for_a_source_includes_the_global_ones(
    client: TestClient,
    make_source: Callable[..., Source],
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """ "What is hidden from this source" is wrong if it omits the global rules."""
    headers = login_as(make_user(UserRole.ANALYST))
    source, other = make_source("mine"), make_source("theirs")
    for body in (
        {"scope": "rule", "pattern": "mine", "source_id": str(source.id), "reason": "r"},
        {"scope": "rule", "pattern": "global", "reason": "r"},
        {"scope": "rule", "pattern": "theirs", "source_id": str(other.id), "reason": "r"},
    ):
        client.post(SUPPRESSIONS, json=body, headers=headers)

    listed = client.get(SUPPRESSIONS, params={"source_id": str(source.id)}).json()

    assert sorted(item["pattern"] for item in listed["items"]) == ["global", "mine"]


def test_listing_can_separate_live_from_expired(
    client: TestClient,
    session: Session,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    headers = login_as(make_user(UserRole.ANALYST))
    live = client.post(
        SUPPRESSIONS,
        json={"scope": "rule", "pattern": "live", "reason": "r"},
        headers=headers,
    ).json()
    lapsing = client.post(
        SUPPRESSIONS,
        json={
            "scope": "rule",
            "pattern": "lapsing",
            "reason": "r",
            "expires_at": (datetime.now(UTC) + timedelta(seconds=1)).isoformat(),
        },
        headers=headers,
    ).json()
    # Backdate rather than sleep: the route refuses a past expiry on the way in.
    row = session.get(Suppression, uuid.UUID(lapsing["id"]))
    assert row is not None
    row.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    session.add(row)
    session.commit()

    active = client.get(SUPPRESSIONS, params={"active": True}).json()
    expired = client.get(SUPPRESSIONS, params={"active": False}).json()

    assert [item["id"] for item in active["items"]] == [live["id"]]
    assert [item["id"] for item in expired["items"]] == [lapsing["id"]]


def test_scope_filters_the_listing(
    client: TestClient,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    headers = login_as(make_user(UserRole.ANALYST))
    client.post(
        SUPPRESSIONS, json={"scope": "rule", "pattern": "r", "reason": "r"}, headers=headers
    )
    client.post(
        SUPPRESSIONS,
        json={"scope": "path_glob", "pattern": "/space/SANDBOX/*", "reason": "r"},
        headers=headers,
    )

    listed = client.get(SUPPRESSIONS, params={"scope": SuppressionScope.PATH_GLOB.value}).json()

    assert [item["pattern"] for item in listed["items"]] == ["/space/SANDBOX/*"]


def test_a_viewer_may_read_but_not_write_suppressions(
    client: TestClient,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    headers = login_as(make_user(UserRole.VIEWER))

    listed = client.get(SUPPRESSIONS)
    created = client.post(
        SUPPRESSIONS, json={"scope": "rule", "pattern": "r", "reason": "r"}, headers=headers
    )

    assert listed.status_code == 200
    assert created.status_code == 403


def test_creating_and_deleting_are_audited(
    client: TestClient,
    session: Session,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """A suppression is a decision to stop looking at something."""
    analyst = make_user(UserRole.ANALYST)
    headers = login_as(analyst)
    created = client.post(
        SUPPRESSIONS,
        json={"scope": "rule", "pattern": "generic-high-entropy", "reason": "noise"},
        headers=headers,
    ).json()
    client.delete(f"{SUPPRESSIONS}/{created['id']}", headers=headers)

    recorded = session.exec(
        select(AuditEvent).where(col(AuditEvent.target_type) == AUDIT_TARGET_SUPPRESSION)
    ).all()

    assert [event.action for event in recorded] == [
        "suppression.created",
        "suppression.deleted",
    ]
    assert {event.actor_id for event in recorded} == {analyst.id}


def test_deleting_one_of_two_overlapping_suppressions_keeps_the_finding_hidden(
    client: TestClient,
    session: Session,
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """Only the first match is recorded, so deletion has to check for another."""
    headers = login_as(make_user(UserRole.ANALYST))
    source = make_source()
    finding = make_finding(
        source, rule_id="generic-high-entropy", resource_locator={"path": "/space/SANDBOX/page-9"}
    )
    by_rule = client.post(
        SUPPRESSIONS,
        json={"scope": "rule", "pattern": "generic-high-entropy", "reason": "noise"},
        headers=headers,
    ).json()
    by_path = client.post(
        SUPPRESSIONS,
        json={"scope": "path_glob", "pattern": "/space/SANDBOX/*", "reason": "throwaway space"},
        headers=headers,
    ).json()

    client.delete(f"{SUPPRESSIONS}/{by_rule['id']}", headers=headers)

    assert _is_hidden(session, finding)
    assert str(finding.suppressed_by_id) == by_path["id"]
    # It never left the hidden set, so nothing claims it came back.
    assert not any("deleted" in entry for entry in _events(session, finding))
