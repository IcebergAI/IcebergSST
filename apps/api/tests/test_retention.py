"""Data retention (#73).

Almost every test here asserts that something was **not** deleted. That is the
right shape for this feature: the purge is trivial and the eligibility rules are
the whole product, and the failure mode of getting them wrong is destroying
evidence nobody can get back.

The rules, and why each exists:

* **Off by default.** No window configured, nothing deleted, ever.
* **Open findings are never eligible.** An unresolved secret is not old news.
* **Only `auto` resolutions.** `false_positive` and `accepted_risk` are analyst
  judgements; letting them expire means the finding returns next scan with nobody
  remembering it was already considered.
* **Suppressed findings are never eligible**, because deleting one resurrects it
  as new on the next scan (ADR 0008).
* **An open finding keeps its whole trail**, however old the events are.
* **The purge audits itself**, because deleting evidence is an administrative
  action.
"""

import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from iceberg_api import retention
from iceberg_core.config import ApiSettings
from iceberg_core.enums import (
    FindingEventKind,
    FindingResolution,
    FindingState,
    ScanStatus,
    ScanTrigger,
    Severity,
    SourceType,
)
from iceberg_core.models import (
    AUDIT_RETENTION_PURGED,
    AuditEvent,
    Finding,
    FindingEvent,
    Scan,
    Source,
)
from pydantic import SecretStr
from sqlmodel import Session, col, select, update

NOW = datetime(2026, 7, 31, 12, 0, tzinfo=UTC)
LONG_AGO = NOW - timedelta(days=400)
RECENTLY = NOW - timedelta(days=2)


def _settings(**windows: int) -> ApiSettings:
    return ApiSettings(
        database_url="postgresql+psycopg://unused/unused",
        master_key=SecretStr("unused"),
        **windows,  # type: ignore[arg-type]
    )


@pytest.fixture(name="source")
def source_fixture(session: Session) -> Source:
    source = Source(
        name=f"confluence-{uuid.uuid4().hex[:6]}",
        type=SourceType.CONFLUENCE,
        connection={"base_url": "https://example.atlassian.net/wiki"},
    )
    session.add(source)
    session.commit()
    return source


@pytest.fixture(name="scan")
def scan_fixture(session: Session, source: Source) -> Scan:
    scan = Scan(source_id=source.id, trigger=ScanTrigger.MANUAL, status=ScanStatus.COMPLETED)
    session.add(scan)
    session.commit()
    return scan


@pytest.fixture(name="make_finding")
def make_finding_fixture(session: Session, source: Source, scan: Scan) -> Callable[..., Finding]:
    def factory(*, updated_at: datetime = LONG_AGO, **fields: Any) -> Finding:
        defaults: dict[str, Any] = {
            "fingerprint": uuid.uuid4().hex,
            "rule_id": "aws-access-key",
            "rulepack_version": "2026.07.1",
            "resource_locator": {"path": "/space/DOCS/page-1"},
            "redacted_snippet": "AKIA****************",
            "secret_hash": uuid.uuid4().hex,
            "severity": Severity.HIGH,
            "state": FindingState.RESOLVED,
            "resolution": FindingResolution.AUTO,
        }
        finding = Finding(
            source_id=source.id,
            first_seen_scan_id=scan.id,
            last_seen_scan_id=scan.id,
            **(defaults | fields),
        )
        session.add(finding)
        session.commit()
        # `updated_at` is maintained by the model on write, so the age is set
        # afterwards with an UPDATE — the same row real time would have produced.
        session.exec(
            update(Finding).where(col(Finding.id) == finding.id).values(updated_at=updated_at)
        )
        session.commit()
        session.refresh(finding)
        return finding

    return factory


def _age_event(session: Session, event: FindingEvent, created_at: datetime) -> None:
    session.exec(
        update(FindingEvent).where(col(FindingEvent.id) == event.id).values(created_at=created_at)
    )
    session.commit()


# ── Off by default ────────────────────────────────────────────────────────────


def test_nothing_is_deleted_without_a_configured_window(
    session: Session, make_finding: Callable[..., Finding]
) -> None:
    """The default is keep-everything, and it has to be: this database records
    where an organisation's secrets are, and losing that on upgrade would be a
    surprise nobody can undo."""
    make_finding()

    result = retention.purge(session, _settings(), now=NOW)

    assert result.total() == 0
    assert len(list(session.exec(select(Finding)))) == 1


# ── Findings ──────────────────────────────────────────────────────────────────


def test_an_old_auto_resolved_finding_is_purged(
    session: Session, make_finding: Callable[..., Finding]
) -> None:
    make_finding()

    result = retention.purge(session, _settings(retention_resolved_findings_days=90), now=NOW)

    assert result.findings == 1
    assert list(session.exec(select(Finding))) == []


def test_an_open_finding_is_never_purged(
    session: Session, make_finding: Callable[..., Finding]
) -> None:
    """An unresolved secret is not old news; it is a secret nobody dealt with."""
    make_finding(state=FindingState.OPEN, resolution=None)

    result = retention.purge(session, _settings(retention_resolved_findings_days=1), now=NOW)

    assert result.findings == 0
    assert len(list(session.exec(select(Finding)))) == 1


@pytest.mark.parametrize(
    ("state", "resolution"),
    [
        (FindingState.ACCEPTED_RISK, None),
        (FindingState.FALSE_POSITIVE, None),
        (FindingState.RESOLVED, FindingResolution.MANUAL),
    ],
)
def test_an_analyst_decision_is_never_purged(
    session: Session,
    make_finding: Callable[..., Finding],
    state: FindingState,
    resolution: FindingResolution | None,
) -> None:
    """A judgement that expires silently means the finding comes back next scan
    with nobody remembering it was already considered."""
    make_finding(state=state, resolution=resolution)

    result = retention.purge(session, _settings(retention_resolved_findings_days=1), now=NOW)

    assert result.findings == 0
    assert len(list(session.exec(select(Finding)))) == 1


def test_a_suppressed_finding_is_never_purged(
    session: Session, make_finding: Callable[..., Finding]
) -> None:
    """Deleting it would resurrect it as new on the next scan, which is the exact
    outcome the suppression exists to prevent (ADR 0008)."""
    make_finding(suppressed_at=LONG_AGO)

    result = retention.purge(session, _settings(retention_resolved_findings_days=1), now=NOW)

    assert result.findings == 0


def test_a_recently_resolved_finding_is_inside_the_window(
    session: Session, make_finding: Callable[..., Finding]
) -> None:
    """The clock runs from the decision, not the first sighting: a secret found
    two years ago and resolved yesterday is a day old for retention."""
    make_finding(updated_at=RECENTLY)

    result = retention.purge(session, _settings(retention_resolved_findings_days=90), now=NOW)

    assert result.findings == 0


def test_a_finding_reopened_mid_purge_is_not_deleted(
    session: Session,
    make_finding: Callable[..., Finding],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The eligibility predicates are repeated on the DELETE, not only the SELECT.

    The purge runs on the maintenance beat while ingest runs in the request path,
    so under READ COMMITTED a submission can re-open one of the ids just read. A
    delete by id alone would take a live secret finding and cascade its whole
    trail away, with nothing to recover it from.
    """
    finding = make_finding()
    original = session.exec

    def reopen_between_the_two_statements(statement: Any, *args: Any, **kwargs: Any) -> Any:
        if not str(statement).startswith("SELECT finding.id"):
            return original(statement, *args, **kwargs)
        eligible = list(original(statement, *args, **kwargs))
        # Stands in for the commit an engine's result submission would land here.
        original(
            update(Finding)
            .where(col(Finding.id) == finding.id)
            .values(state=FindingState.OPEN, resolution=None)
        )
        return eligible

    monkeypatch.setattr(session, "exec", reopen_between_the_two_statements)

    result = retention.purge(session, _settings(retention_resolved_findings_days=90), now=NOW)

    assert result.findings == 0
    assert session.get(Finding, finding.id) is not None


def test_an_event_whose_finding_reopened_mid_purge_is_kept(
    session: Session,
    make_finding: Callable[..., Finding],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Same race, on the trail: an open finding keeps its whole history."""
    finding = make_finding(state=FindingState.ACCEPTED_RISK, resolution=None)
    event = FindingEvent(finding_id=finding.id, kind=FindingEventKind.COMMENT, comment="old")
    session.add(event)
    session.commit()
    _age_event(session, event, LONG_AGO)
    original = session.exec

    def reopen_between_the_two_statements(statement: Any, *args: Any, **kwargs: Any) -> Any:
        if not str(statement).startswith("SELECT finding_event.id"):
            return original(statement, *args, **kwargs)
        eligible = list(original(statement, *args, **kwargs))
        original(
            update(Finding).where(col(Finding.id) == finding.id).values(state=FindingState.OPEN)
        )
        return eligible

    monkeypatch.setattr(session, "exec", reopen_between_the_two_statements)

    result = retention.purge(session, _settings(retention_finding_events_days=30), now=NOW)

    assert result.finding_events == 0
    assert len(list(session.exec(select(FindingEvent)))) == 1


def test_a_purged_finding_takes_its_trail_with_it(
    session: Session, make_finding: Callable[..., Finding]
) -> None:
    finding = make_finding()
    session.add(
        FindingEvent(
            finding_id=finding.id,
            kind=FindingEventKind.STATE_CHANGE,
            from_value="open",
            to_value="resolved",
        )
    )
    session.commit()

    retention.purge(session, _settings(retention_resolved_findings_days=90), now=NOW)

    assert list(session.exec(select(FindingEvent))) == []


# ── Finding events ────────────────────────────────────────────────────────────


def test_an_open_findings_events_are_kept_however_old(
    session: Session, make_finding: Callable[..., Finding]
) -> None:
    """The trail is what an analyst reads to understand the state in front of
    them, and an old open finding is exactly the one that needs explaining."""
    finding = make_finding(state=FindingState.OPEN, resolution=None)
    event = FindingEvent(
        finding_id=finding.id,
        kind=FindingEventKind.COMMENT,
        comment="asked the space owner to rotate this",
    )
    session.add(event)
    session.commit()
    _age_event(session, event, LONG_AGO)

    result = retention.purge(session, _settings(retention_finding_events_days=30), now=NOW)

    assert result.finding_events == 0
    assert len(list(session.exec(select(FindingEvent)))) == 1


def test_old_events_on_a_settled_finding_are_pruned(
    session: Session, make_finding: Callable[..., Finding]
) -> None:
    finding = make_finding(state=FindingState.ACCEPTED_RISK, resolution=None)
    event = FindingEvent(
        finding_id=finding.id,
        kind=FindingEventKind.STATE_CHANGE,
        from_value="open",
        to_value="accepted_risk",
    )
    session.add(event)
    session.commit()
    _age_event(session, event, LONG_AGO)

    result = retention.purge(session, _settings(retention_finding_events_days=30), now=NOW)

    assert result.finding_events == 1
    # The finding itself survives — it is an analyst decision.
    assert len(list(session.exec(select(Finding)))) == 1


def test_a_recent_event_is_kept(session: Session, make_finding: Callable[..., Finding]) -> None:
    finding = make_finding(state=FindingState.ACCEPTED_RISK, resolution=None)
    event = FindingEvent(finding_id=finding.id, kind=FindingEventKind.COMMENT, comment="recent")
    session.add(event)
    session.commit()
    _age_event(session, event, RECENTLY)

    result = retention.purge(session, _settings(retention_finding_events_days=30), now=NOW)

    assert result.finding_events == 0


# ── Audit events ──────────────────────────────────────────────────────────────


def test_old_audit_events_are_pruned_and_recent_ones_kept(session: Session) -> None:
    old = AuditEvent(action="user.role_changed", target_type="user", target_id=uuid.uuid4())
    recent = AuditEvent(action="source.created", target_type="source", target_id=uuid.uuid4())
    session.add(old)
    session.add(recent)
    session.commit()
    for event, when in ((old, LONG_AGO), (recent, RECENTLY)):
        session.exec(
            update(AuditEvent).where(col(AuditEvent.id) == event.id).values(created_at=when)
        )
    session.commit()

    result = retention.purge(session, _settings(retention_audit_events_days=365), now=NOW)

    assert result.audit_events == 1
    surviving = list(
        session.exec(select(AuditEvent).where(col(AuditEvent.action) != "retention.purged"))
    )
    assert [event.action for event in surviving] == ["source.created"]


# ── The purge audits itself ───────────────────────────────────────────────────


def test_a_purge_that_deleted_something_is_audited(
    session: Session, make_finding: Callable[..., Finding]
) -> None:
    """Deleting evidence is an administrative action. The row records what went
    and the window that justified it, so it still explains itself a year later
    when the settings have changed."""
    make_finding()

    retention.purge(session, _settings(retention_resolved_findings_days=90), now=NOW)

    recorded = session.exec(
        select(AuditEvent).where(col(AuditEvent.action) == AUDIT_RETENTION_PURGED)
    ).one()
    assert recorded.actor_id is None  # a policy did this, not a person
    assert recorded.detail["findings"] == "1"
    assert recorded.detail["resolved_findings_days"] == "90"


def test_a_purge_that_deleted_nothing_writes_no_audit_row(session: Session) -> None:
    """An audit log full of "deleted 0 rows" every minute is one nobody reads."""
    retention.purge(session, _settings(retention_resolved_findings_days=90), now=NOW)

    assert list(session.exec(select(AuditEvent))) == []


# ── Batching ──────────────────────────────────────────────────────────────────


def test_a_round_deletes_at_most_the_batch_size(
    session: Session, make_finding: Callable[..., Finding]
) -> None:
    """The first purge on a database that has never had one must not hold locks
    for minutes; what it does not take this round, it takes on the next beat."""
    for _ in range(5):
        make_finding()

    first = retention.purge(
        session,
        _settings(retention_resolved_findings_days=90, retention_batch_size=2),
        now=NOW,
    )
    second = retention.purge(
        session,
        _settings(retention_resolved_findings_days=90, retention_batch_size=2),
        now=NOW,
    )

    assert first.findings == 2
    assert second.findings == 2
    assert len(list(session.exec(select(Finding)))) == 1
