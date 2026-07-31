"""Results ingest and reconciliation (#36, #37 — ADR 0004, 0006, 0008, 0009)."""

from collections.abc import Callable
from typing import Any

import pytest
from conftest import RecordingDispatcher
from fastapi.testclient import TestClient
from iceberg_api.scans import service
from iceberg_core.enums import (
    FindingResolution,
    FindingState,
    ScanStatus,
    ScanTaskKind,
    ScanTaskStatus,
    ScanTrigger,
    SourceType,
    SuppressionScope,
    UserRole,
)
from iceberg_core.models import (
    Engine,
    Finding,
    FindingEvent,
    Scan,
    ScanTask,
    Source,
    Suppression,
    User,
)
from iceberg_core.secrets import EnvKeyBackend
from sqlmodel import Session, select

FINGERPRINT = "a" * 64
OTHER_FINGERPRINT = "b" * 64


def _source(session: Session, store: EnvKeyBackend) -> Source:
    source = Source(
        name="confluence-prod",
        type=SourceType.CONFLUENCE,
        connection={"base_url": "https://example.atlassian.net/wiki"},
        credential_ref=store.seal("token"),
    )
    session.add(source)
    session.commit()
    return source


def _finding_payload(fingerprint: str = FINGERPRINT, **overrides: Any) -> dict[str, Any]:
    return {
        "fingerprint": fingerprint,
        "rule_id": "aws-access-key-id",
        "rulepack_version": "2026.07.1",
        "resource_locator": {"page_id": "12345", "url": "https://wiki/ENG/creds", "line": 42},
        "redacted_snippet": "aws_access_key_id = AKIA…[16 chars redacted]",
        "secret_hash": "f" * 64,
        "severity": "high",
    } | overrides


class Fixture:
    """One scan with a leased fetch task, ready to receive results."""

    def __init__(
        self,
        client: TestClient,
        session: Session,
        dispatcher: RecordingDispatcher,
        store: EnvKeyBackend,
        engine: Engine,
        headers: dict[str, str],
    ) -> None:
        self.client = client
        self.session = session
        self.dispatcher = dispatcher
        self.engine = engine
        self.headers = headers
        self.source = _source(session, store)
        self.scan = service.launch_scan(
            session, self.source, trigger=ScanTrigger.MANUAL, dispatcher=dispatcher
        )
        self.discovery = session.exec(
            select(ScanTask).where(ScanTask.scan_id == self.scan.id)
        ).one()

    def lease(self, task: ScanTask) -> dict[str, Any]:
        response = self.client.post(f"/api/v1/scan-tasks/{task.id}/lease", headers=self.headers)
        assert response.status_code == 200, response.text
        body: dict[str, Any] = response.json()
        return body

    def report(self, task: ScanTask, **body: Any) -> Any:
        payload = {"idempotency_key": f"{task.id}:{task.attempts}", "status": "completed"} | body
        return self.client.post(
            f"/api/v1/scan-tasks/{task.id}/results", json=payload, headers=self.headers
        )

    def fetch_task(self) -> ScanTask:
        """Complete discovery with one fetch spec and lease the resulting task."""
        self.lease(self.discovery)
        self.session.refresh(self.discovery)
        self.report(self.discovery, task_specs=[{"page_ids": ["1"]}])
        task = self.session.exec(
            select(ScanTask)
            .where(ScanTask.scan_id == self.scan.id)
            .where(ScanTask.kind == ScanTaskKind.FETCH)
        ).one()
        self.lease(task)
        self.session.refresh(task)
        return task


@pytest.fixture(name="scan_fixture")
def scan_fixture(
    client: TestClient,
    session: Session,
    dispatcher: RecordingDispatcher,
    secret_store: EnvKeyBackend,
    engine_credential: tuple[Engine, dict[str, str]],
) -> Fixture:
    engine, headers = engine_credential
    return Fixture(client, session, dispatcher, secret_store, engine, headers)


def test_discovery_results_become_fetch_tasks(scan_fixture: Fixture) -> None:
    """Phase two: the API persists what the engine discovered (ADR 0009 §1)."""
    fixture = scan_fixture
    fixture.lease(fixture.discovery)
    fixture.session.refresh(fixture.discovery)
    fixture.dispatcher.enqueued.clear()

    response = fixture.report(
        fixture.discovery, task_specs=[{"page_ids": ["1"]}, {"page_ids": ["2"]}]
    )

    assert response.status_code == 200
    assert response.json()["fetch_tasks_created"] == 2
    fetch_tasks = fixture.session.exec(
        select(ScanTask).where(ScanTask.kind == ScanTaskKind.FETCH)
    ).all()
    assert len(fetch_tasks) == 2
    assert set(fixture.dispatcher.enqueued) == {task.id for task in fetch_tasks}


def test_findings_are_stored_with_no_place_for_a_plaintext_secret(
    scan_fixture: Fixture,
) -> None:
    """The payload has no secret field: the engine redacted before sending (ADR 0004)."""
    fixture = scan_fixture
    task = fixture.fetch_task()

    response = fixture.report(task, findings=[_finding_payload()])

    assert response.status_code == 200
    assert response.json()["findings_ingested"] == 1
    finding = fixture.session.exec(select(Finding)).one()
    assert finding.fingerprint == FINGERPRINT
    assert finding.state is FindingState.OPEN
    assert finding.first_seen_scan_id == finding.last_seen_scan_id == fixture.scan.id
    assert finding.redacted_snippet.endswith("[16 chars redacted]")


def test_a_replayed_submission_does_not_duplicate_findings(scan_fixture: Fixture) -> None:
    """An engine retrying after an API error must be harmless (ADR 0009 §2)."""
    fixture = scan_fixture
    task = fixture.fetch_task()
    key = f"{task.id}:{task.attempts}"

    first = fixture.report(task, idempotency_key=key, findings=[_finding_payload()])
    second = fixture.report(task, idempotency_key=key, findings=[_finding_payload()])

    assert first.json()["replay"] is False
    assert second.json()["replay"] is True
    assert second.json()["findings_ingested"] == 0
    assert len(fixture.session.exec(select(Finding)).all()) == 1


def test_a_different_key_against_a_finished_task_is_a_conflict(
    scan_fixture: Fixture,
) -> None:
    fixture = scan_fixture
    task = fixture.fetch_task()
    fixture.report(task, idempotency_key=f"{task.id}:1", findings=[_finding_payload()])

    response = fixture.report(task, idempotency_key=f"{task.id}:2", findings=[_finding_payload()])

    assert response.status_code == 409


def test_results_for_a_task_this_engine_does_not_hold_are_refused(
    scan_fixture: Fixture, session: Session
) -> None:
    fixture = scan_fixture
    task = fixture.fetch_task()
    stranger = Engine(name="stranger", token_hash="unused")
    session.add(stranger)
    session.commit()
    task.engine_id = stranger.id
    session.commit()

    assert fixture.report(task, findings=[]).status_code == 403


def test_results_for_a_task_that_is_no_longer_leased_are_refused(
    scan_fixture: Fixture,
) -> None:
    """Reclaimed or cancelled: whatever the engine computed is no longer wanted."""
    fixture = scan_fixture
    task = fixture.fetch_task()
    task.status = ScanTaskStatus.QUEUED
    fixture.session.commit()

    assert fixture.report(task, findings=[_finding_payload()]).status_code == 409
    assert fixture.session.exec(select(Finding)).all() == []


@pytest.mark.parametrize("reported", ["cancelled", "queued", "leased"])
def test_an_engine_may_only_report_completed_or_failed(
    scan_fixture: Fixture, reported: str
) -> None:
    fixture = scan_fixture
    task = fixture.fetch_task()

    assert fixture.report(task, status=reported).status_code == 422


def test_a_failed_task_makes_the_scan_partial_and_reconciles_nothing(
    scan_fixture: Fixture,
) -> None:
    """One failed space must not mass-resolve the findings it never saw (ADR 0009 §4)."""
    fixture = scan_fixture
    # A pre-existing finding from an earlier scan, still open.
    earlier = Scan(
        source_id=fixture.source.id, trigger=ScanTrigger.MANUAL, status=ScanStatus.COMPLETED
    )
    fixture.session.add(earlier)
    fixture.session.commit()
    stale = Finding(
        source_id=fixture.source.id,
        fingerprint=OTHER_FINGERPRINT,
        rule_id="aws-access-key-id",
        rulepack_version="2026.07.1",
        resource_locator={},
        redacted_snippet="[redacted]",
        secret_hash="c" * 64,
        severity="high",
        first_seen_scan_id=earlier.id,
        last_seen_scan_id=earlier.id,
    )
    fixture.session.add(stale)
    fixture.session.commit()

    task = fixture.fetch_task()
    response = fixture.report(task, status="failed", error="429 from Confluence")

    assert response.json()["scan_status"] == ScanStatus.PARTIAL.value
    fixture.session.refresh(stale)
    assert stale.state is FindingState.OPEN


def test_a_failed_task_still_has_its_findings_ingested(scan_fixture: Fixture) -> None:
    """A connector that dies halfway through a space still saw real secrets first.

    `complete_task(failed)` is terminal — reclaim only touches leased work — so a
    finding dropped here surfaces only if an operator re-runs the whole scan,
    which defeats the unit-level tolerance the design already pays for (#115).
    """
    fixture = scan_fixture
    task = fixture.fetch_task()

    response = fixture.report(
        task,
        status="failed",
        error="pagination cap hit",
        findings=[_finding_payload()],
        counts={"units_scanned": 3, "units_failed": 1},
    )

    assert response.status_code == 200
    assert response.json()["findings_ingested"] == 1
    finding = fixture.session.exec(select(Finding)).one()
    assert finding.fingerprint == FINGERPRINT
    assert finding.state is FindingState.OPEN
    fixture.session.refresh(fixture.scan)
    # Still partial, so reconciliation refuses to auto-resolve on it (ADR 0009 §4).
    assert fixture.scan.status is ScanStatus.PARTIAL
    assert fixture.scan.counts["findings"] == 1
    assert fixture.scan.counts["units_failed"] == 1


def test_a_failed_scan_says_why_it_failed(scan_fixture: Fixture) -> None:
    """`Scan.error` is on the read contract, so something has to write it.

    Reporting a bare `failed` and a null left every caller chasing the task list
    for the one string that explains the run.
    """
    fixture = scan_fixture
    fixture.lease(fixture.discovery)
    fixture.session.refresh(fixture.discovery)

    fixture.report(fixture.discovery, status="failed", error="401 from Confluence")

    fixture.session.refresh(fixture.scan)
    assert fixture.scan.status is ScanStatus.FAILED
    assert fixture.scan.error == "401 from Confluence"


def test_a_completed_scan_says_nothing_went_wrong(scan_fixture: Fixture) -> None:
    fixture = scan_fixture
    task = fixture.fetch_task()

    fixture.report(task, findings=[_finding_payload()])

    fixture.session.refresh(fixture.scan)
    assert fixture.scan.status is ScanStatus.COMPLETED
    assert fixture.scan.error is None


def test_a_completed_scan_auto_resolves_what_it_did_not_see(
    scan_fixture: Fixture,
) -> None:
    """The "missing" half of reconciliation (ADR 0006)."""
    fixture = scan_fixture
    earlier = Scan(
        source_id=fixture.source.id, trigger=ScanTrigger.MANUAL, status=ScanStatus.COMPLETED
    )
    fixture.session.add(earlier)
    fixture.session.commit()
    remediated = Finding(
        source_id=fixture.source.id,
        fingerprint=OTHER_FINGERPRINT,
        rule_id="aws-access-key-id",
        rulepack_version="2026.07.1",
        resource_locator={},
        redacted_snippet="[redacted]",
        secret_hash="c" * 64,
        severity="high",
        first_seen_scan_id=earlier.id,
        last_seen_scan_id=earlier.id,
    )
    fixture.session.add(remediated)
    fixture.session.commit()

    task = fixture.fetch_task()
    response = fixture.report(task, findings=[_finding_payload()])

    assert response.json()["scan_status"] == ScanStatus.COMPLETED.value
    fixture.session.refresh(remediated)
    assert remediated.state is FindingState.RESOLVED
    assert remediated.resolution is FindingResolution.AUTO
    # Audited without an actor: nobody decided this, a scan observed it.
    event = fixture.session.exec(
        select(FindingEvent).where(FindingEvent.finding_id == remediated.id)
    ).one()
    assert event.actor_id is None
    fixture.session.refresh(fixture.scan)
    assert fixture.scan.counts["resolved"] == 1


def test_reconciliation_never_resolves_a_suppressed_finding(scan_fixture: Fixture) -> None:
    """Engines may pre-filter with the lease's suppressions (#44), so a suppressed
    finding going unreported is not evidence it is gone (ADR 0008)."""
    fixture = scan_fixture
    earlier = Scan(
        source_id=fixture.source.id, trigger=ScanTrigger.MANUAL, status=ScanStatus.COMPLETED
    )
    fixture.session.add(earlier)
    fixture.session.commit()
    suppressed = Finding(
        source_id=fixture.source.id,
        fingerprint=OTHER_FINGERPRINT,
        rule_id="aws-access-key-id",
        rulepack_version="2026.07.1",
        resource_locator={},
        redacted_snippet="[redacted]",
        secret_hash="c" * 64,
        severity="high",
        first_seen_scan_id=earlier.id,
        last_seen_scan_id=earlier.id,
        suppressed_at=earlier.created_at,
    )
    fixture.session.add(suppressed)
    fixture.session.commit()

    task = fixture.fetch_task()
    response = fixture.report(task, findings=[_finding_payload()])

    assert response.json()["scan_status"] == ScanStatus.COMPLETED.value
    fixture.session.refresh(suppressed)
    assert suppressed.state is FindingState.OPEN
    assert suppressed.suppressed_at is not None


def test_a_scan_that_fetched_nothing_does_not_mass_resolve(scan_fixture: Fixture) -> None:
    """A discovery that enumerates zero units — an emptied space, or a credential
    whose scope quietly shrank — must not resolve every open finding at once."""
    fixture = scan_fixture
    earlier = Scan(
        source_id=fixture.source.id, trigger=ScanTrigger.MANUAL, status=ScanStatus.COMPLETED
    )
    fixture.session.add(earlier)
    fixture.session.commit()
    open_finding = Finding(
        source_id=fixture.source.id,
        fingerprint=OTHER_FINGERPRINT,
        rule_id="aws-access-key-id",
        rulepack_version="2026.07.1",
        resource_locator={},
        redacted_snippet="[redacted]",
        secret_hash="c" * 64,
        severity="high",
        first_seen_scan_id=earlier.id,
        last_seen_scan_id=earlier.id,
    )
    fixture.session.add(open_finding)
    fixture.session.commit()

    fixture.lease(fixture.discovery)
    fixture.session.refresh(fixture.discovery)
    response = fixture.report(fixture.discovery, task_specs=[])

    assert response.json()["scan_status"] == ScanStatus.COMPLETED.value
    fixture.session.refresh(open_finding)
    assert open_finding.state is FindingState.OPEN


def test_a_replay_repairs_a_lost_finalisation(scan_fixture: Fixture) -> None:
    """If the crash landed between accepting results and finishing the scan, the
    engine's retry is the first chance to settle it."""
    fixture = scan_fixture
    task = fixture.fetch_task()
    key = f"{task.id}:{task.attempts}"
    fixture.report(task, idempotency_key=key)

    # Simulate the lost follow-up: results accepted, but the scan still active.
    fixture.session.refresh(fixture.scan)
    fixture.scan.status = ScanStatus.RUNNING
    fixture.scan.finished_at = None
    fixture.session.commit()

    replay = fixture.report(task, idempotency_key=key)

    assert replay.json()["replay"] is True
    assert replay.json()["scan_status"] == ScanStatus.COMPLETED.value
    fixture.session.refresh(fixture.scan)
    assert fixture.scan.status is ScanStatus.COMPLETED


def test_a_triaged_finding_keeps_its_state_across_scans(scan_fixture: Fixture) -> None:
    """The whole point of a stable fingerprint (ADR 0006)."""
    fixture = scan_fixture
    task = fixture.fetch_task()
    fixture.report(task, findings=[_finding_payload()])
    finding = fixture.session.exec(select(Finding)).one()
    finding.state = FindingState.FALSE_POSITIVE
    fixture.session.commit()

    # A second scan of the same source sees the same secret again.
    second = service.launch_scan(
        fixture.session,
        fixture.source,
        trigger=ScanTrigger.MANUAL,
        dispatcher=fixture.dispatcher,
    )
    discovery = fixture.session.exec(select(ScanTask).where(ScanTask.scan_id == second.id)).one()
    fixture.lease(discovery)
    fixture.session.refresh(discovery)
    fixture.report(discovery, task_specs=[{"page_ids": ["1"]}])
    fetch = fixture.session.exec(
        select(ScanTask)
        .where(ScanTask.scan_id == second.id)
        .where(ScanTask.kind == ScanTaskKind.FETCH)
    ).one()
    fixture.lease(fetch)
    fixture.session.refresh(fetch)
    fixture.report(fetch, findings=[_finding_payload()])

    fixture.session.refresh(finding)
    assert finding.state is FindingState.FALSE_POSITIVE
    assert finding.last_seen_scan_id == second.id


@pytest.mark.parametrize("resolution", [FindingResolution.AUTO, FindingResolution.MANUAL])
def test_a_secret_that_comes_back_reopens(
    scan_fixture: Fixture, resolution: FindingResolution
) -> None:
    """A sighting refutes "resolved" however it was resolved (ADR 0006). An auto
    resolution was an inference from absence; a manual one was an analyst believing
    the secret had been removed — the reappearance disproves both. Only the
    judgement states (false_positive, accepted_risk) survive a sighting."""
    fixture = scan_fixture
    task = fixture.fetch_task()
    fixture.report(task, findings=[_finding_payload()])
    finding = fixture.session.exec(select(Finding)).one()
    finding.state = FindingState.RESOLVED
    finding.resolution = resolution
    fixture.session.commit()

    second = service.launch_scan(
        fixture.session,
        fixture.source,
        trigger=ScanTrigger.MANUAL,
        dispatcher=fixture.dispatcher,
    )
    discovery = fixture.session.exec(select(ScanTask).where(ScanTask.scan_id == second.id)).one()
    fixture.lease(discovery)
    fixture.session.refresh(discovery)
    fixture.report(discovery, task_specs=[{"page_ids": ["1"]}])
    fetch = fixture.session.exec(
        select(ScanTask)
        .where(ScanTask.scan_id == second.id)
        .where(ScanTask.kind == ScanTaskKind.FETCH)
    ).one()
    fixture.lease(fetch)
    fixture.session.refresh(fetch)

    response = fixture.report(fetch, findings=[_finding_payload()])

    assert response.json()["findings_reopened"] == 1
    fixture.session.refresh(finding)
    assert finding.state is FindingState.OPEN
    assert finding.resolution is None


def test_a_suppressed_finding_is_recorded_not_discarded(scan_fixture: Fixture) -> None:
    """ "Why is this not in my list?" needs an answer (ADR 0008)."""
    fixture = scan_fixture
    fixture.session.add(
        Suppression(
            scope=SuppressionScope.RULE,
            pattern="aws-access-key-id",
            source_id=fixture.source.id,
            reason="test fixtures",
        )
    )
    fixture.session.commit()
    task = fixture.fetch_task()

    response = fixture.report(task, findings=[_finding_payload()])

    assert response.json() | {"findings_suppressed": 1} == response.json()
    finding = fixture.session.exec(select(Finding)).one()
    assert finding.suppressed_at is not None
    assert finding.suppressed_by_id is not None
    assert finding.state is FindingState.OPEN  # recorded, just not active


def test_a_suppression_created_after_the_lease_is_still_applied(
    scan_fixture: Fixture,
) -> None:
    """Ingest is the enforcement point, not the engine's lease snapshot (#44)."""
    fixture = scan_fixture
    task = fixture.fetch_task()  # leased before the suppression exists
    fixture.session.add(
        Suppression(
            scope=SuppressionScope.PATH_GLOB,
            pattern="https://wiki/ENG/*",
            source_id=None,  # global
            reason="known-good space",
        )
    )
    fixture.session.commit()

    fixture.report(task, findings=[_finding_payload()])

    assert fixture.session.exec(select(Finding)).one().suppressed_at is not None


def test_an_expired_suppression_no_longer_hides_a_finding(scan_fixture: Fixture) -> None:
    from datetime import UTC, datetime, timedelta

    fixture = scan_fixture
    fixture.session.add(
        Suppression(
            scope=SuppressionScope.RULE,
            pattern="aws-access-key-id",
            source_id=fixture.source.id,
            reason="silenced for a sprint",
            expires_at=datetime.now(UTC) - timedelta(days=1),
        )
    )
    fixture.session.commit()
    task = fixture.fetch_task()

    fixture.report(task, findings=[_finding_payload()])

    assert fixture.session.exec(select(Finding)).one().suppressed_at is None


def test_the_scan_records_the_rulepack_that_produced_its_findings(
    scan_fixture: Fixture,
) -> None:
    """Results are only reproducible if the version is recorded (ADR 0008)."""
    fixture = scan_fixture
    task = fixture.fetch_task()

    fixture.report(task, findings=[_finding_payload()], rulepack_version="2026.07.2")

    fixture.session.refresh(fixture.scan)
    assert fixture.scan.rulepack_version == "2026.07.2"


def test_engine_counts_accumulate_across_tasks(scan_fixture: Fixture) -> None:
    """Tasks report independently and in any order; counts are their sum."""
    fixture = scan_fixture
    fixture.lease(fixture.discovery)
    fixture.session.refresh(fixture.discovery)
    fixture.report(fixture.discovery, task_specs=[{"page_ids": ["1"]}, {"page_ids": ["2"]}])
    tasks = list(
        fixture.session.exec(
            select(ScanTask)
            .where(ScanTask.scan_id == fixture.scan.id)
            .where(ScanTask.kind == ScanTaskKind.FETCH)
        )
    )

    for index, task in enumerate(tasks):
        fixture.lease(task)
        fixture.session.refresh(task)
        fixture.report(
            task,
            findings=[_finding_payload(fingerprint=str(index) * 64)],
            counts={"units_scanned": 10},
        )

    fixture.session.refresh(fixture.scan)
    assert fixture.scan.counts["units_scanned"] == 20
    assert fixture.scan.counts["findings"] == 2


def test_reconciliation_happens_once_even_if_two_tasks_finish_together(
    scan_fixture: Fixture,
) -> None:
    """The conditional UPDATE decides the winner (ADR 0009 §3)."""
    fixture = scan_fixture
    fixture.lease(fixture.discovery)
    fixture.session.refresh(fixture.discovery)
    fixture.report(fixture.discovery, task_specs=[{"page_ids": ["1"]}, {"page_ids": ["2"]}])
    tasks = list(
        fixture.session.exec(
            select(ScanTask)
            .where(ScanTask.scan_id == fixture.scan.id)
            .where(ScanTask.kind == ScanTaskKind.FETCH)
        )
    )
    statuses: list[str | None] = []
    for index, task in enumerate(tasks):
        fixture.lease(task)
        fixture.session.refresh(task)
        response = fixture.report(task, findings=[_finding_payload(fingerprint=str(index) * 64)])
        statuses.append(response.json()["scan_status"])

    # Only the submission that finished the last task reports a scan status.
    assert statuses == [None, ScanStatus.COMPLETED.value]


def test_a_human_can_read_the_findings_an_engine_reported(
    scan_fixture: Fixture,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """End to end: engine writes through its token, analyst reads through a session."""
    fixture = scan_fixture
    task = fixture.fetch_task()
    fixture.report(task, findings=[_finding_payload()])

    login_as(make_user(UserRole.ANALYST))
    scans = fixture.client.get("/api/v1/scans").json()

    assert scans["items"][0]["status"] == ScanStatus.COMPLETED.value
    assert scans["items"][0]["counts"]["findings"] == 1
