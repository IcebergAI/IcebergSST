"""Batched result submission and durable checkpoints (#143, ADR 0013).

A checkpoint is only sound if the findings up to it are already stored, so the two
move in one transaction and one route. Everything here is about the ways that
could go wrong: a batch arriving twice, out of order, from an engine whose lease is
gone, or carrying a failure the terminal submission no longer mentions.

The recurring theme is **what the API must not take an engine's word for**. It is
the only writer of record, so a task's outcome is judged from what the API
accumulated, never from the last thing it was told.
"""

import ast
from pathlib import Path
from typing import Any

import pytest
from conftest import RecordingDispatcher
from fastapi.testclient import TestClient
from iceberg_api.engines import routes as engine_routes
from iceberg_core.enums import ScanTaskKind, ScanTaskStatus
from iceberg_core.models import Engine, Finding, FindingEvent, ScanTask
from iceberg_core.secrets import EnvKeyBackend
from sqlmodel import Session, select
from test_results_ingest import (
    FINGERPRINT,
    OTHER_FINGERPRINT,
    Fixture,
    _clean_coverage,
    _finding_payload,
)

REFERENCE = "c" * 64


@pytest.fixture(name="scan_fixture")
def scan_fixture(
    client: TestClient,
    session: Session,
    dispatcher: RecordingDispatcher,
    secret_store: EnvKeyBackend,
    engine_credential: tuple[Engine, dict[str, str]],
) -> Fixture:
    """The same leased-fetch-task harness the results-ingest suite builds on."""
    engine, headers = engine_credential
    return Fixture(client, session, dispatcher, secret_store, engine, headers)


def _coverage(
    *,
    scanned: int = 0,
    failed: int = 0,
    reason: str = "connector_error",
) -> dict[str, Any]:
    """A fetch report with an optional unreadable object, and its gap evidence."""
    report = _clean_coverage(ScanTaskKind.FETCH, scanned=scanned)
    if not failed:
        return report
    report["counts"]["requested"] += failed
    report["counts"]["discovered"] += failed
    report["counts"]["failed"] = failed
    report["reasons"] = [{"outcome": "failed", "reason": reason, "count": failed}]
    report["gaps"] = [
        {"kind": "page", "outcome": "failed", "reason": reason, "reference": REFERENCE}
    ] * failed
    return report


def _batch(fixture: Fixture, task: ScanTask, sequence: int, **body: Any) -> Any:
    payload = {"sequence": sequence, "checkpoint": {"version": "1", "position": {}}} | body
    return fixture.client.post(
        f"/api/v1/scan-tasks/{task.id}/progress", json=payload, headers=fixture.headers
    )


# ─── A batch is durable ───────────────────────────────────────────────────────


def test_a_batch_stores_its_findings_and_its_resume_point(scan_fixture: Fixture) -> None:
    fixture = scan_fixture
    task = fixture.fetch_task()

    response = _batch(
        fixture,
        task,
        1,
        checkpoint={"version": "1", "position": {"after": "page-7"}},
        findings=[_finding_payload()],
        counts={"units": 1},
        coverage=_coverage(scanned=1),
    )

    assert response.status_code == 200, response.text
    assert response.json()["findings_ingested"] == 1
    fixture.session.refresh(task)
    assert task.checkpoint == {"version": "1", "position": {"after": "page-7"}}
    assert task.checkpoint_sequence == 1
    assert task.status is not ScanTaskStatus.COMPLETED


def test_a_batch_does_not_finish_the_task_or_the_scan(scan_fixture: Fixture) -> None:
    """A batch says "this much is safe", never "this task is done"."""
    fixture = scan_fixture
    task = fixture.fetch_task()

    _batch(fixture, task, 1, findings=[_finding_payload()], coverage=_coverage(scanned=1))

    fixture.session.refresh(task)
    fixture.session.refresh(fixture.scan)
    assert task.finished_at is None
    assert fixture.scan.finished_at is None


def test_coverage_accumulates_across_batches(scan_fixture: Fixture) -> None:
    fixture = scan_fixture
    task = fixture.fetch_task()

    _batch(fixture, task, 1, coverage=_coverage(scanned=2))
    _batch(fixture, task, 2, coverage=_coverage(scanned=3))

    fixture.session.refresh(task)
    assert task.coverage["counts"]["scanned"] == 5
    assert task.coverage["counts"]["discovered"] == 5


# ─── A batch that should not be accepted ──────────────────────────────────────


def test_a_replayed_batch_ingests_nothing_and_says_so(scan_fixture: Fixture) -> None:
    """The engine's response was lost, not its work. Re-sending must be free."""
    fixture = scan_fixture
    task = fixture.fetch_task()
    _batch(fixture, task, 1, findings=[_finding_payload()], coverage=_coverage(scanned=1))

    response = _batch(
        fixture, task, 1, findings=[_finding_payload()], coverage=_coverage(scanned=1)
    )

    assert response.status_code == 200
    assert response.json() == {
        "task_id": str(task.id),
        "sequence": 1,
        "replay": True,
        "findings_ingested": 0,
        "findings_suppressed": 0,
        "findings_reopened": 0,
        "findings_below_threshold": 0,
    }
    fixture.session.refresh(task)
    assert task.coverage["counts"]["scanned"] == 1


@pytest.mark.parametrize("sequence", [3, 5])
def test_a_batch_that_skips_ahead_is_refused(scan_fixture: Fixture, sequence: int) -> None:
    """Accepting it would store a checkpoint past findings that never arrived."""
    fixture = scan_fixture
    task = fixture.fetch_task()
    _batch(fixture, task, 1, coverage=_coverage(scanned=1))

    response = _batch(fixture, task, sequence, coverage=_coverage(scanned=1))

    assert response.status_code == 200
    assert response.json()["replay"] is True
    fixture.session.refresh(task)
    assert task.checkpoint_sequence == 1


def test_a_batch_after_the_results_were_submitted_is_a_conflict(scan_fixture: Fixture) -> None:
    fixture = scan_fixture
    task = fixture.fetch_task()
    fixture.report(task, coverage=_coverage(scanned=1), counts={"units": 1})

    response = _batch(fixture, task, 1, coverage=_coverage(scanned=1))

    assert response.status_code == 409


def test_a_batch_from_another_engine_is_refused(
    scan_fixture: Fixture,
    client: TestClient,
    session: Session,
) -> None:
    fixture = scan_fixture
    task = fixture.fetch_task()
    from iceberg_api.engines.auth import mint_token

    other = mint_token(Engine(name="other-engine", token_hash=""))
    session.add(other.engine)
    session.commit()

    response = client.post(
        f"/api/v1/scan-tasks/{task.id}/progress",
        json={"sequence": 1, "checkpoint": {}},
        headers={"Authorization": f"Bearer {other.token}"},
    )

    assert response.status_code == 403


def test_a_discovery_task_cannot_batch(scan_fixture: Fixture) -> None:
    """A partial discovery has nothing safe to store: specs mean nothing until all
    of them are in."""
    fixture = scan_fixture
    fixture.lease(fixture.discovery)
    fixture.session.refresh(fixture.discovery)

    response = _batch(fixture, fixture.discovery, 1)

    assert response.status_code == 422
    assert "fetch tasks" in response.json()["detail"]


# ─── The terminal submission merges rather than replaces ──────────────────────


def test_the_final_submission_adds_its_remainder_to_the_batches(scan_fixture: Fixture) -> None:
    fixture = scan_fixture
    task = fixture.fetch_task()
    _batch(fixture, task, 1, coverage=_coverage(scanned=4))

    fixture.report(task, checkpoint_sequence=1, coverage=_coverage(scanned=2), counts={"units": 2})

    fixture.session.refresh(task)
    assert task.status is ScanTaskStatus.COMPLETED
    assert task.coverage["counts"]["scanned"] == 6


def test_a_failure_in_an_early_batch_still_fails_the_task(scan_fixture: Fixture) -> None:
    """The reason `_effective_outcome` judges the task rather than the last body.

    The engine reports each batch's coverage separately, so an unreadable page in
    batch one is simply absent from the terminal submission. Trusting that body
    alone would mark the task completed, which would let a source-wide
    reconciliation treat unread content as evidence its findings disappeared.
    """
    fixture = scan_fixture
    task = fixture.fetch_task()
    _batch(fixture, task, 1, coverage=_coverage(scanned=1, failed=1))

    response = fixture.report(
        task,
        checkpoint_sequence=1,
        status="completed",
        coverage=_coverage(scanned=3),
        counts={"units": 3},
    )

    assert response.status_code == 200
    fixture.session.refresh(task)
    assert task.status is ScanTaskStatus.FAILED
    assert task.error == "coverage report contains uninspected requested content"


def test_a_task_with_no_batches_is_judged_exactly_as_before(scan_fixture: Fixture) -> None:
    """The compatibility path: sequence zero means the body is the whole task."""
    fixture = scan_fixture
    task = fixture.fetch_task()

    fixture.report(task, coverage=_coverage(scanned=2), counts={"units": 2})

    fixture.session.refresh(task)
    assert task.status is ScanTaskStatus.COMPLETED
    assert task.coverage["counts"]["scanned"] == 2


def test_a_submission_disagreeing_about_the_batch_count_is_a_conflict(
    scan_fixture: Fixture,
) -> None:
    """Merging a remainder onto the wrong base would invent coverage."""
    fixture = scan_fixture
    task = fixture.fetch_task()
    _batch(fixture, task, 1, coverage=_coverage(scanned=1))

    response = fixture.report(task, checkpoint_sequence=4, coverage=_coverage(scanned=1))

    assert response.status_code == 409


# ─── Nothing duplicates (AC 1) ────────────────────────────────────────────────


def test_the_same_finding_in_a_batch_and_the_final_body_stays_one_row(
    scan_fixture: Fixture,
) -> None:
    fixture = scan_fixture
    task = fixture.fetch_task()
    _batch(fixture, task, 1, findings=[_finding_payload()], coverage=_coverage(scanned=1))

    fixture.report(
        task,
        checkpoint_sequence=1,
        findings=[_finding_payload(), _finding_payload(OTHER_FINGERPRINT)],
        coverage=_coverage(scanned=2),
        counts={"units": 2},
    )

    findings = fixture.session.exec(select(Finding)).all()
    assert {finding.fingerprint for finding in findings} == {FINGERPRINT, OTHER_FINGERPRINT}
    events = fixture.session.exec(select(FindingEvent)).all()
    assert events == []


# ─── The lease hands the position back ────────────────────────────────────────


def test_a_released_task_is_told_where_it_got_to(scan_fixture: Fixture) -> None:
    fixture = scan_fixture
    task = fixture.fetch_task()
    _batch(
        fixture,
        task,
        1,
        checkpoint={"version": "1", "position": {"after": "page-7"}},
        coverage=_coverage(scanned=1),
    )

    # Reclaimed: the lease lapses and the task is queued again.
    task.status = ScanTaskStatus.QUEUED
    task.engine_id = None
    fixture.session.add(task)
    fixture.session.commit()

    lease = fixture.lease(task)

    assert lease["checkpoint"] == {"version": "1", "position": {"after": "page-7"}}
    assert lease["checkpoint_sequence"] == 1


def test_a_checkpoint_taken_under_a_different_rulepack_is_not_handed_back(
    scan_fixture: Fixture,
) -> None:
    """Resuming would skip content the new rules have never been shown."""
    fixture = scan_fixture
    task = fixture.fetch_task()
    _batch(
        fixture,
        task,
        1,
        checkpoint={"version": "1", "position": {"after": "page-7"}},
        rulepack_version="2026.07.1",
        coverage=_coverage(scanned=1),
    )

    fixture.scan.rulepack_version = "2026.08.1"
    task.status = ScanTaskStatus.QUEUED
    task.engine_id = None
    fixture.session.add(fixture.scan)
    fixture.session.add(task)
    fixture.session.commit()

    lease = fixture.lease(task)

    assert lease["checkpoint"] == {}
    # The batch counter is deliberately not rewound: it is the idempotency guard,
    # and rewinding it would let a replayed batch be accepted a second time.
    assert lease["checkpoint_sequence"] == 1


def test_a_fresh_task_is_handed_no_position_at_all(scan_fixture: Fixture) -> None:
    fixture = scan_fixture
    fixture.lease(fixture.discovery)
    fixture.session.refresh(fixture.discovery)
    fixture.report(
        fixture.discovery,
        task_specs=[{"page_ids": ["1"]}],
        coverage=_clean_coverage(ScanTaskKind.DISCOVERY, scope_discovered=1),
    )
    task = fixture.session.exec(
        select(ScanTask)
        .where(ScanTask.scan_id == fixture.scan.id)
        .where(ScanTask.kind == ScanTaskKind.FETCH)
    ).one()

    lease = fixture.lease(task)

    assert lease["checkpoint"] == {}
    assert lease["checkpoint_sequence"] == 0
    assert lease["cursors"] == {}
    assert lease["mode"] == "full"


# ─── The two writers take their locks in one order (#197) ────────────────────


def _statement_index(function: ast.FunctionDef | ast.AsyncFunctionDef, needle: str) -> int:
    """Where in the body the first statement mentioning ``needle`` appears."""
    for index, statement in enumerate(function.body):
        if needle in ast.dump(statement):
            return index
    raise AssertionError(f"{function.name} no longer contains {needle!r}")


@pytest.mark.parametrize("handler", ["submit_progress", "submit_results"])
def test_both_submission_paths_lock_the_scan_before_the_task(handler: str) -> None:
    """Read from the source, because there is nothing to observe at runtime.

    Both handlers take the same two row locks: the scan, `FOR UPDATE`, and the
    task, through a conditional UPDATE. Taken in opposite orders they are the
    textbook AB/BA deadlock — a retried progress racing the same task's final
    results. Postgres aborts one side and the engine's retry ladder recovers, so
    it would have been rare and confusing rather than fatal; the ordering is free
    to fix and impossible to keep right by memory. SQLite has no `FOR UPDATE` at
    all, so no test that runs these routes could ever catch it (#197).
    """
    tree = ast.parse(Path(engine_routes.__file__).read_text(encoding="utf-8"))
    function = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.AsyncFunctionDef | ast.FunctionDef) and node.name == handler
    )

    scan_lock = _statement_index(function, "with_for_update")
    task_write = _statement_index(
        function, "advance_checkpoint" if handler == "submit_progress" else "claim_result"
    )

    assert scan_lock < task_write, f"{handler} locks the task before the scan"
