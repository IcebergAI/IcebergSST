"""Scan and task lifecycle (#34, #35, #37 — ADR 0009).

The API is the single source of truth for task state. Everything that changes it
lives here, so the invariants are in one file rather than spread across routes:

* **Two-phase.** A scan starts as one *discovery* task. An engine runs the
  connector and posts back specs; those become *fetch* tasks. The control plane
  never runs connector code (ADR 0002).
* **One active scan per source**, enforced by a partial unique index. The database
  refuses the second one, so two replicas racing to launch cannot both win.
* **The lease is the authority.** Claiming is a conditional UPDATE, so two engines
  leasing the same task means one gets it and one gets nothing.
* **Completion is counted atomically**, and the transition that finishes the last
  task is the one that reconciles — exactly once, whichever task it happens to be.
* **Reconciliation only for `completed`.** A partial or failed scan resolves
  nothing: one failed space must not mass-resolve the findings it never saw.
"""

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from iceberg_core.enums import (
    ACTIVE_SCAN_STATUSES,
    ScanStatus,
    ScanTaskKind,
    ScanTaskStatus,
    ScanTrigger,
)
from iceberg_core.metrics import LEASE_RECLAIMS, SCAN_TASKS_COMPLETED, SCANS_STARTED
from iceberg_core.models import Scan, ScanTask, Source
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, col, select, update

from iceberg_api.dispatch import Dispatcher

#: How long a lease is good for without a heartbeat. Long enough for a slow
#: Confluence page fetch, short enough that a dead engine's work is re-dispatched
#: while the scan is still running.
DEFAULT_LEASE_SECONDS = 300

#: Task states that still belong to a live engine.
LEASED_STATUSES = (ScanTaskStatus.LEASED, ScanTaskStatus.RUNNING)

#: Task states that will never change again.
TERMINAL_TASK_STATUSES = (
    ScanTaskStatus.COMPLETED,
    ScanTaskStatus.FAILED,
    ScanTaskStatus.CANCELLED,
)

logger = structlog.get_logger()


class ScanConflict(Exception):
    """This source already has an active scan (ADR 0009 §3)."""


@dataclass(frozen=True, slots=True)
class LeaseGrant:
    """A successful claim: the task, and when the claim lapses."""

    task: ScanTask
    expires_at: datetime


def launch_scan(
    db: Session,
    source: Source,
    *,
    trigger: ScanTrigger,
    dispatcher: Dispatcher,
    now: datetime | None = None,
) -> Scan:
    """Create a scan with its discovery task and dispatch it.

    Raises :class:`ScanConflict` if the source already has an active scan — the
    partial unique index is what detects it, so the answer is the same however many
    replicas try at once.
    """
    started_at = now or datetime.now(UTC)
    scan = Scan(
        source_id=source.id,
        trigger=trigger,
        status=ScanStatus.QUEUED,
        started_at=started_at,
    )
    db.add(scan)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise ScanConflict(f"source {source.name!r} already has an active scan") from exc

    task = ScanTask(
        scan_id=scan.id,
        kind=ScanTaskKind.DISCOVERY,
        # Discovery gets no spec: what to fetch is what it is about to find out.
        spec={},
        status=ScanTaskStatus.QUEUED,
    )
    db.add(task)
    db.commit()
    db.refresh(scan)

    # Dispatched after the commit: a message for a task that does not exist yet is
    # a lease failure and a confused engine.
    dispatcher.enqueue(task.id)
    SCANS_STARTED.labels(trigger=trigger.value).inc()
    logger.info(
        "scan_launched",
        scan_id=str(scan.id),
        source_id=str(source.id),
        trigger=trigger.value,
        discovery_task_id=str(task.id),
    )
    return scan


def fan_out_fetch_tasks(
    db: Session,
    scan: Scan,
    specs: list[dict[str, Any]],
    *,
    dispatcher: Dispatcher,
) -> list[ScanTask]:
    """Turn discovery output into fetch tasks and dispatch them.

    A discovery that found nothing is not an error — an empty space, or a scope
    filter that matches nothing. The scan simply has no fetch work and finishes.
    """
    tasks = [
        ScanTask(
            scan_id=scan.id,
            kind=ScanTaskKind.FETCH,
            spec=spec,
            status=ScanTaskStatus.QUEUED,
        )
        for spec in specs
    ]
    for task in tasks:
        db.add(task)

    scan.status = ScanStatus.RUNNING
    db.add(scan)
    db.commit()

    for task in tasks:
        dispatcher.enqueue(task.id)
    logger.info("scan_fanned_out", scan_id=str(scan.id), fetch_tasks=len(tasks))
    return tasks


def claim_task(
    db: Session,
    task_id: uuid.UUID,
    engine_id: uuid.UUID,
    *,
    now: datetime | None = None,
    lease_seconds: int = DEFAULT_LEASE_SECONDS,
) -> LeaseGrant | None:
    """Claim a queued task for one engine, or return None.

    The claim is a conditional UPDATE rather than read-then-write: two engines
    leasing the same task id must not both believe they own it. Returning None
    covers every legitimate reason a lease fails — already leased, already
    finished, cancelled, or gone — and the engine's response to all of them is the
    same: drop the message (ADR 0009 §2).
    """
    at = now or datetime.now(UTC)
    expires_at = at + timedelta(seconds=lease_seconds)

    result = db.exec(
        update(ScanTask)
        .where(col(ScanTask.id) == task_id, col(ScanTask.status) == ScanTaskStatus.QUEUED)
        .values(
            status=ScanTaskStatus.LEASED,
            engine_id=engine_id,
            lease_expires_at=expires_at,
            heartbeat_at=at,
            started_at=at,
            attempts=col(ScanTask.attempts) + 1,
        )
    )
    if result.rowcount != 1:
        db.rollback()
        return None

    task = db.get(ScanTask, task_id)
    if task is None:  # pragma: no cover — the UPDATE just matched it
        db.rollback()
        return None

    scan = db.get(Scan, task.scan_id)
    if scan is not None and scan.status is ScanStatus.QUEUED:
        # A leased discovery task is what "discovering" means.
        scan.status = (
            ScanStatus.DISCOVERING if task.kind is ScanTaskKind.DISCOVERY else ScanStatus.RUNNING
        )
        db.add(scan)

    db.commit()
    db.refresh(task)
    logger.info(
        "scan_task_leased",
        task_id=str(task.id),
        engine_id=str(engine_id),
        attempt=task.attempts,
        expires_at=expires_at.isoformat(),
    )
    return LeaseGrant(task=task, expires_at=expires_at)


def renew_lease(
    db: Session,
    task: ScanTask,
    *,
    now: datetime | None = None,
    lease_seconds: int = DEFAULT_LEASE_SECONDS,
) -> datetime:
    """Extend a live lease. Heartbeats are what stop reclaim from stealing work."""
    at = now or datetime.now(UTC)
    task.heartbeat_at = at
    task.lease_expires_at = at + timedelta(seconds=lease_seconds)
    task.status = ScanTaskStatus.RUNNING
    db.add(task)
    db.commit()
    return task.lease_expires_at


def complete_task(
    db: Session,
    task: ScanTask,
    *,
    status: ScanTaskStatus,
    error: str | None = None,
    now: datetime | None = None,
) -> None:
    """Mark a task terminal. Does not commit; the caller owns the transaction."""
    task.status = status
    task.error = error
    task.finished_at = now or datetime.now(UTC)
    task.lease_expires_at = None
    db.add(task)
    SCAN_TASKS_COMPLETED.labels(kind=task.kind.value, status=status.value).inc()


def finalize_scan_if_done(
    db: Session,
    scan_id: uuid.UUID,
    *,
    now: datetime | None = None,
) -> ScanStatus | None:
    """Finish the scan if every task is terminal. Returns the status this call set.

    Returns ``None`` when work remains **or when another caller finished it first** —
    which is the point. Two tasks completing at the same instant both land here, and
    the conditional UPDATE means exactly one of them gets a status back and
    therefore exactly one reconciliation happens (ADR 0009 §3).
    """
    at = now or datetime.now(UTC)
    statuses = list(db.exec(select(col(ScanTask.status)).where(col(ScanTask.scan_id) == scan_id)))
    if not statuses or any(status not in TERMINAL_TASK_STATUSES for status in statuses):
        return None

    final = _final_status(statuses)
    result = db.exec(
        update(Scan)
        .where(
            col(Scan.id) == scan_id,
            col(Scan.status).in_(list(ACTIVE_SCAN_STATUSES)),
        )
        .values(status=final, finished_at=at)
    )
    if result.rowcount != 1:
        # Someone else finished it (or it was cancelled). Not our reconciliation.
        return None

    db.commit()
    logger.info("scan_finished", scan_id=str(scan_id), status=final.value)
    return final


def _final_status(task_statuses: list[ScanTaskStatus]) -> ScanStatus:
    """Completed if everything worked, partial if some did, failed if none did.

    The distinction is not cosmetic: only ``completed`` allows reconciliation to
    auto-resolve findings (ADR 0009 §4).
    """
    if any(status is ScanTaskStatus.CANCELLED for status in task_statuses):
        return ScanStatus.CANCELLED
    completed = sum(1 for status in task_statuses if status is ScanTaskStatus.COMPLETED)
    if completed == len(task_statuses):
        return ScanStatus.COMPLETED
    return ScanStatus.PARTIAL if completed else ScanStatus.FAILED


def reclaim_expired_leases(
    db: Session,
    *,
    dispatcher: Dispatcher,
    now: datetime | None = None,
) -> list[uuid.UUID]:
    """Return expired-lease tasks to the queue. The only re-delivery mechanism.

    An engine that dies mid-task stops heartbeating; its lease lapses; the task
    becomes queued again and is re-dispatched. Broker retries are disabled precisely
    so that this is the *single* path back onto the queue (ADR 0009 §2).
    """
    at = now or datetime.now(UTC)
    expired = list(
        db.exec(
            select(ScanTask)
            .where(col(ScanTask.status).in_(list(LEASED_STATUSES)))
            .where(col(ScanTask.lease_expires_at).is_not(None))
            .where(col(ScanTask.lease_expires_at) < at)
        )
    )

    reclaimed: list[uuid.UUID] = []
    for task in expired:
        task.status = ScanTaskStatus.QUEUED
        task.engine_id = None
        task.lease_expires_at = None
        db.add(task)
        reclaimed.append(task.id)
    if reclaimed:
        db.commit()

    for task_id in reclaimed:
        dispatcher.enqueue(task_id)
        LEASE_RECLAIMS.inc()
        logger.info("scan_task_lease_reclaimed", task_id=str(task_id))
    return reclaimed


def cancel_scan(db: Session, scan: Scan, *, now: datetime | None = None) -> Scan:
    """Cancel a scan and every task that has not finished (#68).

    Queued tasks are simply marked: an engine discovers the cancellation when its
    lease attempt fails. Running tasks keep their row marked too, and the engine
    finds out at its next heartbeat — there is no way to reach into a worker, and
    pretending otherwise would be worse than saying so.
    """
    at = now or datetime.now(UTC)
    for task in db.exec(select(ScanTask).where(col(ScanTask.scan_id) == scan.id)):
        if task.status not in TERMINAL_TASK_STATUSES:
            task.status = ScanTaskStatus.CANCELLED
            task.finished_at = at
            task.lease_expires_at = None
            db.add(task)

    scan.status = ScanStatus.CANCELLED
    scan.finished_at = at
    db.add(scan)
    db.commit()
    db.refresh(scan)
    logger.info("scan_cancelled", scan_id=str(scan.id))
    return scan


def active_scan_for(db: Session, source_id: uuid.UUID) -> Scan | None:
    """The source's in-flight scan, if it has one."""
    return db.exec(
        select(Scan)
        .where(col(Scan.source_id) == source_id)
        .where(col(Scan.status).in_(list(ACTIVE_SCAN_STATUSES)))
    ).first()
