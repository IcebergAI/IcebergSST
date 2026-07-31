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
from iceberg_api.notifications import dispatch as notification_dispatch
from iceberg_api.scans.reconcile import reconcile_scan

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
    # a lease failure and a confused engine. A lost enqueue is not fatal — the
    # task is durably queued and redispatch_stale_tasks will deliver it.
    try:
        dispatcher.enqueue(task.id)
    except Exception:
        logger.exception("scan_task_dispatch_failed", task_id=str(task.id))
    SCANS_STARTED.labels(trigger=trigger.value).inc()
    logger.info(
        "scan_launched",
        scan_id=str(scan.id),
        source_id=str(source.id),
        trigger=trigger.value,
        discovery_task_id=str(task.id),
    )
    return scan


def create_fetch_tasks(
    db: Session,
    scan: Scan,
    specs: list[dict[str, Any]],
) -> list[ScanTask]:
    """Turn discovery output into fetch tasks. Does not commit or dispatch.

    Runs inside the transaction that completes the discovery task, so a crash
    cannot record the discovery as done while losing what it discovered.

    A discovery that found nothing is not an error — an empty space, or a scope
    filter that matches nothing. The scan simply has no fetch work and finishes.

    The scan's move to ``running`` is a conditional UPDATE: a scan cancelled while
    the discovery results were in flight stays cancelled, and its would-be fetch
    tasks are never created (#68).
    """
    if not specs:
        return []

    result = db.exec(
        update(Scan)
        .where(col(Scan.id) == scan.id, col(Scan.status).in_(list(ACTIVE_SCAN_STATUSES)))
        .values(status=ScanStatus.RUNNING)
    )
    if result.rowcount != 1:
        logger.info("scan_fan_out_refused_inactive", scan_id=str(scan.id))
        return []
    scan.status = ScanStatus.RUNNING  # keep the ORM object in step with the row

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
) -> datetime | None:
    """Extend a live lease. Heartbeats are what stop reclaim from stealing work.

    Conditional, like every lease transition: a task that was reclaimed or
    finished between the caller's read and this write must not be dragged back to
    ``running`` by a stale heartbeat. Returns ``None`` when the lease was lost.
    """
    at = now or datetime.now(UTC)
    expires_at = at + timedelta(seconds=lease_seconds)
    result = db.exec(
        update(ScanTask)
        .where(
            col(ScanTask.id) == task.id,
            col(ScanTask.status).in_(list(LEASED_STATUSES)),
            col(ScanTask.engine_id) == task.engine_id,
        )
        .values(heartbeat_at=at, lease_expires_at=expires_at, status=ScanTaskStatus.RUNNING)
    )
    if result.rowcount != 1:
        db.rollback()
        return None
    db.commit()
    return expires_at


def claim_result(db: Session, task: ScanTask, idempotency_key: str) -> bool:
    """Atomically record which submission owns this task's results. No commit.

    Of two concurrent submissions, exactly one takes ``result_key``; the loser
    sees ``False`` and can tell a replay (same key) from a conflict (different
    key) by re-reading the row. Also refuses when the lease is gone — reclaimed,
    cancelled, or already terminal — because those results are no longer wanted.
    """
    result = db.exec(
        update(ScanTask)
        .where(
            col(ScanTask.id) == task.id,
            col(ScanTask.engine_id) == task.engine_id,
            col(ScanTask.status).in_(list(LEASED_STATUSES)),
            col(ScanTask.result_key).is_(None),
        )
        .values(result_key=idempotency_key)
    )
    if result.rowcount != 1:
        return False
    task.result_key = idempotency_key  # keep the ORM object in step with the row
    return True


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


def finalize_and_reconcile(
    db: Session,
    scan_id: uuid.UUID,
    *,
    now: datetime | None = None,
) -> ScanStatus | None:
    """Finish the scan if its tasks are done, and reconcile if it completed.

    The two halves stay together because a ``completed`` scan that never
    reconciled is exactly the stalled state the safety sweeps exist to repair.
    Safe to call from anywhere: :func:`finalize_scan_if_done` is conditional, so
    concurrent callers agree on a single winner.
    """
    final = finalize_scan_if_done(db, scan_id, now=now)
    if final is ScanStatus.COMPLETED:
        scan = db.get(Scan, scan_id)
        if scan is not None:  # pragma: no branch — the UPDATE just matched it
            db.refresh(scan)
            reconcile_scan(db, scan, now=now)
            # Queue announcements for what this scan opened (#60). Writing the
            # outbox rows here — after reconciliation, so a finding auto-resolved
            # in the same pass is not announced — keeps "the scan finished" and
            # "somebody will be told" in one transaction. Sending happens in the
            # maintenance loop; nothing here talks to SMTP or a webhook.
            if notification_dispatch.enqueue_for_scan(db, scan, now=now):
                db.commit()
    return final


def finalize_stalled_scans(db: Session, *, now: datetime | None = None) -> list[uuid.UUID]:
    """Finish active scans whose tasks are all terminal. The safety net.

    The live path finalizes after each result submission, but that follow-up runs
    in its own transaction: a crash between the two leaves a scan active forever —
    and, through the one-active-scan index, blocks every future scan of its source.
    This sweep is how such a scan eventually settles.
    """
    finished: list[uuid.UUID] = []
    scan_ids = list(
        db.exec(select(col(Scan.id)).where(col(Scan.status).in_(list(ACTIVE_SCAN_STATUSES))))
    )
    for scan_id in scan_ids:
        if finalize_and_reconcile(db, scan_id, now=now) is not None:
            finished.append(scan_id)
            logger.info("stalled_scan_finalized", scan_id=str(scan_id))
    return finished


def redispatch_stale_tasks(
    db: Session,
    *,
    dispatcher: Dispatcher,
    now: datetime | None = None,
    stale_after_seconds: int = DEFAULT_LEASE_SECONDS,
) -> list[uuid.UUID]:
    """Re-enqueue tasks that have sat ``queued`` too long. The other safety net.

    Enqueues happen after the commit that creates a task, so a crash (or a broker
    outage) between the two loses the message while the row stays ``queued`` —
    and nothing else would ever deliver it. Touching ``updated_at`` on each
    re-dispatch paces this to once per stale window rather than every beat.
    """
    at = now or datetime.now(UTC)
    cutoff = at - timedelta(seconds=stale_after_seconds)
    stale = list(
        db.exec(
            select(col(ScanTask.id))
            .where(col(ScanTask.status) == ScanTaskStatus.QUEUED)
            .where(col(ScanTask.updated_at) < cutoff)
        )
    )
    if not stale:
        db.rollback()
        return []

    for task_id in stale:
        db.exec(update(ScanTask).where(col(ScanTask.id) == task_id).values(updated_at=at))
    db.commit()

    for task_id in stale:
        logger.info("scan_task_redispatched", task_id=str(task_id))
        try:
            dispatcher.enqueue(task_id)
        except Exception:  # still queued in the DB; the next sweep retries
            logger.exception("scan_task_redispatch_failed", task_id=str(task_id))
    return stale


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
            select(col(ScanTask.id))
            .where(col(ScanTask.status).in_(list(LEASED_STATUSES)))
            .where(col(ScanTask.lease_expires_at).is_not(None))
            .where(col(ScanTask.lease_expires_at) < at)
        )
    )

    # Conditional per task, not read-then-write: an engine that finishes in the
    # instant between the SELECT and this write must keep its completion — a
    # reclaim that overwrote a just-completed task would resurrect finished work
    # into a lease nobody can ever satisfy.
    reclaimed: list[uuid.UUID] = []
    for task_id in expired:
        result = db.exec(
            update(ScanTask)
            .where(
                col(ScanTask.id) == task_id,
                col(ScanTask.status).in_(list(LEASED_STATUSES)),
                col(ScanTask.lease_expires_at).is_not(None),
                col(ScanTask.lease_expires_at) < at,
            )
            # updated_at is stamped with the caller's clock (not the column
            # onupdate) so redispatch pacing and reclaim agree on time.
            .values(
                status=ScanTaskStatus.QUEUED, engine_id=None, lease_expires_at=None, updated_at=at
            )
            # The datetime predicate cannot be evaluated against in-session
            # objects (SQLite hands back naive datetimes), so sync by re-select.
            .execution_options(synchronize_session="fetch")
        )
        if result.rowcount == 1:
            reclaimed.append(task_id)
    if reclaimed:
        db.commit()
    else:
        db.rollback()

    for task_id in reclaimed:
        LEASE_RECLAIMS.inc()
        logger.info("scan_task_lease_reclaimed", task_id=str(task_id))
        try:
            dispatcher.enqueue(task_id)
        except Exception:  # already queued in the DB; redispatch_stale_tasks retries
            logger.exception("scan_task_redispatch_failed", task_id=str(task_id))
    return reclaimed


def cancel_scan(db: Session, scan: Scan, *, now: datetime | None = None) -> Scan:
    """Cancel a scan and every task that has not finished (#68).

    Queued tasks are simply marked: an engine discovers the cancellation when its
    lease attempt fails. Running tasks keep their row marked too, and the engine
    finds out at its next heartbeat — there is no way to reach into a worker, and
    pretending otherwise would be worse than saying so.

    Both writes are conditional in SQL rather than read-then-write, so a task
    that completes while the cancellation is in flight keeps its completion.
    """
    at = now or datetime.now(UTC)
    db.exec(
        update(ScanTask)
        .where(
            col(ScanTask.scan_id) == scan.id,
            col(ScanTask.status).not_in(list(TERMINAL_TASK_STATUSES)),
        )
        .values(status=ScanTaskStatus.CANCELLED, finished_at=at, lease_expires_at=None)
    )
    db.exec(
        update(Scan)
        .where(col(Scan.id) == scan.id, col(Scan.status).in_(list(ACTIVE_SCAN_STATUSES)))
        .values(status=ScanStatus.CANCELLED, finished_at=at)
    )
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
