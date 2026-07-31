"""The in-process maintenance loop (#33, #35, #40).

A handful of jobs run on a timer in every API replica, and a Postgres advisory lock
decides which replica actually does them:

* **the scheduler tick** — fire due schedules;
* **lease reclaim** — return work from engines that stopped heartbeating;
* **the safety sweeps** — repair scans a crash left wedged;
* **suppression lapse** — return findings whose suppression has expired.

They live in the API rather than in a separate cron container because both need the
database and neither needs a connector: an extra deployable would be one more thing
to run, monitor, and forget to scale.

Failures are logged and the loop continues. A tick that raises must not take the API
down with it, and the next beat is a minute away.
"""

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime

import structlog
from iceberg_core.config import ApiSettings, get_api_settings
from iceberg_core.db import session_scope
from iceberg_core.secrets import SecretStore, build_secret_store

from iceberg_api import suppressions
from iceberg_api.dispatch import Dispatcher, build_dispatcher
from iceberg_api.notifications import dispatch as notification_dispatch
from iceberg_api.scans import service
from iceberg_api.scheduler import postgres_advisory_lock, tick
from iceberg_api.scheduler_launcher import build_launcher

logger = structlog.get_logger()


def run_once(
    dispatcher: Dispatcher,
    *,
    now: datetime | None = None,
    settings: ApiSettings | None = None,
    store: SecretStore | None = None,
) -> None:
    """One maintenance round: schedules, reclaim, the safety sweeps, then alerts.

    Leadership is held on a session of its own for the whole round. Holding it on
    the working session would not work: ``pg_try_advisory_xact_lock`` releases at
    transaction end, and the scan launcher commits mid-tick — so the lock would be
    gone after the first schedule fired, and every replica would run the rest of
    the round at once. The guard session runs no other statements, so its
    transaction — and the lock — spans everything below.

    ``settings``/``store`` are injectable so a test can drive a round without a
    configured SMTP relay; both default to the process configuration.
    """
    at = now or datetime.now(UTC)
    resolved = settings or get_api_settings()
    secret_store = store or build_secret_store(resolved)
    with session_scope() as guard:
        if not postgres_advisory_lock(guard):
            # Another replica is doing this round — the whole round, sweeps
            # included, so that two replicas cannot re-dispatch the same task
            # twice in one beat.
            logger.debug("maintenance_round_not_leader")
            return
        with session_scope() as db:
            tick(db, now=at, launcher=build_launcher(dispatcher), lock=_already_leader)
        with session_scope() as db:
            service.reclaim_expired_leases(db, dispatcher=dispatcher, now=at)
        # The safety nets (ADR 0009): a crash between the commit that ends a task
        # and its follow-up work can strand a queued task with no broker message,
        # or leave a scan active with every task terminal. Each sweep repairs one
        # of those, so a wedged scan is a delayed scan instead of a stuck source.
        with session_scope() as db:
            service.redispatch_stale_tasks(db, dispatcher=dispatcher, now=at)
        with session_scope() as db:
            service.finalize_stalled_scans(db, now=at)
        # Expiry is a property of the clock, not of the scan schedule: without this
        # a lapsed suppression would keep hiding findings until the next scan of
        # that source, which for a weekly cadence is six days of silence (ADR 0008).
        with session_scope() as db:
            suppressions.release_lapsed(db, now=at)
        # Announcements queued by reconciliation (#60). Sending here rather than at
        # ingest means a webhook that hangs for its full timeout delays an alert
        # instead of an engine's result submission, and a receiver that is down
        # gets retried on the next beat instead of losing the alert.
        with session_scope() as db:
            notification_dispatch.deliver_pending(db, resolved, secret_store, now=at)


def _already_leader(db: object) -> bool:
    """The tick's lock hook when :func:`run_once` already holds the round lock."""
    return True


@asynccontextmanager
async def background_maintenance(settings: ApiSettings | None = None) -> AsyncIterator[None]:
    """Run :func:`run_once` on a cadence for as long as the app is up."""
    resolved = settings or get_api_settings()
    dispatcher = build_dispatcher(resolved)
    task = asyncio.create_task(_loop(resolved.background_interval_seconds, dispatcher))
    logger.info("maintenance_loop_started", interval=resolved.background_interval_seconds)
    try:
        yield
    finally:
        task.cancel()
        # Awaiting the cancellation means shutdown does not leave a half-finished
        # round holding a database session.
        await asyncio.gather(task, return_exceptions=True)
        logger.info("maintenance_loop_stopped")


async def _loop(interval_seconds: int, dispatcher: Dispatcher) -> None:
    while True:
        await asyncio.sleep(interval_seconds)
        try:
            # to_thread because everything below is blocking SQLAlchemy.
            await asyncio.to_thread(run_once, dispatcher)
        except Exception:  # a bad round must not stop the loop
            logger.exception("maintenance_round_failed")
