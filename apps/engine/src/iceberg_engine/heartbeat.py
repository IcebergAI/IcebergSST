"""Keeping leases alive, and hearing about cancellations (#51 — ADR 0009).

A lease lasts five minutes. A scan task can easily take longer, and an engine that
stays silent has its task reclaimed and handed to somebody else while it is still
working — the first engine then submits results for a task it no longer owns, and
the API answers 409. Nothing is corrupted, but the work is wasted and the scan is
slower than it needed to be.

So a background thread beats every minute, naming the tasks this process holds.
The interval is a fifth of the lease on purpose: four consecutive failures can
pass before anything is actually lost, which is the difference between a blip and
an outage.

The reply matters as much as the request. **A heartbeat is the only way a running
engine learns its work was cancelled** — there is no way to reach into a worker
(ADR 0009 §4) — so the cancelled ids come back here and land in the registry the
runner checks.
"""

import threading
import uuid
from collections import Counter
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import structlog
from iceberg_core.metrics import ENGINE_HEARTBEAT_FAILURES

from iceberg_engine.api_client import EngineApiError, EngineClient

logger = structlog.get_logger()

#: A fifth of the API's 300-second lease: four failed beats before anything lapses.
DEFAULT_INTERVAL_SECONDS = 60.0


class TaskRegistry:
    """Which tasks this process holds, and which the API has cancelled.

    Shared between the worker threads doing the tasks and the heartbeat thread
    reporting them, so every method takes the lock. The contents are small — one
    id per in-flight task — and the operations are set arithmetic, so contention
    is not a concern worth designing around.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # Reference-counted, not a set: a reclaimed task can be redelivered to this
        # same process and run in a second thread while the first is still going.
        # A set would let the first thread's cleanup de-register the live attempt,
        # stranding its lease. The id stays held until the last holder releases it.
        self._held: Counter[uuid.UUID] = Counter()
        self._cancelled: set[uuid.UUID] = set()

    @contextmanager
    def holding(self, task_id: uuid.UUID) -> Iterator[None]:
        """Register a task for the duration of the work.

        Releasing in a ``finally`` matters more than it looks: a task left
        registered after it finished would keep being heartbeated, renewing a
        lease on work nobody is doing and delaying the API's reclaim of it.
        """
        with self._lock:
            self._held[task_id] += 1
        try:
            yield
        finally:
            with self._lock:
                self._held[task_id] -= 1
                if self._held[task_id] <= 0:
                    del self._held[task_id]
                    self._cancelled.discard(task_id)

    def held(self) -> list[uuid.UUID]:
        with self._lock:
            return sorted(self._held)

    def note_cancelled(self, task_ids: list[uuid.UUID]) -> None:
        with self._lock:
            # Only tasks we actually hold: a cancellation for something this
            # process finished is stale news, and remembering it would make a
            # later task with a recycled id look cancelled.
            self._cancelled |= set(task_ids) & set(self._held)

    def is_cancelled(self, task_id: uuid.UUID) -> bool:
        with self._lock:
            return task_id in self._cancelled


class Heartbeat:
    """The background thread that renews leases for as long as the process runs."""

    def __init__(
        self,
        client: EngineClient,
        registry: TaskRegistry,
        *,
        interval_seconds: float = DEFAULT_INTERVAL_SECONDS,
        version: str | None = None,
        rulepack: dict[str, Any] | None = None,
    ) -> None:
        self._client = client
        self._registry = registry
        self._interval = interval_seconds
        self._version = version
        self._rulepack = rulepack
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def beat_once(self) -> list[uuid.UUID]:
        """One beat. Returns the tasks the API says are cancelled.

        Failures are logged and swallowed. A control plane that is briefly
        unreachable should cost a beat, not the thread — and the next one is a
        minute away, well inside the lease.
        """
        try:
            cancelled = self._client.heartbeat(
                task_ids=self._registry.held(),
                version=self._version,
                rulepack=self._rulepack,
            )
        except EngineApiError as exc:
            logger.warning("heartbeat_failed", error=str(exc))
            ENGINE_HEARTBEAT_FAILURES.inc()
            return []

        if cancelled:
            logger.info("tasks_cancelled", task_ids=[str(task_id) for task_id in cancelled])
            self._registry.note_cancelled(cancelled)
        return cancelled

    def start(self) -> None:
        if self._thread is not None:  # pragma: no cover — defensive
            return
        self._thread = threading.Thread(target=self._run, name="heartbeat", daemon=True)
        self._thread.start()
        logger.info("heartbeat_started", interval_seconds=self._interval)

    def stop(self, *, timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None
        logger.info("heartbeat_stopped")

    def _run(self) -> None:
        # `Event.wait` rather than `sleep`, so shutdown is prompt instead of
        # taking up to a full interval.
        while not self._stop.wait(self._interval):
            try:
                self.beat_once()
            except Exception:  # a single bad beat must never end the thread
                # If the thread died, leases would silently stop renewing and every
                # long task would be reclaimed and rescanned forever, with only a
                # threadexcepthook trace to show for it. Log and beat again.
                logger.exception("heartbeat_beat_crashed")
