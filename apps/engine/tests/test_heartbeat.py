"""Lease renewal and cancellation delivery (#51 — ADR 0009).

Two jobs, one thread. Renewing is why it exists: a lease lasts five minutes and a
scan task can take longer, and a silent engine has its work reclaimed and handed
to somebody else while it is still doing it. Cancellation is what comes back — a
heartbeat is the *only* way a running engine learns its task was cancelled.

The thread itself is exercised through `beat_once`, so the tests assert behaviour
rather than wait on a timer. `start`/`stop` get one test of their own.
"""

import threading
import uuid
from typing import Any

import httpx2
import pytest
from iceberg_engine.api_client import EngineClient
from iceberg_engine.heartbeat import Heartbeat, TaskRegistry

TASK_A = uuid.UUID("11111111-1111-1111-1111-111111111111")
TASK_B = uuid.UUID("22222222-2222-2222-2222-222222222222")
ENGINE_ID = uuid.UUID("33333333-3333-3333-3333-333333333333")


class Api:
    """Records heartbeats and answers with whatever cancellations are queued."""

    def __init__(self, *, cancelled: list[str] | None = None, status: int = 200) -> None:
        self.cancelled = cancelled or []
        self.status = status
        self.bodies: list[dict[str, Any]] = []

    def __call__(self, request: httpx2.Request) -> httpx2.Response:
        import json

        self.bodies.append(json.loads(request.content))
        if self.status != 200:
            return httpx2.Response(self.status)
        return httpx2.Response(200, json={"cancelled_task_ids": self.cancelled})


def _client(api: Api) -> EngineClient:
    return EngineClient(
        base_url="http://api.test",
        token="engine-token",
        engine_id=ENGINE_ID,
        transport=httpx2.MockTransport(api),
        sleep=lambda _seconds: None,
    )


# ─── The registry ─────────────────────────────────────────────────────────────


def test_a_held_task_is_reported_and_released_when_done() -> None:
    """Releasing matters: a task left registered keeps renewing a lease on work
    nobody is doing, delaying the API's reclaim of it."""
    tasks = TaskRegistry()

    with tasks.holding(TASK_A):
        assert tasks.held() == [TASK_A]

    assert tasks.held() == []


def test_a_task_is_released_even_when_the_work_raises() -> None:
    tasks = TaskRegistry()

    with pytest.raises(RuntimeError), tasks.holding(TASK_A):
        raise RuntimeError("the scan blew up")

    assert tasks.held() == []


def test_cancellations_apply_only_to_tasks_this_process_holds() -> None:
    """A cancellation for something already finished is stale news, and keeping it
    would make a later task look cancelled."""
    tasks = TaskRegistry()

    with tasks.holding(TASK_A):
        tasks.note_cancelled([TASK_A, TASK_B])

        assert tasks.is_cancelled(TASK_A)
        assert not tasks.is_cancelled(TASK_B)


def test_finishing_a_task_forgets_its_cancellation() -> None:
    tasks = TaskRegistry()
    with tasks.holding(TASK_A):
        tasks.note_cancelled([TASK_A])

    with tasks.holding(TASK_A):
        assert not tasks.is_cancelled(TASK_A)


def test_a_redelivered_task_stays_held_until_the_last_holder_finishes() -> None:
    """A reclaimed task can run again in this same process before the first attempt
    finishes. The first attempt's cleanup must not de-register the second, or the
    live attempt's lease would silently stop renewing."""
    tasks = TaskRegistry()

    outer = tasks.holding(TASK_A)
    outer.__enter__()
    inner = tasks.holding(TASK_A)
    inner.__enter__()

    inner.__exit__(None, None, None)  # first attempt finishes
    assert tasks.held() == [TASK_A]  # second attempt still holds it

    outer.__exit__(None, None, None)
    assert tasks.held() == []


def test_a_cancellation_survives_until_every_holder_of_the_id_is_done() -> None:
    tasks = TaskRegistry()
    outer = tasks.holding(TASK_A)
    outer.__enter__()
    inner = tasks.holding(TASK_A)
    inner.__enter__()

    tasks.note_cancelled([TASK_A])
    inner.__exit__(None, None, None)
    assert tasks.is_cancelled(TASK_A)  # still held by the outer attempt

    outer.__exit__(None, None, None)


def test_the_registry_is_safe_across_threads() -> None:
    """The worker threads write it and the heartbeat thread reads it."""
    tasks = TaskRegistry()
    ids = [uuid.uuid4() for _ in range(50)]

    def hold(task_id: uuid.UUID) -> None:
        with tasks.holding(task_id):
            tasks.held()

    threads = [threading.Thread(target=hold, args=(task_id,)) for task_id in ids]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert tasks.held() == []


# ─── The beat ─────────────────────────────────────────────────────────────────


def test_a_beat_names_the_tasks_this_engine_holds() -> None:
    api = Api()
    tasks = TaskRegistry()
    heartbeat = Heartbeat(_client(api), tasks)

    with tasks.holding(TASK_A):
        heartbeat.beat_once()

    assert api.bodies[0]["task_ids"] == [str(TASK_A)]


def test_a_beat_records_the_cancellations_it_is_told_about() -> None:
    """The only channel: there is no way to reach into a worker (ADR 0009 §4)."""
    api = Api(cancelled=[str(TASK_A)])
    tasks = TaskRegistry()
    heartbeat = Heartbeat(_client(api), tasks)

    with tasks.holding(TASK_A):
        cancelled = heartbeat.beat_once()

        assert cancelled == [TASK_A]
        assert tasks.is_cancelled(TASK_A)


def test_a_beat_reports_the_rulepack_so_a_rolling_deploy_is_visible() -> None:
    """`GET /rules` is sourced from what the fleet reports (#70)."""
    api = Api()
    pack = {"version": "2026.07.1", "rules": [{"id": "r", "description": "d", "severity": "high"}]}
    heartbeat = Heartbeat(_client(api), TaskRegistry(), version="0.2.0", rulepack=pack)

    heartbeat.beat_once()

    assert api.bodies[0]["rulepack"] == pack
    assert api.bodies[0]["version"] == "0.2.0"


def test_a_failed_beat_is_swallowed_rather_than_killing_the_thread() -> None:
    """A briefly-unreachable control plane should cost a beat, not the loop — and
    the next one is well inside the lease."""
    api = Api(status=503)
    heartbeat = Heartbeat(_client(api), TaskRegistry())

    assert heartbeat.beat_once() == []


def test_a_malformed_cancelled_id_is_skipped_not_fatal() -> None:
    """A bad entry in the reply must not raise on the heartbeat thread and stop
    every lease from renewing; it is dropped and the good ones are kept."""
    api = Api(cancelled=["not-a-uuid", str(TASK_A)])
    heartbeat = Heartbeat(_client(api), TaskRegistry())

    assert heartbeat.beat_once() == [TASK_A]


def test_an_unexpected_beat_error_does_not_end_the_run_loop() -> None:
    """The loop guards every beat: a beat that raised anything at all would
    otherwise silently kill lease renewal for the whole process."""
    tasks = TaskRegistry()
    heartbeat = Heartbeat(_client(Api()), tasks, interval_seconds=0.01)
    beats = {"n": 0}

    def exploding() -> list[uuid.UUID]:
        beats["n"] += 1
        if beats["n"] == 1:
            raise RuntimeError("boom")
        heartbeat.stop()
        return []

    heartbeat.beat_once = exploding  # type: ignore[method-assign]
    heartbeat.start()
    heartbeat._thread.join(timeout=2.0)  # type: ignore[union-attr]

    assert beats["n"] >= 2  # survived the first beat's exception and beat again


def test_the_thread_starts_and_stops() -> None:
    heartbeat = Heartbeat(_client(Api()), TaskRegistry(), interval_seconds=0.01)

    heartbeat.start()
    heartbeat.stop()

    # Stopping twice is what a shutdown path does after an exception.
    heartbeat.stop()
