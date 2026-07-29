"""Putting task ids on the broker (ADR 0009).

The API's whole relationship with Redis is this file: enqueue a task id, forget
about it. No results come back this way — engines POST them — and the message
carries nothing an eavesdropper could use.

The dispatcher is a dependency so that tests can record dispatches instead of
needing Redis, and so an operator running the API without a broker gets a clear
failure at the point of enqueue rather than a stack trace from deep inside
Dramatiq.
"""

import uuid
from functools import lru_cache
from typing import Annotated, Protocol

import dramatiq
import structlog
from dramatiq.brokers.redis import RedisBroker
from dramatiq.brokers.stub import StubBroker
from fastapi import Depends
from iceberg_core.config import ApiSettings
from iceberg_core.tasks import SCAN_TASK_ACTOR, SCAN_TASK_OPTIONS, SCAN_TASK_QUEUE

from iceberg_api.auth.dependencies import SettingsDep

logger = structlog.get_logger()


class Dispatcher(Protocol):
    """Something that can put a scan-task id on the queue."""

    def enqueue(self, task_id: uuid.UUID) -> None: ...


class BrokerDispatcher:
    """The real dispatcher: one Dramatiq message per task id."""

    def __init__(self, broker: dramatiq.Broker) -> None:
        self._broker = broker

    def enqueue(self, task_id: uuid.UUID) -> None:
        # dramatiq.Message is generic over the actor's return type; nothing here
        # collects results, so it is None.
        message: dramatiq.Message[None] = dramatiq.Message(
            queue_name=SCAN_TASK_QUEUE,
            actor_name=SCAN_TASK_ACTOR,
            args=(str(task_id),),
            kwargs={},
            options=dict(SCAN_TASK_OPTIONS),
        )
        self._broker.enqueue(message)
        logger.info("scan_task_dispatched", task_id=str(task_id))


@lru_cache(maxsize=1)
def _broker_for(redis_url: str) -> dramatiq.Broker:
    """One broker per process.

    A stub broker when no Redis URL is configured: the API stays usable for
    everything that is not dispatch (reading findings, managing sources) instead of
    refusing to start, and the dispatch itself is a visible no-op in the logs.
    """
    if not redis_url:
        logger.warning("dispatch_broker_missing", detail="no ICEBERG_REDIS_URL; using a stub")
        return StubBroker()
    broker: dramatiq.Broker = RedisBroker(url=redis_url)  # type: ignore[no-untyped-call]
    broker.declare_queue(SCAN_TASK_QUEUE)
    return broker


def build_dispatcher(settings: ApiSettings) -> Dispatcher:
    return BrokerDispatcher(_broker_for(settings.redis_url))


def get_dispatcher(settings: SettingsDep) -> Dispatcher:
    """The dispatcher as a dependency, so tests can record instead of enqueue."""
    return build_dispatcher(settings)


DispatcherDep = Annotated[Dispatcher, Depends(get_dispatcher)]


def reset_broker_cache() -> None:
    """Drop the cached broker. For tests."""
    _broker_for.cache_clear()
