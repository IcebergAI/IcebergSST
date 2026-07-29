"""Engine worker bootstrap.

Actors arrive with M2. This module establishes what every actor will inherit:
JSON logs carrying a per-message ``task_id`` correlation id, and a standalone
Prometheus metrics server (engines have no web framework to piggyback on).

The deployed entrypoint is the Dramatiq CLI — ``dramatiq iceberg_engine.worker:broker``
(see ``deploy/docker/engine.Dockerfile``). Dramatiq imports this module and
consumes from the broker bound at the bottom of it, so broker registration has
to happen at import. The observability side effects must not: the CLI imports
this module in the parent process before forking workers, and pytest imports it
every session, so binding a metrics port or reconfiguring logging at import
would fight both. They are deferred to the worker-boot hooks instead.

Engines talk to Redis and the API only — never the database (ADR 0002).
"""

import os

import dramatiq
import structlog
from dramatiq.broker import MessageProxy
from dramatiq.brokers.redis import RedisBroker
from dramatiq.brokers.stub import StubBroker
from dramatiq.worker import Worker
from iceberg_core import metrics as _metrics  # noqa: F401  # registers iceberg_* series
from iceberg_core.logging import configure_logging
from prometheus_client import start_http_server

DEFAULT_METRICS_PORT = 9191

logger = structlog.get_logger()


class CorrelationMiddleware(dramatiq.Middleware):
    """Bind the broker message id as ``task_id`` for the duration of a message."""

    def before_process_message(self, broker: dramatiq.Broker, message: MessageProxy) -> None:
        structlog.contextvars.bind_contextvars(task_id=message.message_id)

    def after_process_message(
        self,
        broker: dramatiq.Broker,
        message: MessageProxy,
        *,
        result: object | None = None,
        exception: BaseException | None = None,
    ) -> None:
        structlog.contextvars.unbind_contextvars("task_id")

    def after_skip_message(self, broker: dramatiq.Broker, message: MessageProxy) -> None:
        structlog.contextvars.unbind_contextvars("task_id")


class ObservabilityMiddleware(dramatiq.Middleware):
    """Bring up logging and the metrics endpoint when a worker process boots.

    Bound only to the deployed broker below, never by :func:`build_broker`, so
    that tests constructing their own broker keep control of their logging
    stream and never bind a port.
    """

    def __init__(self, *, metrics_port: int) -> None:
        self.metrics_port = metrics_port

    def before_worker_boot(self, broker: dramatiq.Broker, worker: Worker) -> None:
        configure_logging(role="engine")

    def after_worker_boot(self, broker: dramatiq.Broker, worker: Worker) -> None:
        # Deliberately unguarded: one metrics endpoint per container is the
        # deal (hence ``--processes 1`` in the image), and an engine that
        # silently scans without being observable is worse than one that
        # refuses to start.
        start_http_server(self.metrics_port)
        logger.info(
            "engine_worker_ready",
            metrics_port=self.metrics_port,
            # A StubBroker here means ICEBERG_REDIS_URL was never set — the
            # worker would idle forever consuming nothing, so name it.
            broker=type(broker).__name__,
        )


def build_broker(redis_url: str | None = None) -> dramatiq.Broker:
    """Return the configured broker: Redis when a URL is given, stub otherwise.

    The stub fallback keeps tests and local smoke runs broker-free; real
    deployments always set ``ICEBERG_REDIS_URL``.
    """
    broker: dramatiq.Broker = (
        RedisBroker(url=redis_url)  # type: ignore[no-untyped-call]  # RedisBroker.__init__ lacks hints
        if redis_url
        else StubBroker()
    )
    broker.add_middleware(CorrelationMiddleware())
    dramatiq.set_broker(broker)
    return broker


# The broker the Dramatiq CLI consumes from. Importing this module is what
# builds it, which is why nothing here may bind a port or write to a log.
broker = build_broker(os.environ.get("ICEBERG_REDIS_URL"))
broker.add_middleware(
    ObservabilityMiddleware(
        metrics_port=int(os.environ.get("ICEBERG_METRICS_PORT", DEFAULT_METRICS_PORT))
    )
)
