"""Engine worker bootstrap — observability baseline only (issue #67).

Actors arrive with M2. This module establishes what every actor will inherit:
JSON logs carrying a per-message ``task_id`` correlation id, and a standalone
Prometheus metrics server (engines have no web framework to piggyback on).

Engines talk to Redis and the API only — never the database (ADR 0002).
"""

import os

import dramatiq
import structlog
from dramatiq.broker import MessageProxy
from dramatiq.brokers.redis import RedisBroker
from dramatiq.brokers.stub import StubBroker
from iceberg_core import metrics as _metrics  # noqa: F401  # registers iceberg_* series
from iceberg_core.config import get_engine_settings
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


def serve_metrics(port: int) -> bool:
    """Expose the Prometheus endpoint, tolerating a sibling that got there first.

    ``dramatiq iceberg_engine.worker`` forks several worker processes and each one
    re-imports this module, so every fork would otherwise race to bind the same
    port and all but one would die with EADDRINUSE. One exporter per container is
    what we want; the losers simply skip it.

    Caveat worth knowing: prometheus_client keeps counters per process, so the
    single exporter reports only the counters of the process that won the bind.
    Aggregating across forks needs multiprocess mode (a shared
    ``PROMETHEUS_MULTIPROC_DIR``) — deferred, since no engine actor increments a
    counter yet. Returns whether this process is the exporter.
    """
    try:
        start_http_server(port)
    except OSError:
        logger.debug("metrics_server_already_bound", metrics_port=port)
        return False
    return True


def bootstrap() -> None:
    """Configure logging, register the broker, and expose metrics.

    Called at **import time** below, not only under ``__main__``: the container
    runs ``dramatiq iceberg_engine.worker``, and the dramatiq CLI imports this
    module and expects to find an already-registered global broker. Guarding this
    behind ``if __name__ == "__main__"`` would leave the CLI with no broker at all.
    """
    settings = get_engine_settings()
    configure_logging(role="engine")
    build_broker(settings.redis_url)
    if serve_metrics(settings.metrics_port):
        logger.info("engine_bootstrap_complete", metrics_port=settings.metrics_port)


def main() -> None:
    """Standalone entrypoint, kept for `python -m iceberg_engine.worker` smoke runs."""
    bootstrap()


# Import-time registration. Skipped under pytest, where each test builds the
# broker it wants (usually a StubBroker) and no metrics port should be bound.
if not os.environ.get("PYTEST_VERSION"):
    bootstrap()


if __name__ == "__main__":
    main()
