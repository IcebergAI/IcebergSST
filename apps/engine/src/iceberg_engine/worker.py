"""Engine worker bootstrap — observability baseline only (issue #67).

Actors arrive with M2. This module establishes what every actor will inherit:
JSON logs carrying a per-message ``task_id`` correlation id, and a standalone
Prometheus metrics server (engines have no web framework to piggyback on).

Engines talk to Redis and the API only — never the database (ADR 0002).
"""

import dramatiq
import structlog
from dramatiq.broker import MessageProxy
from dramatiq.brokers.redis import RedisBroker
from dramatiq.brokers.stub import StubBroker
from iceberg_core import metrics as _metrics  # noqa: F401  # registers iceberg_* series
from iceberg_core.config import EngineSettings, get_engine_settings
from iceberg_core.logging import configure_logging
from prometheus_client import start_http_server

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


def main(settings: EngineSettings | None = None) -> None:
    """Process entrypoint: logging, metrics server, broker registration.

    Configuration comes from :class:`~iceberg_core.config.EngineSettings` — the
    engine reads no environment variable directly, which is what keeps the
    "no raw env reads" invariant checkable (ADR 0007).
    """
    resolved = settings or get_engine_settings()
    configure_logging(role="engine")
    start_http_server(resolved.metrics_port)
    build_broker(resolved.redis_url)
    logger.info("engine_bootstrap_complete", metrics_port=resolved.metrics_port)


if __name__ == "__main__":
    main()
