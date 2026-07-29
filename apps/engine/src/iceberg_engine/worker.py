"""Engine worker bootstrap.

Actors arrive with M2 (#50). This module establishes what every actor will
inherit: JSON logs carrying a per-message ``task_id`` correlation id, a
standalone Prometheus metrics server (engines have no web framework to piggyback
on), and the broker connection.

Until the Dramatiq consumer lands, the process bootstraps and then waits for a
signal rather than exiting — an engine container that exited immediately would
restart-loop, and `make up` would never report a healthy stack. The
``dramatiq iceberg_engine.worker`` consumer replaces the wait in #50.

Engines talk to Redis and the API only — never the database (ADR 0002).
"""

import signal
import threading
from http.server import HTTPServer

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


def bootstrap(settings: EngineSettings | None = None) -> tuple[HTTPServer, dramatiq.Broker]:
    """Configure logging, serve metrics, connect the broker.

    Configuration comes from :class:`~iceberg_core.config.EngineSettings` — the
    engine reads no environment variable directly, which is what keeps the
    "no raw env reads" invariant checkable (ADR 0007).
    """
    resolved = settings or get_engine_settings()
    configure_logging(role="engine")
    server, _thread = start_http_server(resolved.metrics_port)
    broker = build_broker(resolved.redis_url)
    logger.info(
        "engine_bootstrap_complete",
        metrics_port=server.server_port,
        broker=type(broker).__name__,
    )
    return server, broker


def main(settings: EngineSettings | None = None) -> None:
    """Process entrypoint: bootstrap, then wait for SIGTERM/SIGINT.

    Docker stops containers with SIGTERM, so handling it is what makes
    ``docker compose down`` a clean shutdown rather than a ten-second wait
    followed by SIGKILL.
    """
    server, _broker = bootstrap(settings)
    shutdown = threading.Event()

    def request_shutdown(signum: int, _frame: object) -> None:
        logger.info("engine_shutdown_requested", signal=signal.Signals(signum).name)
        shutdown.set()

    for received in (signal.SIGINT, signal.SIGTERM):
        signal.signal(received, request_shutdown)

    shutdown.wait()
    server.shutdown()
    logger.info("engine_stopped")


if __name__ == "__main__":
    main()
