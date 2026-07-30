"""Engine worker: the process, and the actor that runs a scan task (#50).

Establishes what every message inherits — JSON logs carrying a ``task_id``
correlation id, a standalone Prometheus server (engines have no web framework to
piggyback on), the broker connection — and registers the actor the API's
dispatcher addresses.

**A broker message carries a task id and nothing else** (ADR 0009). The actor
leases the task to get anything else: the spec, the credential, the pepper, the
suppressions. That is what keeps a compromised broker to re-delivery noise rather
than a data leak, and it is why this module does so little — everything that
matters is behind the lease, in :mod:`iceberg_engine.runner`.

Broker-level retries are off (`SCAN_TASK_OPTIONS`). Lease expiry and API-side
reclaim are the single re-delivery authority; a second, uncoordinated one would
put two engines on one task (ADR 0009 §2).

Engines talk to Redis and the API only — never the database (ADR 0002).
"""

import signal
import threading
import uuid
from functools import lru_cache
from http.server import HTTPServer

import dramatiq
import structlog
from dramatiq.broker import MessageProxy
from dramatiq.brokers.redis import RedisBroker
from dramatiq.brokers.stub import StubBroker
from iceberg_core import metrics as _metrics  # noqa: F401  # registers iceberg_* series
from iceberg_core.config import EngineSettings, get_engine_settings
from iceberg_core.logging import configure_logging
from iceberg_core.tasks import SCAN_TASK_ACTOR, SCAN_TASK_OPTIONS, SCAN_TASK_QUEUE
from iceberg_detect import RulePack, load_named_pack
from prometheus_client import start_http_server

from iceberg_engine import __version__
from iceberg_engine.api_client import EngineClient
from iceberg_engine.heartbeat import Heartbeat, TaskRegistry
from iceberg_engine.runner import run_task

logger = structlog.get_logger()

#: Tasks this process holds. Shared by the actor threads doing the work and the
#: heartbeat thread renewing their leases (#51).
TASKS = TaskRegistry()


@lru_cache(maxsize=1)
def rulepack() -> RulePack:
    """The pack shipped in this image, loaded once per process.

    Loading is strict and slow-ish (every regex compiled and checked), so it
    happens at first use and is then reused — and a bad pack fails the first
    message loudly rather than every message quietly.
    """
    return load_named_pack()


def build_client(settings: EngineSettings) -> EngineClient:
    """The API client this engine reports through.

    The token is the only credential the process holds. It arrives as
    configuration because an engine cannot mint its own — enrolment is an operator
    action (docs/security.md § Bootstrap).
    """
    if settings.engine_token is None:
        raise RuntimeError(
            "no engine token configured; mint one with "
            "`python -m iceberg_api mint-engine-token` and set ICEBERG_ENGINE_TOKEN"
        )
    return EngineClient(
        base_url=settings.api_base_url,
        token=settings.engine_token.get_secret_value(),
        # Without it this engine can lease and report but never renew: the
        # heartbeat route requires the path id to match the token.
        engine_id=settings.engine_id,
    )


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


@dramatiq.actor(actor_name=SCAN_TASK_ACTOR, queue_name=SCAN_TASK_QUEUE, **SCAN_TASK_OPTIONS)
def run_scan_task(task_id: str) -> None:
    """Consume one dispatched task id.

    Thin on purpose: the message is a hint that work exists, and everything real
    happens after the lease. Exceptions are not swallowed here — `run_task`
    reports a failure to the API itself, so anything reaching this frame is a bug
    worth a stack trace in the logs.
    """
    run_task(
        uuid.UUID(task_id),
        client=build_client(get_engine_settings()),
        pack=rulepack(),
        tasks=TASKS,
    )


def main(settings: EngineSettings | None = None) -> None:
    """Process entrypoint: bootstrap, then wait for SIGTERM/SIGINT.

    Docker stops containers with SIGTERM, so handling it is what makes
    ``docker compose down`` a clean shutdown rather than a ten-second wait
    followed by SIGKILL.

    The consumer is started here rather than by the `dramatiq` CLI so that
    importing this module stays free of side effects. The CLI configures a broker
    at import time, which would make the no-DB import probe — and every test that
    imports the worker — try to reach Redis.
    """
    resolved = settings or get_engine_settings()
    server, broker = bootstrap(resolved)

    consumer = dramatiq.Worker(
        broker, queues={SCAN_TASK_QUEUE}, worker_threads=resolved.worker_threads
    )
    consumer.start()
    logger.info("engine_consuming", queue=SCAN_TASK_QUEUE, threads=resolved.worker_threads)

    heartbeat = _start_heartbeat(resolved)
    shutdown = threading.Event()

    def request_shutdown(signum: int, _frame: object) -> None:
        logger.info("engine_shutdown_requested", signal=signal.Signals(signum).name)
        shutdown.set()

    for received in (signal.SIGINT, signal.SIGTERM):
        signal.signal(received, request_shutdown)

    shutdown.wait()
    # Stop consuming before the metrics server goes: a message picked up during
    # shutdown still holds a lease, and finishing it is cheaper for the scan than
    # waiting out an expiry.
    consumer.stop()
    if heartbeat is not None:
        heartbeat.stop()
    server.shutdown()
    logger.info("engine_stopped")


def _start_heartbeat(settings: EngineSettings) -> Heartbeat | None:
    """Begin renewing leases, if this engine knows which engine it is.

    An engine configured with a token but no id can still lease, scan, and report
    — it simply cannot renew, so any task outlasting the lease is reclaimed. That
    is a degraded mode worth a warning rather than a refusal to start: the scan
    still completes, just less efficiently.
    """
    if settings.engine_id is None:
        logger.warning(
            "heartbeat_disabled",
            reason="no ICEBERG_ENGINE_ID configured; long tasks will lose their lease",
        )
        return None

    pack = rulepack()
    heartbeat = Heartbeat(
        build_client(settings),
        TASKS,
        version=__version__,
        # Reported every beat, so `GET /rules` reflects a rolling deploy as it
        # happens rather than at the next registration (#70).
        rulepack={
            "version": pack.version,
            "rules": [
                {"id": rule.id, "description": rule.description, "severity": rule.severity.value}
                for rule in pack.rules
            ],
        },
    )
    heartbeat.start()
    return heartbeat


if __name__ == "__main__":
    main()
