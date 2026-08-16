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
from iceberg_connectors import (
    ConfluenceConnector,
    FileshareConnector,
    JiraConnector,
    registry,
)
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
from iceberg_engine.validation import RateLimiter, RedisMinuteLimiter

logger = structlog.get_logger()

#: Tasks this process holds. Shared by the actor threads doing the work and the
#: heartbeat thread renewing their leases (#51).
TASKS = TaskRegistry()

#: The client every thread in this process reports through, and the lock that
#: keeps a burst of first messages from building more than one.
_CLIENT: EngineClient | None = None
_CLIENT_LOCK = threading.Lock()


@lru_cache(maxsize=1)
def validation_limiter(redis_url: str) -> RateLimiter:
    """The fleet-wide credential-validation budget shared by all replicas."""
    return RedisMinuteLimiter.from_url(redis_url)


@lru_cache(maxsize=1)
def rulepack() -> RulePack:
    """The pack shipped in this image, loaded once per process.

    Loading is strict and slow-ish (every regex compiled and checked), so it
    happens at first use and is then reused — and a bad pack fails the first
    message loudly rather than every message quietly.
    """
    return load_named_pack()


def require_token(settings: EngineSettings) -> str:
    """The engine token, or a refusal to go any further without one.

    The token is the only credential the process holds. It arrives as
    configuration because an engine cannot mint its own — enrolment is an operator
    action (docs/security.md § Bootstrap).
    """
    if settings.engine_token is None:
        raise RuntimeError(
            "no engine token configured; mint one with "
            "`python -m iceberg_api mint-engine-token` and set ICEBERG_ENGINE_TOKEN"
        )
    return settings.engine_token.get_secret_value()


def build_client(settings: EngineSettings) -> EngineClient:
    """The API client this engine reports through."""
    return EngineClient(
        base_url=settings.api_base_url,
        token=require_token(settings),
        # Without it this engine can lease and report but never renew: the
        # heartbeat route requires the path id to match the token.
        engine_id=settings.engine_id,
    )


def api_client(settings: EngineSettings | None = None) -> EngineClient:
    """The one client this process talks to the API through.

    Built once and shared by every actor thread and the heartbeat, because a
    client is a connection pool: one per message paid a TCP and TLS handshake for
    every lease, submission and beat, which is the load `worker_threads`' own
    documentation says it is trading against (#130).
    """
    global _CLIENT
    with _CLIENT_LOCK:
        if _CLIENT is None:
            _CLIENT = build_client(settings or get_engine_settings())
        return _CLIENT


def close_api_client() -> None:
    """Drop the shared client and its pool. Idempotent, for shutdown and tests."""
    global _CLIENT
    with _CLIENT_LOCK:
        if _CLIENT is not None:
            _CLIENT.close()
            _CLIENT = None


def register_connectors() -> tuple[str, ...]:
    """Make this image's connectors available for lookup, and say which they are.

    Explicit rather than import-time scanning: the set of source types an engine can
    scan decides whether a task runs or fails, and "whichever modules happened to be
    imported" is a hard thing to reason about when that is the question (#45).

    Idempotent, because `bootstrap` may run more than once in a test process and a
    second registration of the same type is not an error worth failing a boot over.
    """
    registry.register(ConfluenceConnector(), replace=True)
    registry.register(JiraConnector(), replace=True)
    registry.register(FileshareConnector(), replace=True)
    types = registry.registered_types()
    logger.info("connectors_registered", source_types=list(types))
    return types


class CorrelationMiddleware(dramatiq.Middleware):
    """Bind the scan-task id as ``task_id`` for the duration of a message.

    The dispatcher puts the ScanTask id in ``args[0]`` (dispatch.py); the broker's
    own ``message_id`` is a random per-delivery UUID that matches nothing in the
    database. Binding the real id is what lets an operator correlate a stuck task
    across the engine and API logs — including the frames `run_task` does not set
    it on itself (a dramatiq-level error, a heartbeat line)."""

    def before_process_message(self, broker: dramatiq.Broker, message: MessageProxy) -> None:
        task_id = message.args[0] if message.args else message.message_id
        structlog.contextvars.bind_contextvars(task_id=str(task_id))

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
    broker: dramatiq.Broker
    if redis_url:
        broker = RedisBroker(url=redis_url)  # type: ignore[no-untyped-call]  # RedisBroker.__init__ lacks hints
    else:
        # A stub broker consumes nothing: the engine would boot "healthy" (metrics
        # up, heartbeats reporting it alive) while every scan sits queued forever.
        # Fine for tests and local smoke runs, a misconfiguration in a real deploy.
        logger.warning(
            "engine_broker_missing",
            detail="no ICEBERG_REDIS_URL; using a stub broker that consumes no tasks",
        )
        broker = StubBroker()
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
    # Before anything is consumed, because a tokenless engine cannot process a
    # single message: it boots, serves metrics, drops every task it is handed, and
    # the API's reclaim hands each one straight back to it. The fleet reads as
    # alive while its scans never move (#131).
    require_token(resolved)
    server, _thread = start_http_server(resolved.metrics_port)
    broker = build_broker(resolved.redis_url)
    source_types = register_connectors()
    logger.info(
        "engine_bootstrap_complete",
        metrics_port=server.server_port,
        broker=type(broker).__name__,
        source_types=list(source_types),
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
        client=api_client(),
        pack=rulepack(),
        tasks=TASKS,
        validation_limiter=validation_limiter(get_engine_settings().redis_url),
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
    client = api_client(resolved)

    consumer = dramatiq.Worker(
        broker, queues={SCAN_TASK_QUEUE}, worker_threads=resolved.worker_threads
    )
    consumer.start()
    logger.info("engine_consuming", queue=SCAN_TASK_QUEUE, threads=resolved.worker_threads)

    heartbeat = _start_heartbeat(resolved, client)
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
    # Only once both are stopped: until then, threads are still reporting through
    # this pool.
    close_api_client()
    server.shutdown()
    logger.info("engine_stopped")


def _start_heartbeat(settings: EngineSettings, client: EngineClient) -> Heartbeat | None:
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
        client,
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
