import io
import json
import socket
import urllib.request

import dramatiq
import pytest
import structlog
from dramatiq.brokers.stub import StubBroker
from dramatiq.worker import Worker
from iceberg_connectors import registry
from iceberg_core.config import EngineSettings
from iceberg_core.logging import configure_logging
from iceberg_engine.worker import (
    api_client,
    bootstrap,
    build_broker,
    close_api_client,
    register_connectors,
)
from pydantic import SecretStr


def test_build_broker_defaults_to_stub() -> None:
    broker = build_broker()
    assert isinstance(broker, StubBroker)


def test_processed_message_logs_carry_task_id() -> None:
    buf = io.StringIO()
    configure_logging(role="engine", stream=buf)
    broker = build_broker()

    @dramatiq.actor(broker=broker)
    def sample_task() -> None:
        structlog.get_logger().info("task_body_ran")

    sample_task.send()
    worker = Worker(broker, worker_timeout=100)
    worker.start()
    try:
        broker.join(sample_task.queue_name, timeout=5000)
        worker.join()
    finally:
        worker.stop()

    events = [json.loads(line) for line in buf.getvalue().splitlines()]
    task_events = [e for e in events if e["event"] == "task_body_ran"]
    assert len(task_events) == 1
    assert task_events[0]["task_id"]
    assert task_events[0]["role"] == "engine"


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port: int = probe.getsockname()[1]
    return port


#: A fixture, not a credential.
TOKEN = SecretStr("engine-token")


def _settings(*, engine_token: SecretStr | None = TOKEN) -> EngineSettings:
    """A configured engine: a token, and a metrics port nobody else is on.

    An ephemeral port keeps the test off 9191, where a real engine (or another
    test) may already be listening. An empty Redis URL selects the stub broker,
    since there is no broker to talk to here.
    """
    return EngineSettings(metrics_port=_free_port(), redis_url="", engine_token=engine_token)


def test_bootstrap_serves_metrics_and_connects_a_broker() -> None:
    """What the container entrypoint does, minus the wait for SIGTERM."""
    settings = _settings()

    server, broker = bootstrap(settings)
    try:
        with urllib.request.urlopen(  # localhost, literal http scheme
            f"http://127.0.0.1:{server.server_port}/metrics"
        ) as response:
            body = response.read().decode()

        # The engine's own series. An API-side counter is registered here too, but
        # nothing in this process can ever move one, so a scrape of an engine that
        # asserted on those would look identical to a dead engine (#132).
        assert "iceberg_engine_tasks_run_total" in body
        assert "iceberg_engine_api_retries_total" in body
        assert dramatiq.get_broker() is broker
        # Without this the registry is empty and every task fails with "no
        # connector for source type" — a whole fleet scanning nothing.
        assert "confluence" in registry.registered_types()
    finally:
        server.shutdown()
        server.server_close()


def test_an_engine_without_a_token_refuses_to_boot() -> None:
    """It cannot process a single message, and nothing downstream would say so: it
    boots, serves metrics, consumes every dispatched task and drops it, and the
    API's reclaim hands each one back to the same broken consumer. Better to fail
    where an operator is looking (#131)."""
    with pytest.raises(RuntimeError, match="no engine token"):
        bootstrap(_settings(engine_token=None))


def test_the_process_shares_one_api_client() -> None:
    """One client is one connection pool. Building one per message paid a TCP and
    TLS handshake for every lease, submission and beat (#130)."""
    close_api_client()
    settings = _settings()

    first = api_client(settings)
    try:
        assert api_client(settings) is first
    finally:
        close_api_client()


def test_shutdown_closes_the_shared_client() -> None:
    close_api_client()
    client = api_client(_settings())

    close_api_client()

    assert client._http.is_closed
    close_api_client()  # a shutdown path may run twice


def test_the_shipped_connectors_are_registered() -> None:
    """A lease names a source type and nothing else, so a type this image cannot
    resolve fails the task. Registration is explicit rather than by import-time
    scanning, which means it can be forgotten — hence a test (#45)."""
    registry.clear()

    types = register_connectors()

    assert "confluence" in types
    assert registry.get("confluence").connector_type == "confluence"


def test_registering_twice_is_not_an_error() -> None:
    """`bootstrap` may run more than once in a test process, and a duplicate
    registration is not worth failing a boot over."""
    register_connectors()
    register_connectors()

    assert "confluence" in registry.registered_types()


@pytest.fixture(autouse=True)
def _restore_registry() -> object:
    """Leave the registry as it was: other suites register their own doubles."""
    yield
    registry.clear()
