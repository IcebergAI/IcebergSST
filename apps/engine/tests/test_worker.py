import io
import json
import socket
import urllib.request

import dramatiq
import structlog
from dramatiq.brokers.stub import StubBroker
from dramatiq.worker import Worker
from iceberg_core.config import EngineSettings
from iceberg_core.logging import configure_logging
from iceberg_engine.worker import bootstrap, build_broker


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


def test_bootstrap_serves_metrics_and_connects_a_broker() -> None:
    """What the container entrypoint does, minus the wait for SIGTERM.

    An ephemeral port keeps the test off 9191, where a real engine (or another
    test) may already be listening. An empty Redis URL selects the stub broker,
    since there is no broker to talk to here.
    """
    settings = EngineSettings(metrics_port=_free_port(), redis_url="")

    server, broker = bootstrap(settings)
    try:
        with urllib.request.urlopen(  # localhost, literal http scheme
            f"http://127.0.0.1:{server.server_port}/metrics"
        ) as response:
            body = response.read().decode()

        assert "iceberg_scans_started_total" in body
        assert dramatiq.get_broker() is broker
    finally:
        server.shutdown()
        server.server_close()
