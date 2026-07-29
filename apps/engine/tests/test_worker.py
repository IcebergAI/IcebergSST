import io
import json
import socket

import dramatiq
import structlog
from dramatiq.brokers.stub import StubBroker
from dramatiq.worker import Worker
from iceberg_core.logging import configure_logging
from iceberg_engine.worker import build_broker, serve_metrics


def test_build_broker_defaults_to_stub() -> None:
    broker = build_broker()
    assert isinstance(broker, StubBroker)


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port: int = sock.getsockname()[1]
    return port


def test_serve_metrics_binds_once_and_yields_to_siblings() -> None:
    """`dramatiq` forks workers that all re-import the module (#20).

    Every fork calls this; exactly one may own the port and the rest must carry
    on rather than dying with EADDRINUSE, which crash-looped the container.
    """
    port = _free_port()
    assert serve_metrics(port) is True
    assert serve_metrics(port) is False


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
