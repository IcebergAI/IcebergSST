import io
import json

import dramatiq
import structlog
from dramatiq.brokers.stub import StubBroker
from dramatiq.worker import Worker
from iceberg_core.logging import configure_logging
from iceberg_engine import worker as worker_module
from iceberg_engine.worker import (
    CorrelationMiddleware,
    ObservabilityMiddleware,
    build_broker,
)


def has_middleware(broker: dramatiq.Broker, kind: type[dramatiq.Middleware]) -> bool:
    return any(isinstance(middleware, kind) for middleware in broker.middleware)


def test_module_exposes_the_broker_the_image_entrypoint_names() -> None:
    """deploy/docker/engine.Dockerfile runs ``dramatiq iceberg_engine.worker:broker``.

    Renaming this attribute breaks the container entrypoint and nothing else,
    so pin the name here rather than discover it from a crash-looping pod.
    """
    assert isinstance(worker_module.broker, dramatiq.Broker)


def test_deployed_broker_carries_observability_middleware() -> None:
    assert has_middleware(worker_module.broker, ObservabilityMiddleware)


def test_build_broker_leaves_observability_to_the_deployed_broker() -> None:
    """Tests build their own broker; booting one must not bind a port or
    reconfigure logging out from under them."""
    broker = build_broker()
    assert has_middleware(broker, CorrelationMiddleware)
    assert not has_middleware(broker, ObservabilityMiddleware)


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
