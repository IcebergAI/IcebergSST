import io
import json

import structlog
from iceberg_core.logging import MASK, configure_logging

# Deliberately fake and low-entropy so the repo's own secret scanner (gitleaks,
# issue #19) does not flag it; the redaction processor is key-driven, so the
# value's shape is irrelevant to what this test proves.
FAKE_CREDENTIAL = "fake-not-a-real-secret-value"


def capture_configured_log(**event_kwargs: object) -> tuple[str, dict[str, object]]:
    buf = io.StringIO()
    configure_logging(role="test", stream=buf)
    structlog.get_logger().info("event_under_test", **event_kwargs)
    raw = buf.getvalue()
    parsed: dict[str, object] = json.loads(raw)
    return raw, parsed


def test_output_is_json_with_role_level_and_timestamp() -> None:
    _, event = capture_configured_log()
    assert event["event"] == "event_under_test"
    assert event["role"] == "test"
    assert event["level"] == "info"
    assert "timestamp" in event


def test_bound_correlation_id_appears_in_every_event() -> None:
    buf = io.StringIO()
    configure_logging(role="test", stream=buf)
    structlog.contextvars.bind_contextvars(request_id="req-123")
    try:
        structlog.get_logger().info("first")
        structlog.get_logger().info("second")
    finally:
        structlog.contextvars.unbind_contextvars("request_id")
    events = [json.loads(line) for line in buf.getvalue().splitlines()]
    assert [e["request_id"] for e in events] == ["req-123", "req-123"]


def test_credential_never_appears_in_log_output() -> None:
    """Issue #67 acceptance: secrets provably never reach log output."""
    raw, event = capture_configured_log(
        source_token=FAKE_CREDENTIAL,
        connection={"password": FAKE_CREDENTIAL, "host": "confluence.local"},
        attempts=[{"api_key": FAKE_CREDENTIAL}, {"note": "benign"}],
    )
    assert FAKE_CREDENTIAL not in raw
    assert event["source_token"] == MASK
    connection = event["connection"]
    assert isinstance(connection, dict)
    assert connection == {"password": MASK, "host": "confluence.local"}
    attempts = event["attempts"]
    assert isinstance(attempts, list)
    assert attempts[0] == {"api_key": MASK}


def test_non_sensitive_values_pass_through_unmasked() -> None:
    _, event = capture_configured_log(scan_id=42, source_name="wiki")
    assert event["scan_id"] == 42
    assert event["source_name"] == "wiki"
