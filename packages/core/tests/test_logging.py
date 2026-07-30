import io
import json

import pytest
import structlog
from iceberg_core.logging import MASK, TRUNCATED, configure_logging

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


def test_a_connection_url_password_is_scrubbed_but_the_host_is_kept() -> None:
    """A DSN is a plain string under a key no pattern catches; the userinfo is
    masked in place so the host stays useful for debugging."""
    raw, event = capture_configured_log(
        database_url="postgresql+psycopg://api:S3CRETPW@db:5432/iceberg",
        redis_url="redis://:hunter2@redis:6379/0",
    )
    assert "S3CRETPW" not in raw and "hunter2" not in raw
    assert event["database_url"] == "postgresql+psycopg://[REDACTED]@db:5432/iceberg"
    assert event["redis_url"] == "redis://[REDACTED]@redis:6379/0"


def test_a_url_password_inside_an_object_repr_is_scrubbed() -> None:
    """An object logged under a benign key is rendered with repr; a DSN in that
    repr must be scrubbed too, not just bare string values."""

    class Settings:
        def __repr__(self) -> str:
            return "Settings(database_url='postgresql://api:S3CRETPW@db/iceberg')"

    raw, event = capture_configured_log(settings=Settings())
    assert "S3CRETPW" not in raw
    assert "[REDACTED]" in str(event["settings"])


def test_a_plain_url_without_credentials_is_untouched() -> None:
    _, event = capture_configured_log(endpoint="http://api:8000/healthz")
    assert event["endpoint"] == "http://api:8000/healthz"


def test_credential_masked_at_every_nesting_shape() -> None:
    """A secret is a secret wherever it sits — lists of lists, tuples, deep dicts."""
    raw, _ = capture_configured_log(
        batches=[[{"password": FAKE_CREDENTIAL}]],
        pages=({"token": FAKE_CREDENTIAL},),
        deep={"a": {"b": {"c": {"private_key": FAKE_CREDENTIAL}}}},
        mixed=[{"conns": [{"access_key": FAKE_CREDENTIAL}]}],
    )
    assert FAKE_CREDENTIAL not in raw


@pytest.mark.parametrize(
    "key",
    ["db_pwd", "passphrase", "bearer", "session_cookie", "private_key", "access_key", "hash_salt"],
)
def test_additional_credential_key_spellings_are_masked(key: str) -> None:
    raw, event = capture_configured_log(**{key: FAKE_CREDENTIAL})
    assert FAKE_CREDENTIAL not in raw
    assert event[key] == MASK


def test_logging_does_not_mutate_caller_owned_values() -> None:
    """A log call must not leave the caller holding a masked credential."""
    connection = {"host": "confluence.local", "password": FAKE_CREDENTIAL}
    attempts = [{"api_key": FAKE_CREDENTIAL}]

    buf = io.StringIO()
    configure_logging(role="test", stream=buf)
    structlog.get_logger().info("connecting", connection=connection, attempts=attempts)

    assert FAKE_CREDENTIAL not in buf.getvalue()
    assert connection["password"] == FAKE_CREDENTIAL
    assert attempts[0]["api_key"] == FAKE_CREDENTIAL


def test_self_referential_value_is_truncated_not_fatal() -> None:
    """A cycle must bottom out in a marker rather than blow the stack mid-log."""
    cyclic: dict[str, object] = {"host": "confluence.local"}
    cyclic["self"] = cyclic

    _, event = capture_configured_log(config=cyclic)

    rendered = json.dumps(event)
    assert TRUNCATED in rendered
