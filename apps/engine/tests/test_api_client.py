"""The engine's client for the control plane (#51).

Driven against a scripted transport rather than a mock client, so the real request
building, header, status handling, and backoff all run. `sleep` is injected, so a
test of four attempts costs no wall-clock.

The theme throughout: **what is retried, and what is not**. Retrying the wrong
thing is worse than not retrying — a 409 replayed four times is four requests
whose answer was already known, and a lease held while the API reclaims it is two
engines believing they own one task.
"""

import uuid
from typing import Any

import httpx2
import pytest
from iceberg_engine.api_client import (
    AuthenticationFailed,
    EngineApiError,
    EngineClient,
    Lease,
    LeaseNotHeld,
    LeaseRefused,
    RetryPolicy,
)

TASK_ID = uuid.UUID("11111111-1111-1111-1111-111111111111")
ENGINE_ID = uuid.UUID("22222222-2222-2222-2222-222222222222")

LEASE_BODY: dict[str, Any] = {
    "task_id": str(TASK_ID),
    "scan_id": "33333333-3333-3333-3333-333333333333",
    "source_id": "44444444-4444-4444-4444-444444444444",
    "source_type": "fake",
    "kind": "fetch",
    "attempt": 2,
    "lease_expires_at": "2026-07-30T00:00:00Z",
    "spec": {"label": "space DOCS", "params": {"space": "DOCS"}},
    "connection": {"base_url": "https://wiki.test"},
    "credential": "the-token",
    "fingerprint_pepper": "cGVwcGVy",
    "suppressions": [{"id": str(uuid.uuid4()), "scope": "rule", "pattern": "noisy"}],
    "confidence_threshold": 0.7,
}


class Script:
    """Answers requests from a list, recording what it was asked."""

    def __init__(self, *responses: httpx2.Response) -> None:
        self.responses = list(responses)
        self.requests: list[httpx2.Request] = []

    def __call__(self, request: httpx2.Request) -> httpx2.Response:
        self.requests.append(request)
        # The last response repeats, so "always 503" needs one entry.
        return self.responses[min(len(self.requests) - 1, len(self.responses) - 1)]


def _client(script: Script, **overrides: Any) -> tuple[EngineClient, list[float]]:
    slept: list[float] = []
    defaults: dict[str, Any] = {
        "base_url": "http://api.test",
        "token": "engine-token",  # a fixture, not a credential
        "engine_id": ENGINE_ID,
        "transport": httpx2.MockTransport(script),
        "sleep": slept.append,
    }
    return EngineClient(**(defaults | overrides)), slept


# ─── Requests are built the way the API expects ───────────────────────────────


def test_a_lease_is_claimed_and_read() -> None:
    script = Script(httpx2.Response(200, json=LEASE_BODY))
    client, _ = _client(script)

    lease = client.lease(TASK_ID)

    assert str(script.requests[0].url) == f"http://api.test/api/v1/scan-tasks/{TASK_ID}/lease"
    assert lease.kind == "fetch"
    assert lease.spec["params"] == {"space": "DOCS"}
    assert lease.credential == "the-token"
    assert lease.confidence_threshold == 0.7


def test_every_request_carries_the_engine_token() -> None:
    """It is the only credential this process holds, and it works nowhere else."""
    script = Script(httpx2.Response(200, json=LEASE_BODY))
    client, _ = _client(script)

    client.lease(TASK_ID)

    assert script.requests[0].headers["authorization"] == "Bearer engine-token"


def test_the_idempotency_key_is_the_task_and_attempt() -> None:
    """What turns a retried submission into a replay rather than a second ingest."""
    lease = Lease(payload=LEASE_BODY)

    assert lease.idempotency_key == f"{TASK_ID}:2"


def test_a_lease_tolerates_fields_it_does_not_know() -> None:
    """The API and the engine version separately; an engine that refused to start
    because the API grew a field would be a rolling-deploy outage."""
    script = Script(httpx2.Response(200, json=LEASE_BODY | {"a_new_field": "from a newer api"}))
    client, _ = _client(script)

    assert client.lease(TASK_ID).kind == "fetch"


def test_a_lease_missing_optional_fields_reads_sane_defaults() -> None:
    """An older API, or a discovery task with no spec."""
    minimal = {
        "task_id": str(TASK_ID),
        "scan_id": "33333333-3333-3333-3333-333333333333",
        "source_type": "fake",
        "kind": "discovery",
    }
    lease = Lease(payload=minimal)

    assert (lease.spec, lease.connection, lease.suppressions) == ({}, {}, [])
    assert lease.credential is None
    assert lease.attempt == 1


def test_a_heartbeat_reports_held_tasks_and_returns_cancellations() -> None:
    """The only way a running engine learns its work was cancelled (ADR 0009 §4)."""
    cancelled = str(uuid.uuid4())
    script = Script(httpx2.Response(200, json={"cancelled_task_ids": [cancelled]}))
    client, _ = _client(script)

    result = client.heartbeat(task_ids=[TASK_ID], version="0.2.0")

    assert result == [uuid.UUID(cancelled)]
    assert str(script.requests[0].url).endswith(f"/engines/{ENGINE_ID}/heartbeat")


def test_results_without_an_idempotency_key_are_refused_before_sending() -> None:
    """Keeping the bug where it was written, rather than as a 422 from the API."""
    script = Script(httpx2.Response(200, json={}))
    client, _ = _client(script)

    with pytest.raises(EngineApiError, match="idempotency key"):
        client.submit_results(TASK_ID, {"status": "completed"})

    assert script.requests == []


# ─── What is retried ──────────────────────────────────────────────────────────


def test_a_5xx_is_retried_with_growing_backoff() -> None:
    script = Script(httpx2.Response(503))
    client, slept = _client(script, retry=RetryPolicy(attempts=4, base_delay_seconds=0.5))

    with pytest.raises(EngineApiError, match="after 4 attempts"):
        client.lease(TASK_ID)

    assert len(script.requests) == 4
    assert slept == [0.5, 1.0, 2.0]  # three waits between four attempts


def test_backoff_is_capped() -> None:
    """An engine cannot wait forever: the lease it holds expires and the API
    reclaims the task, and two engines then believe they own it."""
    policy = RetryPolicy(attempts=6, base_delay_seconds=1.0, max_delay_seconds=4.0)
    client, slept = _client(Script(httpx2.Response(500)), retry=policy)

    with pytest.raises(EngineApiError):
        client.lease(TASK_ID)

    assert slept == [1.0, 2.0, 4.0, 4.0, 4.0]


def test_a_transient_failure_followed_by_success_returns_the_result() -> None:
    """The case retrying exists for."""
    script = Script(httpx2.Response(503), httpx2.Response(200, json=LEASE_BODY))
    client, slept = _client(script)

    lease = client.lease(TASK_ID)

    assert lease.kind == "fetch"
    assert len(slept) == 1


def test_a_transport_error_is_retried() -> None:
    """A timeout leaves the engine unable to tell "never seen" from "reply lost" —
    which is exactly what the idempotency key makes survivable."""
    attempts = {"n": 0}

    def flaky(request: httpx2.Request) -> httpx2.Response:
        attempts["n"] += 1
        if attempts["n"] < 3:
            raise httpx2.ConnectError("connection refused")
        return httpx2.Response(200, json=LEASE_BODY)

    client, _ = _client(Script(), transport=httpx2.MockTransport(flaky))

    assert client.lease(TASK_ID).kind == "fetch"
    assert attempts["n"] == 3


def test_a_non_json_body_is_retried() -> None:
    """A proxy's error page in front of a healthy API."""
    script = Script(
        httpx2.Response(200, text="<html>gateway</html>"), httpx2.Response(200, json=LEASE_BODY)
    )
    client, _ = _client(script)

    assert client.lease(TASK_ID).kind == "fetch"


# ─── What is not ──────────────────────────────────────────────────────────────


def test_a_refused_lease_is_not_retried() -> None:
    """409 means already claimed, finished, cancelled, or unknown. The engine's
    response to all four is to drop the message — asking again changes nothing."""
    script = Script(httpx2.Response(409))
    client, slept = _client(script)

    with pytest.raises(LeaseRefused):
        client.lease(TASK_ID)

    assert len(script.requests) == 1
    assert slept == []


def test_a_rejected_token_is_not_retried() -> None:
    """Rotated or revoked. Retrying makes the same rejected request more often."""
    script = Script(httpx2.Response(401))
    client, _ = _client(script)

    with pytest.raises(AuthenticationFailed):
        client.lease(TASK_ID)

    assert len(script.requests) == 1


def test_a_lease_this_engine_does_not_hold_is_told_apart_from_a_rejected_token() -> None:
    """Both are 4xx and neither is retried, but they mean opposite things: a 403 is
    a lease that moved on while the engine worked, where a 401 is an engine that
    can no longer talk to the API at all. Collapsing them hides a token rotation
    behind a routine log line (#131)."""
    script = Script(httpx2.Response(403))
    client, _ = _client(script)

    with pytest.raises(LeaseNotHeld):
        client.lease(TASK_ID)

    assert len(script.requests) == 1


def test_a_bad_request_is_not_retried() -> None:
    """A 422 is something this engine built wrongly; sending it again will not fix it."""
    script = Script(httpx2.Response(422))
    client, _ = _client(script)

    with pytest.raises(EngineApiError, match="rejected the request"):
        client.submit_results(TASK_ID, {"idempotency_key": "k", "status": "completed"})

    assert len(script.requests) == 1


# ─── The connection pool ──────────────────────────────────────────────────────


def test_one_http_client_serves_every_request(monkeypatch: pytest.MonkeyPatch) -> None:
    """A client is a connection pool. One per request — which is one per lease,
    submission, beat *and* retry — is a TCP and TLS handshake each time, sustained
    for as long as the engine runs (#130). A MockTransport cannot feel the cost, so
    the assertion is on how many clients get built."""
    built: list[httpx2.Client] = []
    real_client = httpx2.Client

    def counting(**kwargs: Any) -> httpx2.Client:
        built.append(real_client(**kwargs))
        return built[-1]

    monkeypatch.setattr(httpx2, "Client", counting)
    script = Script(httpx2.Response(503), httpx2.Response(200, json=LEASE_BODY))
    client, _ = _client(script)

    client.lease(TASK_ID)
    client.lease(TASK_ID)

    assert len(built) == 1
    assert not built[0].is_closed


def test_closing_the_client_releases_the_pool() -> None:
    """Shutdown, not per-request cleanup: the process holds one of these."""
    client, _ = _client(Script(httpx2.Response(200, json=LEASE_BODY)))
    client.lease(TASK_ID)

    client.close()

    assert client._http.is_closed


def test_an_injected_transport_still_reaches_the_pooled_client() -> None:
    """Every test in this file rests on it, and a pool built before the transport
    was read would answer from the network instead."""
    script = Script(httpx2.Response(200, json=LEASE_BODY))
    client, _ = _client(script)

    client.lease(TASK_ID)

    assert len(script.requests) == 1


def test_heartbeating_without_an_engine_id_fails_locally() -> None:
    script = Script(httpx2.Response(200, json={}))
    client, _ = _client(script, engine_id=None)

    with pytest.raises(EngineApiError, match="engine id"):
        client.heartbeat()

    assert script.requests == []
