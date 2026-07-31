"""Rate limiting on the endpoints an unauthenticated caller can reach (#63).

The limits themselves are dull; the decisions around them are what these tests
pin down.

* **Failing open.** A store that is unreachable must not lock every operator out
  of the console. There is a test for that, because the opposite behaviour is the
  kind that looks responsible in review and takes a deployment down at 3am.
* **Engines are charged per engine, not per address.** A fleet behind one NAT
  sharing a bucket would make `--scale engine=N` throttle itself.
* **Only rejected token presentations are charged to an address.** That keeps the
  credential-stuffing bucket small without any risk to a healthy fleet.
* **`X-Forwarded-For` is ignored unless the operator says how many proxies there
  are.** Trusting it by default would let a caller take a fresh identity per
  request, which is the same as having no limit at all.
"""

import uuid
from collections.abc import Callable

import pytest
from fastapi import FastAPI, status
from fastapi.testclient import TestClient
from iceberg_api import ratelimit
from iceberg_api.auth.dependencies import get_settings
from iceberg_api.engines.auth import mint_token
from iceberg_api.ratelimit import (
    LIMIT_HEADER,
    REMAINING_HEADER,
    Decision,
    InMemoryStore,
    RedisStore,
    client_address,
    get_rate_limit_store,
)
from iceberg_core.config import ApiSettings
from iceberg_core.models import Engine
from pydantic import SecretStr
from sqlmodel import Session
from starlette.requests import Request


def _settings(**overrides: object) -> ApiSettings:
    return ApiSettings(
        database_url="postgresql+psycopg://unused/unused",
        master_key=SecretStr("unused"),
        **overrides,  # type: ignore[arg-type]
    )


def _request(*, client_host: str = "203.0.113.7", headers: dict[str, str] | None = None) -> Request:
    raw = [(key.lower().encode(), value.encode()) for key, value in (headers or {}).items()]
    return Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "GET",
            "path": "/",
            "headers": raw,
            "client": (client_host, 51234),
        }
    )


# ── The counter ───────────────────────────────────────────────────────────────


def test_the_window_allows_up_to_the_limit_then_refuses() -> None:
    store = InMemoryStore()

    decisions = [store.hit("k", limit=3, window_seconds=60) for _ in range(4)]

    assert [d.allowed for d in decisions] == [True, True, True, False]
    assert [d.remaining for d in decisions] == [2, 1, 0, 0]


def test_separate_keys_have_separate_budgets() -> None:
    store = InMemoryStore()
    for _ in range(3):
        store.hit("a", limit=3, window_seconds=60)

    assert store.hit("b", limit=3, window_seconds=60).allowed is True


def test_a_refusal_reports_when_to_come_back() -> None:
    store = InMemoryStore()
    store.hit("k", limit=1, window_seconds=60)

    refused = store.hit("k", limit=1, window_seconds=60)

    assert refused.allowed is False
    assert 1 <= refused.reset_after <= 60


class _BrokenRedis:
    def incr(self, key: str) -> int:
        raise ConnectionError("redis is unreachable")

    def expire(self, key: str, seconds: int) -> bool:  # pragma: no cover — never reached
        raise ConnectionError("redis is unreachable")


def test_an_unreachable_store_allows_the_request() -> None:
    """Fail open. A limiter that shuts the door when its counter store hiccups has
    done more damage than the traffic it was defending against — and it is never
    the last line of defence; authentication is."""
    store = RedisStore(_BrokenRedis())

    decision = store.hit("k", limit=1, window_seconds=60)

    assert decision.allowed is True


class _CountingRedis:
    """Enough of the redis client for the fixed-window algorithm."""

    def __init__(self) -> None:
        self.counts: dict[str, int] = {}
        self.expiries: dict[str, int] = {}

    def incr(self, key: str) -> int:
        self.counts[key] = self.counts.get(key, 0) + 1
        return self.counts[key]

    def expire(self, key: str, seconds: int) -> bool:
        self.expiries[key] = seconds
        return True


def test_the_redis_window_expires_so_keys_do_not_accumulate() -> None:
    client = _CountingRedis()
    store = RedisStore(client)

    store.hit("k", limit=5, window_seconds=60)
    store.hit("k", limit=5, window_seconds=60)

    # Set once, on the first hit, and long enough that a key created at the end of
    # a window is still readable for the whole of it.
    assert list(client.expiries.values()) == [120]


# ── Whose budget is it ────────────────────────────────────────────────────────


def test_the_peer_address_is_used_when_no_proxies_are_configured() -> None:
    request = _request(client_host="203.0.113.7", headers={"X-Forwarded-For": "198.51.100.1"})

    assert client_address(request, trusted_proxy_hops=0) == "203.0.113.7"


def test_a_spoofed_forwarded_header_cannot_change_the_bucket() -> None:
    """The header is caller-controlled. Trusting it by default would let an
    attacker take a fresh identity per request — the same as no limit."""
    first = _request(client_host="203.0.113.7", headers={"X-Forwarded-For": "10.0.0.1"})
    second = _request(client_host="203.0.113.7", headers={"X-Forwarded-For": "10.0.0.2"})

    assert client_address(first) == client_address(second)


def test_one_trusted_proxy_yields_the_client_address() -> None:
    request = _request(client_host="10.0.0.9", headers={"X-Forwarded-For": "198.51.100.1"})

    assert client_address(request, trusted_proxy_hops=1) == "198.51.100.1"


def test_two_trusted_proxies_skip_the_inner_hop() -> None:
    request = _request(
        client_host="10.0.0.9",
        headers={"X-Forwarded-For": "198.51.100.1, 10.0.0.8"},
    )

    assert client_address(request, trusted_proxy_hops=2) == "198.51.100.1"


def test_a_short_forwarded_chain_falls_back_to_the_peer() -> None:
    """Fewer hops than configured means the header did not come from the expected
    topology, so it is not evidence about anything."""
    request = _request(client_host="10.0.0.9", headers={"X-Forwarded-For": "198.51.100.1"})

    assert client_address(request, trusted_proxy_hops=3) == "10.0.0.9"


# ── enforce() ─────────────────────────────────────────────────────────────────


def test_enforce_raises_429_with_retry_after() -> None:
    from fastapi import HTTPException

    store = InMemoryStore()
    settings = _settings()
    request = _request()

    ratelimit.enforce(
        request, store, settings, bucket="b", identity="i", limit=1, window_seconds=60
    )
    with pytest.raises(HTTPException) as raised:
        ratelimit.enforce(
            request, store, settings, bucket="b", identity="i", limit=1, window_seconds=60
        )

    assert raised.value.status_code == status.HTTP_429_TOO_MANY_REQUESTS
    assert raised.value.headers is not None
    assert "Retry-After" in raised.value.headers
    assert raised.value.headers[LIMIT_HEADER] == "1"


def test_enforce_does_nothing_when_disabled() -> None:
    store = InMemoryStore()
    settings = _settings(rate_limit_enabled=False)
    request = _request()

    for _ in range(50):
        ratelimit.enforce(
            request, store, settings, bucket="b", identity="i", limit=1, window_seconds=60
        )


def test_an_allowed_request_records_advisory_headers() -> None:
    store = InMemoryStore()
    request = _request()

    ratelimit.enforce(
        request, store, _settings(), bucket="b", identity="i", limit=5, window_seconds=60
    )

    assert request.state.rate_limit_headers[REMAINING_HEADER] == "4"


# ── Through the app ───────────────────────────────────────────────────────────


@pytest.fixture(name="limited_client")
def limited_client_fixture(client: TestClient, app: FastAPI) -> TestClient:
    """The app with a fresh in-memory store, so one test cannot exhaust another."""
    store = InMemoryStore()
    app.dependency_overrides[get_rate_limit_store] = lambda: store
    return client


def test_login_is_rate_limited_per_address(limited_client: TestClient, api: str) -> None:
    settings = _settings()
    refused = None

    for _ in range(settings.auth_rate_limit + 5):
        response = limited_client.get(f"{api}/auth/login", follow_redirects=False)
        if response.status_code == status.HTTP_429_TOO_MANY_REQUESTS:
            refused = response
            break

    assert refused is not None, "login should be refused once the window is exhausted"
    assert refused.headers["Retry-After"].isdigit()


def test_the_callback_is_rate_limited(limited_client: TestClient, api: str) -> None:
    """Verifying a token means asymmetric crypto and an outbound JWKS fetch — the
    cheapest way for an anonymous caller to make the API do expensive work."""
    refused = None

    for _ in range(40):
        response = limited_client.get(f"{api}/auth/callback", follow_redirects=False)
        if response.status_code == status.HTTP_429_TOO_MANY_REQUESTS:
            refused = response
            break

    assert refused is not None


def test_rejected_engine_tokens_are_rate_limited(limited_client: TestClient, api: str) -> None:
    task_id = uuid.uuid4()
    refused = None

    for _ in range(60):
        response = limited_client.post(
            f"{api}/scan-tasks/{task_id}/lease",
            headers={"Authorization": "Bearer not-a-real-token"},
            json={"engine_id": str(uuid.uuid4())},
        )
        if response.status_code == status.HTTP_429_TOO_MANY_REQUESTS:
            refused = response
            break
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    assert refused is not None, "repeated bad tokens should eventually be refused"


def test_an_engine_that_exhausts_its_budget_is_refused(
    limited_client: TestClient,
    api: str,
    app: FastAPI,
    api_settings: ApiSettings,
    make_engine: Callable[..., tuple[Engine, str]],
) -> None:
    app.dependency_overrides[get_settings] = lambda: api_settings.model_copy(
        update={"engine_rate_limit": 3}
    )
    _, token = make_engine("engine-1")
    headers = {"Authorization": f"Bearer {token}"}

    codes = [
        limited_client.post(
            f"{api}/engines/{uuid.uuid4()}/heartbeat", headers=headers, json={}
        ).status_code
        for _ in range(4)
    ]

    assert codes[-1] == status.HTTP_429_TOO_MANY_REQUESTS


def test_one_engine_exhausting_its_budget_does_not_throttle_another(
    limited_client: TestClient,
    api: str,
    app: FastAPI,
    api_settings: ApiSettings,
    make_engine: Callable[..., tuple[Engine, str]],
) -> None:
    """The reason engines are charged per engine and not per address.

    Both of these arrive from the same client address. If the bucket were keyed on
    that, a fleet behind one NAT would throttle itself and `--scale engine=N`
    would stop meaning anything.
    """
    app.dependency_overrides[get_settings] = lambda: api_settings.model_copy(
        update={"engine_rate_limit": 3}
    )
    _, first_token = make_engine("engine-1")
    _, second_token = make_engine("engine-2")

    for _ in range(5):
        limited_client.post(
            f"{api}/engines/{uuid.uuid4()}/heartbeat",
            headers={"Authorization": f"Bearer {first_token}"},
            json={},
        )
    # engine-1 is now over its limit; engine-2 has spent nothing.
    response = limited_client.post(
        f"{api}/engines/{uuid.uuid4()}/heartbeat",
        headers={"Authorization": f"Bearer {second_token}"},
        json={},
    )

    assert response.status_code != status.HTTP_429_TOO_MANY_REQUESTS


@pytest.fixture(name="make_engine")
def make_engine_fixture(session: Session) -> Callable[..., tuple[Engine, str]]:
    def factory(name: str) -> tuple[Engine, str]:
        engine = Engine(name=name, token_hash="")
        minted = mint_token(engine)
        session.add(minted.engine)
        session.commit()
        return minted.engine, minted.token

    return factory


def test_a_healthy_request_carries_advisory_headers(limited_client: TestClient, api: str) -> None:
    response = limited_client.get(f"{api}/auth/login", follow_redirects=False)

    assert response.headers[LIMIT_HEADER] == str(_settings().auth_rate_limit)
    assert int(response.headers[REMAINING_HEADER]) >= 0


def test_an_unlimited_endpoint_carries_no_rate_limit_headers(
    limited_client: TestClient,
) -> None:
    response = limited_client.get("/healthz")

    assert LIMIT_HEADER not in response.headers


def test_a_decision_is_a_value_not_a_side_effect() -> None:
    """`Decision` is deliberately inert: `enforce` decides what to do with it, so
    a call site cannot accidentally consume budget by inspecting one."""
    decision = Decision(allowed=False, limit=5, remaining=0, reset_after=30)

    assert decision.allowed is False
    assert decision.reset_after == 30
