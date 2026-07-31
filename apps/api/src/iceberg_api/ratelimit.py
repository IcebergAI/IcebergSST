"""Rate limiting for the endpoints an unauthenticated caller can reach (#63).

Three endpoints are worth limiting, for three different reasons:

* **`/auth/login`** starts an OIDC flow and sets a signed cookie. Unlimited, it is
  a way to make the API hammer the identity provider on someone else's behalf.
* **`/auth/callback`** verifies a token against the provider's JWKS. It is the
  cheapest way for an anonymous caller to make the API do asymmetric crypto and
  outbound HTTP.
* **Engine token presentation.** Tokens are 256-bit random, so guessing one is not
  a realistic threat — but an endpoint that does a database lookup per request
  with no session behind it is still worth a ceiling, and the limit is what turns
  a credential-stuffing attempt into something visible in the metrics.

Two properties are deliberate.

**It fails open.** If Redis is unreachable the request is allowed, with a log
line. A rate limiter that locks every operator out of the console when its
counter store hiccups has done more damage than the traffic it was defending
against — and none of these limits is the last line of defence: authentication is.

**Authenticated engines are limited per engine, not per address.** A fleet behind
one NAT would otherwise share a budget and throttle each other, and the whole
point of `--scale engine=N` is that adding replicas works.

The store is Redis when configured, so a limit means the same thing across
replicas. In-memory is the fallback, and is honest rather than wrong: with one
replica it is exact, and with several each enforces the limit independently
(``docs/security.md`` § Rate limiting says so).
"""

import threading
import time
from dataclasses import dataclass
from typing import Annotated, Protocol

import structlog
from fastapi import Depends, HTTPException, Request, Response, status
from iceberg_core.config import ApiSettings

from iceberg_api.auth.dependencies import SettingsDep

logger = structlog.get_logger()

#: Header names from the (expired but widely implemented) IETF draft. A client
#: that reads them can back off before it is refused.
LIMIT_HEADER = "RateLimit-Limit"
REMAINING_HEADER = "RateLimit-Remaining"
RESET_HEADER = "RateLimit-Reset"


@dataclass(frozen=True, slots=True)
class Decision:
    """The outcome of one hit against a bucket."""

    allowed: bool
    limit: int
    remaining: int
    #: Seconds until the window rolls over; the value for ``Retry-After``.
    reset_after: int


class RateLimitStore(Protocol):
    """Counts hits in a fixed window.

    Fixed window rather than a sliding log or a token bucket: it is one INCR, it
    needs no per-key data structure, and its worst case — twice the limit across a
    window boundary — is irrelevant at limits chosen to stop floods rather than to
    meter usage precisely.
    """

    def hit(self, key: str, *, limit: int, window_seconds: int) -> Decision: ...


class InMemoryStore:
    """Per-process counters. Exact for one replica, per-replica for several.

    Entries carry their expiry and lapsed ones are swept, because the unauthenticated
    buckets are keyed by client address: an attacker rotating source addresses —
    trivial over IPv6 — would otherwise grow this map for the life of the process.
    What is left after a sweep is one entry per address seen *within the current
    window*, which is the smallest a fixed-window counter can be.
    """

    #: Entries tolerated before a sweep. High enough that a normal deployment never
    #: pays for one, low enough that a flood cannot get far before it does.
    SWEEP_THRESHOLD = 10_000

    def __init__(self) -> None:
        self._windows: dict[str, tuple[int, int]] = {}
        # Uvicorn serves sync endpoints from a thread pool, so two requests really
        # can land here at once.
        self._lock = threading.Lock()

    def hit(self, key: str, *, limit: int, window_seconds: int) -> Decision:
        now = int(time.monotonic())
        window_start = now - (now % window_seconds)
        # Stored as the expiry rather than the start: buckets have different window
        # lengths, so an entry can only say for itself when it stopped counting.
        expires_at = window_start + window_seconds
        with self._lock:
            if len(self._windows) >= self.SWEEP_THRESHOLD:
                self._windows = {
                    stale: entry for stale, entry in self._windows.items() if entry[0] > now
                }
            expiry, count = self._windows.get(key, (0, 0))
            count = count + 1 if expiry > now else 1
            self._windows[key] = (expires_at, count)
        return Decision(
            allowed=count <= limit,
            limit=limit,
            remaining=max(0, limit - count),
            reset_after=max(1, expires_at - now),
        )

    def clear(self) -> None:
        """Drop every counter. For tests, and for nothing else."""
        with self._lock:
            self._windows.clear()


class RedisStore:
    """Counters shared by every API replica.

    ``INCR`` then ``EXPIRE`` on first hit. Not a transaction on purpose: the worst
    case is a key that misses its expiry and lives one extra window, which costs a
    caller one window of budget and cannot deny anyone else.
    """

    def __init__(self, client: object) -> None:
        self._client = client

    def hit(self, key: str, *, limit: int, window_seconds: int) -> Decision:
        now = int(time.time())
        window_start = now - (now % window_seconds)
        redis_key = f"ratelimit:{key}:{window_start}"
        try:
            count = int(self._client.incr(redis_key))  # type: ignore[attr-defined]
            if count == 1:
                # Twice the window, so a key created at the very end of one is
                # still around to be read for the whole of it.
                self._client.expire(redis_key, window_seconds * 2)  # type: ignore[attr-defined]
        except Exception:
            # Fail open — see the module docstring. Deliberately broad: any redis
            # client error, including ones raised while connecting.
            logger.warning("rate_limit_store_unavailable", key=key, exc_info=True)
            return Decision(allowed=True, limit=limit, remaining=limit, reset_after=window_seconds)

        return Decision(
            allowed=count <= limit,
            limit=limit,
            remaining=max(0, limit - count),
            reset_after=max(1, window_start + window_seconds - now),
        )


def build_store(settings: ApiSettings) -> RateLimitStore:
    """The store this deployment should use.

    Redis when it is configured, which in any real deployment it is — the broker
    needs it. Constructing the client does not connect, so a Redis that is down at
    startup does not stop the API coming up; the first hit fails open and logs.
    """
    if not settings.rate_limit_use_redis:
        return InMemoryStore()
    try:
        import redis

        return RedisStore(redis.Redis.from_url(settings.redis_url))
    except Exception:
        logger.warning("rate_limit_redis_unavailable_falling_back", exc_info=True)
        return InMemoryStore()


def client_address(request: Request, *, trusted_proxy_hops: int = 0) -> str:
    """The address to charge a request to.

    ``X-Forwarded-For`` is only consulted when the operator says how many proxies
    sit in front (``ICEBERG_TRUSTED_PROXY_HOPS``), because a caller can put
    anything in that header: trusting it by default would let an attacker pick a
    fresh identity per request and make the limit meaningless. With no proxies
    configured the peer address is the truth.
    """
    if trusted_proxy_hops > 0:
        forwarded = request.headers.get("x-forwarded-for", "")
        hops = [part.strip() for part in forwarded.split(",") if part.strip()]
        # Each proxy appends the address it saw, so the client is the entry the
        # outermost trusted proxy added: `hops[-trusted_proxy_hops]`.
        if len(hops) >= trusted_proxy_hops:
            return hops[-trusted_proxy_hops]
    return request.client.host if request.client else "unknown"


def enforce(
    request: Request,
    store: RateLimitStore,
    settings: ApiSettings,
    *,
    bucket: str,
    identity: str,
    limit: int,
    window_seconds: int,
) -> None:
    """Charge one hit, and raise 429 if the bucket is empty.

    Raising rather than returning a decision keeps every call site to one line and
    means a route cannot forget to check the answer.
    """
    if not settings.rate_limit_enabled:
        return

    decision = store.hit(f"{bucket}:{identity}", limit=limit, window_seconds=window_seconds)
    headers = {
        LIMIT_HEADER: str(decision.limit),
        REMAINING_HEADER: str(decision.remaining),
        RESET_HEADER: str(decision.reset_after),
    }
    if decision.allowed:
        # Advisory even on success, so a well-behaved client can slow down before
        # it is refused rather than after.
        request.state.rate_limit_headers = headers
        return

    logger.warning("rate_limited", bucket=bucket, limit=limit, window_seconds=window_seconds)
    raise HTTPException(
        status.HTTP_429_TOO_MANY_REQUESTS,
        "too many requests",
        headers={**headers, "Retry-After": str(decision.reset_after)},
    )


# ── FastAPI wiring ────────────────────────────────────────────────────────────

#: One store per process. Built lazily rather than at import so constructing the
#: app never depends on Redis being reachable.
_store: RateLimitStore | None = None


def get_rate_limit_store(settings: SettingsDep) -> RateLimitStore:
    """The process's store, as an overridable dependency."""
    global _store
    if _store is None:
        _store = build_store(settings)
    return _store


def reset_rate_limit_store() -> None:
    """Drop the cached store. For tests that change settings between apps."""
    global _store
    _store = None


RateLimitStoreDep = Annotated[RateLimitStore, Depends(get_rate_limit_store)]


def auth_rate_limit(
    request: Request,
    settings: SettingsDep,
    store: RateLimitStoreDep,
) -> None:
    """Ceiling on the OIDC entry points, per client address."""
    enforce(
        request,
        store,
        settings,
        bucket="auth",
        identity=client_address(request, trusted_proxy_hops=settings.trusted_proxy_hops),
        limit=settings.auth_rate_limit,
        window_seconds=settings.auth_rate_limit_window_seconds,
    )


#: Declared by the login and callback routes.
AuthRateLimited = Depends(auth_rate_limit)


def attach_headers(request: Request, response: Response) -> None:
    """Copy the advisory headers a successful hit recorded onto the response."""
    headers: dict[str, str] | None = getattr(request.state, "rate_limit_headers", None)
    if headers:
        response.headers.update(headers)


__all__ = [
    "LIMIT_HEADER",
    "REMAINING_HEADER",
    "RESET_HEADER",
    "AuthRateLimited",
    "Decision",
    "InMemoryStore",
    "RateLimitStore",
    "RateLimitStoreDep",
    "RedisStore",
    "attach_headers",
    "auth_rate_limit",
    "build_store",
    "client_address",
    "enforce",
    "get_rate_limit_store",
    "reset_rate_limit_store",
]
