"""The engine's half of the engine↔API conversation (#51 — ADR 0002, 0009).

An engine talks to exactly two things: Redis, for a nudge that work exists, and
this client, for everything that matters. It has no database credentials and no
way to acquire any, which is the boundary ADR 0002 draws and the reason this
module is the only place the engine reaches the control plane.

**What is safe to retry, and why.** A network error leaves the engine unable to
tell "the API never saw it" from "the API saw it and the reply was lost". Retrying
blind would double-count findings — except that results submission carries an
idempotency key (``<task id>:<attempt>``), so a replay of an accepted submission
is answered as a replay rather than ingested twice (ADR 0009 §2). Retry here is
safe *because of* that key, not despite it, so the two belong in one module.

Retries cover transport failures and 5xx. They deliberately do not cover 4xx: a
409 on lease means the task is not available and the correct response is to drop
the message, and a 401 means this engine's token is no longer valid — retrying
either just makes the same wrong request more often.
"""

import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import httpx2
import structlog
from iceberg_core.metrics import ENGINE_API_RETRIES

logger = structlog.get_logger()

#: Statuses worth trying again. Everything else is the API's considered answer.
RETRYABLE_STATUSES = frozenset({500, 502, 503, 504})


class EngineApiError(Exception):
    """The API could not be reached, or answered in a way the engine cannot use.

    Terminal by default. Only :class:`RetryableApiError` is tried again — a plain
    `EngineApiError` means asking a second time would send the same wrong request.
    """


class RetryableApiError(EngineApiError):
    """A transport failure or a 5xx: the API may well answer if asked again."""


class LeaseRefused(EngineApiError):
    """The task is not available to lease.

    Already claimed, already finished, cancelled, or unknown — the API answers 409
    to all of them because the engine's response is the same for each: drop the
    broker message and move on (ADR 0009 §2).
    """


class LeaseNotHeld(EngineApiError):
    """403: the API does not believe this engine holds the task.

    Kept apart from a rejected token, which is the other way to get a 4xx here and
    means something entirely different: the lease was reclaimed or the task
    cancelled while the engine worked, which is routine, where a rejected token
    means this engine can no longer talk to the API at all (#131).
    """


class AuthenticationFailed(EngineApiError):
    """401: this engine's token was rejected. Rotated, revoked, or never valid."""


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    """How hard to try before giving up on the control plane.

    Bounded on purpose. An engine that retried forever would hold a lease it
    cannot renew while the API decides it is dead and reclaims the task — two
    engines then believe they own it, and the only thing stopping a duplicate
    submission is the idempotency key. Failing fast lets reclaim be the single
    recovery path it is designed to be.
    """

    attempts: int = 4
    base_delay_seconds: float = 0.5
    max_delay_seconds: float = 8.0

    def delay_for(self, attempt: int) -> float:
        """Exponential backoff, capped. No jitter: one engine per task, so there
        is no thundering herd to spread — and a deterministic delay is testable."""
        return float(min(self.base_delay_seconds * (2**attempt), self.max_delay_seconds))


@dataclass(frozen=True, slots=True)
class Lease:
    """A granted lease, as the engine sees it.

    A plain view over the response body rather than a typed mirror of the API's
    schema: the two are versioned separately, and an engine that refused to start
    because the API grew a field would be a rolling-deploy outage.
    """

    payload: dict[str, Any]

    @property
    def task_id(self) -> uuid.UUID:
        return uuid.UUID(str(self.payload["task_id"]))

    @property
    def scan_id(self) -> uuid.UUID:
        return uuid.UUID(str(self.payload["scan_id"]))

    @property
    def source_id(self) -> uuid.UUID:
        return uuid.UUID(str(self.payload["source_id"]))

    @property
    def kind(self) -> str:
        return str(self.payload["kind"])

    @property
    def source_type(self) -> str:
        return str(self.payload["source_type"])

    @property
    def attempt(self) -> int:
        return int(self.payload.get("attempt", 1))

    @property
    def spec(self) -> dict[str, Any]:
        spec = self.payload.get("spec")
        return dict(spec) if isinstance(spec, dict) else {}

    @property
    def connection(self) -> dict[str, Any]:
        connection = self.payload.get("connection")
        return dict(connection) if isinstance(connection, dict) else {}

    @property
    def credential(self) -> str | None:
        credential = self.payload.get("credential")
        return str(credential) if credential else None

    @property
    def fingerprint_pepper(self) -> str | None:
        pepper = self.payload.get("fingerprint_pepper")
        return str(pepper) if pepper else None

    @property
    def previous_fingerprint_pepper(self) -> str | None:
        """The outgoing pepper, present only during a rotation window (#64)."""
        pepper = self.payload.get("previous_fingerprint_pepper")
        return str(pepper) if pepper else None

    @property
    def suppressions(self) -> list[dict[str, str]]:
        rules = self.payload.get("suppressions")
        return list(rules) if isinstance(rules, list) else []

    @property
    def confidence_threshold(self) -> float:
        return float(self.payload.get("confidence_threshold", 0.5))

    @property
    def validation_policies(self) -> list[dict[str, object]]:
        policies = self.payload.get("validation_policies")
        if not isinstance(policies, list):
            return []
        return [dict(policy) for policy in policies if isinstance(policy, dict)]

    @property
    def idempotency_key(self) -> str:
        """``<task id>:<attempt>`` — what makes a results retry a replay."""
        return f"{self.task_id}:{self.attempt}"


@dataclass(slots=True)
class EngineClient:
    """Everything an engine says to the API.

    ``transport`` and ``sleep`` are injectable so tests drive the real client
    against a scripted transport and assert on backoff without waiting for it.
    """

    base_url: str
    token: str
    engine_id: uuid.UUID | None = None
    retry: RetryPolicy = field(default_factory=RetryPolicy)
    transport: httpx2.BaseTransport | None = None
    sleep: Callable[[float], None] = time.sleep
    timeout_seconds: float = 30.0
    #: One connection pool, held for as long as the client is. A client per
    #: request paid a TCP and TLS handshake on every lease, submission, beat and
    #: retry — with `worker_threads` up to 64 and a beat a minute, that is
    #: sustained load on the control plane for nothing (#130).
    _http: httpx2.Client = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        self._http = httpx2.Client(transport=self.transport, timeout=self.timeout_seconds)

    def close(self) -> None:
        """Release the pool. A process holds one client, so this is shutdown."""
        self._http.close()

    def heartbeat(
        self,
        *,
        task_ids: list[uuid.UUID] | None = None,
        version: str | None = None,
        rulepack: dict[str, Any] | None = None,
    ) -> list[uuid.UUID]:
        """Renew leases and learn which tasks were cancelled underneath us.

        The returned ids are the only way a running engine finds out its work was
        cancelled — there is no way to reach into a worker (ADR 0009 §4).
        """
        if self.engine_id is None:
            raise EngineApiError("cannot heartbeat without an engine id")

        body: dict[str, Any] = {"task_ids": [str(task_id) for task_id in task_ids or []]}
        if version:
            body["version"] = version
        if rulepack:
            body["rulepack"] = rulepack

        payload = self._request("POST", f"/engines/{self.engine_id}/heartbeat", json=body)
        return _parse_cancelled_ids(payload.get("cancelled_task_ids"))

    def lease(self, task_id: uuid.UUID) -> Lease:
        """Claim a task. Raises :class:`LeaseRefused` if it is not available."""
        payload = self._request("POST", f"/scan-tasks/{task_id}/lease")
        return Lease(payload=payload)

    def submit_results(self, task_id: uuid.UUID, submission: dict[str, Any]) -> dict[str, Any]:
        """Report what a task produced. Safe to retry — see the module docstring."""
        if not submission.get("idempotency_key"):
            # Without it a retried submission double-counts. Refusing here rather
            # than letting the API 422 keeps the bug where it was written.
            raise EngineApiError("results submission requires an idempotency key")
        return self._request("POST", f"/scan-tasks/{task_id}/results", json=submission)

    # ─── Transport ────────────────────────────────────────────────────────────

    def _request(
        self, method: str, path: str, *, json: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        url = f"{self.base_url.rstrip('/')}/api/v1{path}"
        last_error: Exception | None = None

        for attempt in range(self.retry.attempts):
            if attempt:
                delay = self.retry.delay_for(attempt - 1)
                logger.info("engine_api_retry", path=path, attempt=attempt, delay_seconds=delay)
                ENGINE_API_RETRIES.inc()
                self.sleep(delay)
            try:
                return self._send(method, url, json)
            except LeaseRefused, LeaseNotHeld, AuthenticationFailed:
                # The API's considered answer. Asking again changes nothing.
                raise
            except RetryableApiError as exc:
                last_error = exc
            except httpx2.HTTPError as exc:
                # Transport-level: timeout, connection refused, DNS. The API may or
                # may not have seen the request, which is exactly what the
                # idempotency key exists to make survivable.
                last_error = RetryableApiError(f"{type(exc).__name__}: {exc}")

        raise EngineApiError(
            f"{method} {path} failed after {self.retry.attempts} attempts: {last_error}"
        ) from last_error

    def _send(self, method: str, url: str, json: dict[str, Any] | None) -> dict[str, Any]:
        response = self._http.request(
            method,
            url,
            json=json,
            # The engine token is the only credential this process holds, and it
            # works nowhere else in the API (ADR 0002).
            headers={"Authorization": f"Bearer {self.token}"},
        )

        if response.status_code == 401:
            raise AuthenticationFailed("engine token rejected (401)")
        if response.status_code == 403:
            raise LeaseNotHeld("engine does not hold this task (403)")
        if response.status_code == 409:
            raise LeaseRefused("task is not available to lease")
        if response.status_code in RETRYABLE_STATUSES:
            raise RetryableApiError(f"api returned {response.status_code}")
        if response.status_code >= 400:
            # Another 4xx: a request this engine built wrongly. Retrying sends the
            # same wrong thing again, so it is terminal.
            raise EngineApiError(f"api rejected the request ({response.status_code})")

        try:
            body = response.json()
        except ValueError as exc:
            # A proxy's error page in front of a healthy API looks like this, and
            # it is worth another attempt.
            raise RetryableApiError("api returned a non-JSON body") from exc
        if not isinstance(body, dict):
            raise EngineApiError("api returned an unexpected body shape")
        return body


def _parse_cancelled_ids(raw: object) -> list[uuid.UUID]:
    """The cancelled ids from a heartbeat reply, tolerant of a malformed one.

    This runs on the heartbeat thread, so an API that returned ``null`` or a
    non-UUID here must not raise and kill the thread — a bad entry is skipped,
    not fatal. A wholly wrong shape is retryable, since a healthy API never sends
    it (a proxy or a mid-deploy regression might)."""
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise RetryableApiError("heartbeat returned a malformed cancelled_task_ids")
    parsed: list[uuid.UUID] = []
    for value in raw:
        try:
            parsed.append(uuid.UUID(str(value)))
        except ValueError, AttributeError:
            logger.warning("heartbeat_bad_cancelled_id", value=str(value)[:64])
    return parsed
