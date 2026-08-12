"""Bounded, status-only validation of detected credentials.

Plaintext already exists transiently in the engine during detection.  This module
is the only additional boundary allowed to consume it: one fixed, reviewed
provider request.  Provider responses and exceptions are deliberately collapsed
to stable codes before control returns to the scan runner.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol

import httpx2


@dataclass(frozen=True, slots=True)
class OpaqueCredential:
    """A credential whose normal string representations never reveal its value."""

    _value: str = field(repr=False)

    def __str__(self) -> str:
        return "[REDACTED]"

    def reveal_for_provider(self) -> str:
        """Return plaintext only at the reviewed request-construction boundary."""
        return self._value


@dataclass(frozen=True, slots=True)
class ValidationOutcome:
    provider: str
    validator_id: str
    contract_version: str
    status: str
    reason: str

    def as_payload(self) -> dict[str, str]:
        return {
            "provider": self.provider,
            "validator_id": self.validator_id,
            "contract_version": self.contract_version,
            "status": self.status,
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class ValidationPolicy:
    policy_id: str
    rule_id: str
    validator_id: str
    timeout_seconds: float
    requests_per_minute: int
    max_attempts_per_task: int

    @classmethod
    def from_payload(cls, payload: Mapping[str, object]) -> ValidationPolicy:
        timeout = payload["timeout_seconds"]
        requests = payload["requests_per_minute"]
        attempts = payload["max_attempts_per_task"]
        if not isinstance(timeout, int | float) or isinstance(timeout, bool):
            raise TypeError("timeout_seconds must be numeric")
        if not isinstance(requests, int) or isinstance(requests, bool):
            raise TypeError("requests_per_minute must be an integer")
        if not isinstance(attempts, int) or isinstance(attempts, bool):
            raise TypeError("max_attempts_per_task must be an integer")
        return cls(
            policy_id=str(payload["policy_id"]),
            rule_id=str(payload["rule_id"]),
            validator_id=str(payload["validator_id"]),
            timeout_seconds=float(timeout),
            requests_per_minute=requests,
            max_attempts_per_task=attempts,
        )


class CredentialValidator(Protocol):
    validator_id: str
    provider: str
    contract_version: str
    supported_rule_ids: frozenset[str]

    def validate(
        self, credential: OpaqueCredential, *, timeout_seconds: float
    ) -> ValidationOutcome:
        """Perform at most one side-effect-free provider request."""


@dataclass(slots=True)
class GithubTokenValidator:
    """Validate GitHub tokens with one read-only identity request.

    The endpoint, method and auth placement are constants. Redirects, environment
    proxies and response-body parsing are all disabled.
    """

    transport: httpx2.BaseTransport | None = None
    validator_id: str = "github-token-v1"
    provider: str = "github"
    contract_version: str = "1"
    supported_rule_ids: frozenset[str] = frozenset({"github-token", "github-fine-grained-pat"})

    def validate(
        self, credential: OpaqueCredential, *, timeout_seconds: float
    ) -> ValidationOutcome:
        try:
            timeout = httpx2.Timeout(timeout_seconds)
            with httpx2.Client(
                transport=self.transport,
                timeout=timeout,
                follow_redirects=False,
                trust_env=False,
            ) as client:
                request = client.build_request(
                    "GET",
                    "https://api.github.com/user",
                    headers={
                        "Authorization": f"Bearer {credential.reveal_for_provider()}",
                        "Accept": "application/vnd.github+json",
                        "X-GitHub-Api-Version": "2022-11-28",
                        "User-Agent": "IcebergSST-credential-validator/1",
                    },
                )
                response = client.send(request, stream=True)
                try:
                    status_code = response.status_code
                finally:
                    response.close()
        except httpx2.TimeoutException:
            return self._outcome("error", "timeout")
        except httpx2.HTTPError:
            return self._outcome("error", "provider_unavailable")
        except Exception:
            # Provider-library exception messages may contain request headers or
            # reflected response data. Never retain or chain them.
            return self._outcome("error", "protocol_error")

        if status_code == 200:
            return self._outcome("live", "credential_accepted")
        if status_code == 401:
            return self._outcome("revoked", "credential_rejected")
        if status_code == 429:
            return self._outcome("unknown", "provider_rate_limited")
        if 500 <= status_code <= 599:
            return self._outcome("error", "provider_unavailable")
        return self._outcome("unknown", "inconclusive_response")

    def _outcome(self, status: str, reason: str) -> ValidationOutcome:
        return ValidationOutcome(
            provider=self.provider,
            validator_id=self.validator_id,
            contract_version=self.contract_version,
            status=status,
            reason=reason,
        )


class RateLimiter(Protocol):
    """Fleet or process budget used before any credential reaches a provider."""

    def acquire(self, validator_id: str, limit: int) -> bool: ...


class _MinuteLimiter:
    """Process-wide bounded provider budget; failure is deny, never fail-open."""

    def __init__(self, *, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._attempts: dict[str, deque[float]] = defaultdict(deque)

    def acquire(self, validator_id: str, limit: int) -> bool:
        now = self._clock()
        with self._lock:
            attempts = self._attempts[validator_id]
            while attempts and attempts[0] <= now - 60:
                attempts.popleft()
            if len(attempts) >= limit:
                return False
            attempts.append(now)
            return True


_PROCESS_LIMITER = _MinuteLimiter()


class RedisMinuteLimiter:
    """Fleet-wide fixed-window budget backed by the engine's existing Redis.

    Only the reviewed validator identifier and a counter cross this boundary.
    Provider credentials and their hashes are never keys, arguments, or values.
    Any Redis failure denies the provider call.
    """

    _SCRIPT = """
local current = redis.call('INCR', KEYS[1])
if current == 1 then
  redis.call('EXPIRE', KEYS[1], 61)
end
if current <= tonumber(ARGV[1]) then
  return 1
end
return 0
"""

    def __init__(self, client: Any) -> None:
        self._client = client

    @classmethod
    def from_url(cls, redis_url: str) -> RedisMinuteLimiter:
        import redis

        return cls(redis.Redis.from_url(redis_url, decode_responses=False))

    def acquire(self, validator_id: str, limit: int) -> bool:
        # validator_id comes from the compiled registry, but keep the Redis key
        # alphabet bounded even if a future caller violates that invariant.
        if not validator_id or any(not (char.isalnum() or char in "-_") for char in validator_id):
            return False
        try:
            result = self._client.eval(
                self._SCRIPT,
                1,
                f"icebergsst:credential-validation:{validator_id}",
                limit,
            )
        except Exception:
            return False
        return isinstance(result, int) and result == 1


@dataclass(slots=True)
class ValidationExecutor:
    """Apply an immutable lease policy to candidates within one scan task."""

    policies: tuple[ValidationPolicy, ...]
    validators: Mapping[str, CredentialValidator]
    limiter: RateLimiter = field(default_factory=lambda: _PROCESS_LIMITER)
    _attempts: dict[str, int] = field(default_factory=dict)
    _cache: dict[tuple[str, str], ValidationOutcome] = field(default_factory=dict)

    @classmethod
    def from_payloads(
        cls,
        payloads: list[dict[str, object]],
        *,
        validators: Mapping[str, CredentialValidator] | None = None,
        limiter: RateLimiter | None = None,
    ) -> ValidationExecutor:
        registry = validators or {"github-token-v1": GithubTokenValidator()}
        policies: list[ValidationPolicy] = []
        for payload in payloads:
            try:
                policy = ValidationPolicy.from_payload(payload)
            except KeyError, TypeError, ValueError:
                continue
            validator = registry.get(policy.validator_id)
            if validator is None or policy.rule_id not in validator.supported_rule_ids:
                continue
            if (
                policy.timeout_seconds <= 0
                or policy.requests_per_minute <= 0
                or policy.max_attempts_per_task <= 0
            ):
                continue
            policies.append(policy)
        return cls(
            policies=tuple(policies),
            validators=registry,
            limiter=limiter or _PROCESS_LIMITER,
        )

    def validate(self, *, rule_id: str, secret_hash: str, secret: str) -> ValidationOutcome | None:
        policy = next((item for item in self.policies if item.rule_id == rule_id), None)
        if policy is None:
            return None
        validator = self.validators[policy.validator_id]
        cache_key = (policy.validator_id, secret_hash)
        if cached := self._cache.get(cache_key):
            return cached

        attempts = self._attempts.get(policy.policy_id, 0)
        if attempts >= policy.max_attempts_per_task:
            outcome = ValidationOutcome(
                provider=validator.provider,
                validator_id=validator.validator_id,
                contract_version=validator.contract_version,
                status="blocked",
                reason="policy_budget_exhausted",
            )
            self._cache[cache_key] = outcome
            return outcome
        if not self.limiter.acquire(policy.validator_id, policy.requests_per_minute):
            outcome = ValidationOutcome(
                provider=validator.provider,
                validator_id=validator.validator_id,
                contract_version=validator.contract_version,
                status="blocked",
                reason="policy_budget_exhausted",
            )
            self._cache[cache_key] = outcome
            return outcome

        self._attempts[policy.policy_id] = attempts + 1
        outcome = validator.validate(
            OpaqueCredential(secret), timeout_seconds=policy.timeout_seconds
        )
        self._cache[cache_key] = outcome
        return outcome
