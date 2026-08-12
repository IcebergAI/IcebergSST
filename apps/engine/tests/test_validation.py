from __future__ import annotations

import httpx2
import pytest
from iceberg_engine.validation import (
    GithubTokenValidator,
    OpaqueCredential,
    RedisMinuteLimiter,
    ValidationExecutor,
    ValidationOutcome,
)

SECRET = "github_pat_11AA_test-only-never-live"


def _policy(**overrides: object) -> dict[str, object]:
    return {
        "policy_id": "11111111-1111-1111-1111-111111111111",
        "rule_id": "github-fine-grained-pat",
        "validator_id": "github-token-v1",
        "timeout_seconds": 2.0,
        "requests_per_minute": 10,
        "max_attempts_per_task": 3,
    } | overrides


@pytest.mark.parametrize(
    ("status_code", "status", "reason"),
    [
        (200, "live", "credential_accepted"),
        (401, "revoked", "credential_rejected"),
        (403, "unknown", "inconclusive_response"),
        (429, "unknown", "provider_rate_limited"),
        (503, "error", "provider_unavailable"),
    ],
)
def test_github_contract_maps_only_documented_signals(
    status_code: int, status: str, reason: str
) -> None:
    requests: list[httpx2.Request] = []

    def handle(request: httpx2.Request) -> httpx2.Response:
        requests.append(request)
        return httpx2.Response(
            status_code,
            headers={"Location": f"https://evil.test/{SECRET}"},
            content=SECRET.encode() * 100,
        )

    validator = GithubTokenValidator(transport=httpx2.MockTransport(handle))
    outcome = validator.validate(OpaqueCredential(SECRET), timeout_seconds=1)

    assert (outcome.status, outcome.reason) == (status, reason)
    assert len(requests) == 1
    request = requests[0]
    assert request.method == "GET"
    assert str(request.url) == "https://api.github.com/user"
    assert request.headers["Authorization"] == f"Bearer {SECRET}"
    assert SECRET not in repr(outcome)


def test_opaque_credential_never_renders_plaintext() -> None:
    credential = OpaqueCredential(SECRET)
    assert SECRET not in str(credential)
    assert SECRET not in repr(credential)


class _FakeValidator:
    validator_id = "github-token-v1"
    provider = "github"
    contract_version = "1"
    supported_rule_ids = frozenset({"github-fine-grained-pat"})

    def __init__(self) -> None:
        self.seen: list[str] = []

    def validate(
        self, credential: OpaqueCredential, *, timeout_seconds: float
    ) -> ValidationOutcome:
        self.seen.append(credential.reveal_for_provider())
        return ValidationOutcome(
            provider=self.provider,
            validator_id=self.validator_id,
            contract_version=self.contract_version,
            status="live",
            reason="credential_accepted",
        )


def test_unknown_or_mismatched_policy_is_fail_closed_without_provider_call() -> None:
    validator = _FakeValidator()
    executor = ValidationExecutor.from_payloads(
        [_policy(rule_id="aws-access-key-id")],
        validators={validator.validator_id: validator},
    )

    assert (
        executor.validate(rule_id="aws-access-key-id", secret_hash="a" * 64, secret=SECRET) is None
    )
    assert validator.seen == []


def test_same_secret_hash_is_validated_once_per_task() -> None:
    validator = _FakeValidator()
    executor = ValidationExecutor.from_payloads(
        [_policy()], validators={validator.validator_id: validator}
    )

    first = executor.validate(
        rule_id="github-fine-grained-pat", secret_hash="a" * 64, secret=SECRET
    )
    second = executor.validate(
        rule_id="github-fine-grained-pat", secret_hash="a" * 64, secret=SECRET
    )

    assert first == second
    assert validator.seen == [SECRET]


def test_task_budget_blocks_without_calling_provider() -> None:
    validator = _FakeValidator()
    executor = ValidationExecutor.from_payloads(
        [_policy(max_attempts_per_task=1)], validators={validator.validator_id: validator}
    )

    executor.validate(rule_id="github-fine-grained-pat", secret_hash="a" * 64, secret=SECRET)
    blocked = executor.validate(
        rule_id="github-fine-grained-pat", secret_hash="b" * 64, secret="different"
    )

    assert blocked is not None
    assert (blocked.status, blocked.reason) == ("blocked", "policy_budget_exhausted")
    assert validator.seen == [SECRET]


class _Redis:
    def __init__(self, result: int = 1, *, fails: bool = False) -> None:
        self.result = result
        self.fails = fails
        self.calls: list[tuple[str, int, str, int]] = []

    def eval(self, script: str, keys: int, key: str, limit: int) -> int:
        self.calls.append((script, keys, key, limit))
        if self.fails:
            raise ConnectionError
        return self.result


def test_redis_limiter_uses_only_bounded_policy_metadata() -> None:
    redis = _Redis()
    limiter = RedisMinuteLimiter(redis)

    assert limiter.acquire("github-token-v1", 17) is True
    assert len(redis.calls) == 1
    _script, keys, key, limit = redis.calls[0]
    assert (keys, key, limit) == (
        1,
        "icebergsst:credential-validation:github-token-v1",
        17,
    )
    assert SECRET not in repr(redis.calls)


def test_redis_limiter_fails_closed_on_budget_or_redis_failure() -> None:
    assert RedisMinuteLimiter(_Redis(result=0)).acquire("github-token-v1", 1) is False
    assert RedisMinuteLimiter(_Redis(fails=True)).acquire("github-token-v1", 1) is False
    assert RedisMinuteLimiter(_Redis()).acquire("../../unsafe", 1) is False
