"""One scan task, start to finish (#50).

Driven through the real client against a scripted transport, so the lease request,
the submission body, and everything between are the actual ones. The connector is
the shipped `FakeConnector` rather than a mock — it really iterates and really
tallies, so a change to the protocol breaks this rather than sliding past it.

Most of these are failure cases. The happy path is one test; what earns the rest
is the rule that **a task always ends by reporting**, because a task that dies
silently leaves the API waiting out a lease before it can settle the scan.
"""

import base64
import json
import uuid
from collections.abc import Iterator
from typing import Any

import httpx2
import pytest
from dramatiq.middleware import TimeLimitExceeded
from iceberg_connectors import (
    ConnectorError,
    FakeConnector,
    FakePage,
    RateLimitError,
    TaskSpec,
    registry,
)
from iceberg_connectors.confluence import ConfluenceConnector
from iceberg_detect import load_named_pack
from iceberg_engine.api_client import EngineClient
from iceberg_engine.runner import run_task
from iceberg_engine.validation import OpaqueCredential, ValidationExecutor, ValidationOutcome
from prometheus_client import REGISTRY
from structlog.testing import capture_logs

PACK = load_named_pack()
PEPPER = b"0123456789abcdef0123456789abcdef"
TASK_ID = uuid.UUID("11111111-1111-1111-1111-111111111111")

#: AWS's own documented example key — it has never authenticated anything.
LEAKY = "Deployment notes: set aws access key AKIAIOSFODNN7EXAMPLE in the runbook."
CLEAN = "The fix landed in commit 3f2b1c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b on main."
GITHUB_SECRET = "github_pat_" + "A" * 80


def _lease(**overrides: Any) -> dict[str, Any]:
    return {
        "task_id": str(TASK_ID),
        "scan_id": "33333333-3333-3333-3333-333333333333",
        "source_id": "44444444-4444-4444-4444-444444444444",
        "source_type": "fake",
        "kind": "fetch",
        "attempt": 1,
        "lease_expires_at": "2026-07-30T00:00:00Z",
        "spec": {"label": "space DOCS", "params": {"space": "DOCS"}},
        "connection": {},
        "credential": None,
        "fingerprint_pepper": base64.b64encode(PEPPER).decode(),
        "suppressions": [],
        "confidence_threshold": 0.5,
    } | overrides


class Api:
    """A scripted API that records what the engine submitted."""

    def __init__(
        self,
        lease: dict[str, Any] | None = None,
        *,
        lease_status: int = 200,
        results_status: int = 200,
    ) -> None:
        self.lease_body = lease if lease is not None else _lease()
        self.lease_status = lease_status
        self.results_status = results_status
        self.submissions: list[dict[str, Any]] = []

    def __call__(self, request: httpx2.Request) -> httpx2.Response:
        if request.url.path.endswith("/lease"):
            if self.lease_status != 200:
                return httpx2.Response(self.lease_status)
            return httpx2.Response(200, json=self.lease_body)
        self.submissions.append(json.loads(request.content))
        if self.results_status != 200:
            return httpx2.Response(self.results_status)
        return httpx2.Response(200, json={"task_id": str(TASK_ID)})

    @property
    def submission(self) -> dict[str, Any]:
        assert len(self.submissions) == 1, f"expected one submission, got {len(self.submissions)}"
        return self.submissions[0]


def _client(api: Api) -> EngineClient:
    return EngineClient(
        base_url="http://api.test",
        token="engine-token",
        transport=httpx2.MockTransport(api),
        sleep=lambda _seconds: None,
    )


@pytest.fixture(name="source", autouse=True)
def source_fixture() -> Iterator[FakeConnector]:
    connector = FakeConnector(
        spaces={
            "DOCS": [
                FakePage("page-1", LEAKY, display={"url": "https://wiki.test/page/1"}),
                FakePage("page-2", CLEAN),
                FakePage("page-3", "", skip=True),
            ]
        }
    )
    registry.clear()
    registry.register(connector)
    yield connector
    registry.clear()


# ─── The happy path ───────────────────────────────────────────────────────────


def test_a_fetch_task_reports_redacted_findings_and_counts() -> None:
    api = Api()

    report = run_task(TASK_ID, client=_client(api), pack=PACK)

    assert report is not None
    assert report.status == "completed"
    submission = api.submission
    assert submission["idempotency_key"] == f"{TASK_ID}:1"
    assert submission["rulepack_version"] == PACK.version
    assert [f["rule_id"] for f in submission["findings"]] == ["aws-access-key-id"]
    assert submission["counts"]["units"] == 2
    assert submission["counts"]["units_skipped"] == 1
    assert submission["coverage"]["phase"] == "fetch"
    assert submission["coverage"]["counts"] == {
        "requested": 3,
        "discovered": 3,
        "scanned": 2,
        "skipped": 1,
        "failed": 0,
    }
    assert submission["coverage"]["reasons"] == [
        {"outcome": "skipped", "reason": "unsupported_type", "count": 1}
    ]


def test_no_plaintext_reaches_the_api() -> None:
    """ADR 0004, asserted against the bytes actually sent."""
    api = Api()

    run_task(TASK_ID, client=_client(api), pack=PACK)

    assert "AKIAIOSFODNN7EXAMPLE" not in json.dumps(api.submission)


def test_validation_uses_plaintext_only_inside_provider_boundary(
    source: FakeConnector,
) -> None:
    source.spaces["DOCS"] = [FakePage("page-1", GITHUB_SECRET)]
    api = Api(
        _lease(
            validation_policies=[
                {
                    "policy_id": "55555555-5555-5555-5555-555555555555",
                    "rule_id": "github-fine-grained-pat",
                    "validator_id": "github-token-v1",
                    "timeout_seconds": 1,
                    "requests_per_minute": 10,
                    "max_attempts_per_task": 1,
                }
            ]
        )
    )

    class Provider:
        validator_id = "github-token-v1"
        provider = "github"
        contract_version = "1"
        supported_rule_ids = frozenset({"github-fine-grained-pat"})

        def __init__(self) -> None:
            self.received: list[str] = []

        def validate(
            self, credential: OpaqueCredential, *, timeout_seconds: float
        ) -> ValidationOutcome:
            self.received.append(credential.reveal_for_provider())
            return ValidationOutcome(
                provider=self.provider,
                validator_id=self.validator_id,
                contract_version=self.contract_version,
                status="live",
                reason="credential_accepted",
            )

    provider = Provider()
    executor = ValidationExecutor.from_payloads(
        api.lease_body["validation_policies"],
        validators={provider.validator_id: provider},
    )

    run_task(
        TASK_ID,
        client=_client(api),
        pack=PACK,
        validation_executor=executor,
    )

    assert provider.received == [GITHUB_SECRET]
    assert api.submission["findings"][0]["validation"] == {
        "provider": "github",
        "validator_id": "github-token-v1",
        "contract_version": "1",
        "status": "live",
        "reason": "credential_accepted",
    }
    assert GITHUB_SECRET not in json.dumps(api.submission)


def test_coverage_gap_references_cross_the_wire_without_raw_source_identifiers() -> None:
    api = Api()

    run_task(TASK_ID, client=_client(api), pack=PACK)

    coverage = api.submission["coverage"]
    serialized = json.dumps(coverage)
    assert "page-3" not in serialized
    assert coverage["gaps"] == [
        {
            "kind": "record",
            "outcome": "skipped",
            "reason": "unsupported_type",
            "reference": coverage["gaps"][0]["reference"],
        }
    ]
    assert len(coverage["gaps"][0]["reference"]) == 64


def test_a_discovery_task_reports_specs_rather_than_findings() -> None:
    api = Api(_lease(kind="discovery", spec={}))

    run_task(TASK_ID, client=_client(api), pack=PACK)

    submission = api.submission
    assert [spec["params"]["space"] for spec in submission["task_specs"]] == ["DOCS"]
    assert submission["findings"] == []
    assert submission["status"] == "completed"
    assert submission["coverage"] == {
        "version": "1",
        "phase": "discovery",
        "counts": {
            "requested": 0,
            "discovered": 0,
            "scanned": 0,
            "skipped": 0,
            "failed": 0,
        },
        "scope": {"requested": None, "discovered": 1, "gaps": 0},
        "reasons": [],
        "gaps": [],
        "gaps_omitted": 0,
    }


def test_legacy_duplicate_configured_scopes_are_normalized_for_coverage() -> None:
    api = Api(
        _lease(
            kind="discovery",
            spec={},
            connection={"spaces": ["DOCS", "docs"]},
        )
    )

    run_task(TASK_ID, client=_client(api), pack=PACK)

    assert len(api.submission["task_specs"]) == 1
    assert api.submission["coverage"]["scope"] == {
        "requested": 1,
        "discovered": 1,
        "gaps": 0,
    }


def test_duplicate_connector_scopes_fail_with_reconciling_partial_coverage() -> None:
    def duplicate_spaces(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(
            200,
            json={
                "results": [
                    {"id": "s1", "key": "DOCS", "name": "Docs"},
                    {"id": "s1", "key": "DOCS", "name": "Docs repeated"},
                ]
            },
        )

    registry.clear()
    registry.register(
        ConfluenceConnector(
            transport=httpx2.MockTransport(duplicate_spaces),
            sleep=lambda _seconds: None,
            sandbox_factory=None,
        )
    )
    api = Api(
        _lease(
            source_type="confluence",
            kind="discovery",
            spec={},
            connection={"base_url": "https://wiki.test", "spaces": ["DOCS"]},
        )
    )

    run_task(TASK_ID, client=_client(api), pack=PACK)

    assert api.submission["status"] == "failed"
    assert len(api.submission["task_specs"]) == 1
    assert api.submission["coverage"]["scope"] == {
        "requested": None,
        "discovered": 1,
        "gaps": 1,
    }
    assert api.submission["coverage"]["reasons"] == [
        {"outcome": "scope_gap", "reason": "connector_error", "count": 1}
    ]


def test_a_failed_configured_scope_is_reported_without_exposing_its_name() -> None:
    class PartlyDiscoverable(FakeConnector):
        def discover(self, *args: Any, **kwargs: Any) -> Iterator[TaskSpec]:
            yield TaskSpec(
                label="space DOCS",
                params={"space": "DOCS", "space_key": "DOCS"},
            )
            raise ConnectorError("configured space customer-acquisition was not found")

    registry.clear()
    registry.register(PartlyDiscoverable())
    api = Api(
        _lease(
            kind="discovery",
            spec={},
            connection={"spaces": ["DOCS", "customer-acquisition"]},
        )
    )

    run_task(TASK_ID, client=_client(api), pack=PACK)

    coverage = api.submission["coverage"]
    assert coverage["scope"] == {"requested": 2, "discovered": 1, "gaps": 1}
    assert coverage["reasons"] == [
        {"outcome": "scope_gap", "reason": "connector_error", "count": 1}
    ]
    assert "customer-acquisition" not in json.dumps(coverage)


def test_a_failed_discovery_keeps_specs_found_before_the_failure() -> None:
    """Matched spaces remain useful work even when another explicitly requested
    space is missing.  The failed discovery keeps the eventual scan partial."""

    class PartlyDiscoverable(FakeConnector):
        def discover(self, *args: Any, **kwargs: Any) -> Iterator[TaskSpec]:
            yield TaskSpec(label="space DOCS", params={"space": "DOCS"})
            raise ConnectorError("configured space MISSING was not found")

    registry.clear()
    registry.register(PartlyDiscoverable())
    api = Api(_lease(kind="discovery", spec={}))

    report = run_task(TASK_ID, client=_client(api), pack=PACK)

    assert report is not None and report.status == "failed"
    assert api.submission["status"] == "failed"
    assert api.submission["task_specs"] == [{"label": "space DOCS", "params": {"space": "DOCS"}}]
    assert api.submission["counts"]["specs_discovered"] == 1


def test_the_lease_suppressions_are_applied_before_reporting() -> None:
    """Bandwidth saved locally; the API applies them again, authoritatively (#44)."""
    api = Api(
        _lease(
            suppressions=[
                {"id": str(uuid.uuid4()), "scope": "rule", "pattern": "aws-access-key-id"}
            ]
        )
    )

    run_task(TASK_ID, client=_client(api), pack=PACK)

    assert api.submission["findings"] == []
    assert api.submission["counts"]["prefiltered"] == 1


def test_the_lease_threshold_is_what_detection_uses() -> None:
    """One value, set on the API and delivered per task (#70)."""
    api = Api(_lease(confidence_threshold=0.99))

    run_task(TASK_ID, client=_client(api), pack=PACK)

    assert api.submission["findings"] == []
    assert api.submission["counts"]["dropped_below_threshold"] == 1


# ─── Failure paths ────────────────────────────────────────────────────────────


def test_a_refused_lease_reports_nothing_and_drops_the_message() -> None:
    """Already claimed, finished, or cancelled — there is nothing to say."""
    api = Api(lease_status=409)

    report = run_task(TASK_ID, client=_client(api), pack=PACK)

    assert report is None
    assert api.submissions == []


@pytest.mark.parametrize("results_status", [409, 403])
def test_a_results_submission_the_api_refuses_does_not_crash_the_actor(
    results_status: int,
) -> None:
    """The lease can be reclaimed or the task cancelled while the scan runs. The
    API answers 409 ("no longer leased") or 403 ("not leased by this engine"); both
    are routine (ADR 0009 §2) and must not escape run_task as an exception."""
    api = Api(results_status=results_status)

    report = run_task(TASK_ID, client=_client(api), pack=PACK)

    assert report is None  # nothing the API would accept
    assert len(api.submissions) == 1  # it was attempted, once


def test_an_unreachable_api_at_report_time_does_not_crash_the_actor() -> None:
    """Every retry exhausted: the task will be reclaimed and redone, so this is
    logged rather than left to escape the actor frame."""
    api = Api(results_status=503)

    report = run_task(TASK_ID, client=_client(api), pack=PACK)

    assert report is None


def test_an_unsupported_task_kind_fails_the_task_rather_than_mis_running_it() -> None:
    """A kind a newer API introduced must fail cleanly, not be executed as a fetch."""
    api = Api(_lease(kind="reindex"))

    run_task(TASK_ID, client=_client(api), pack=PACK)

    assert api.submission["status"] == "failed"
    assert api.submission["error"] == "ConnectorError: connector_error"


def test_an_unreachable_source_is_reported_as_failed_with_a_reason() -> None:
    """An empty result would read as "no secrets here". The reason reported to the
    API is the exception type, never its message — a library's message may quote
    the content it choked on, which could be a secret (ADR 0004)."""
    registry.clear()
    registry.register(FakeConnector(discovery_fails=True))
    api = Api(_lease(kind="discovery", spec={}))

    report = run_task(TASK_ID, client=_client(api), pack=PACK)

    assert report is not None and report.status == "failed"
    assert api.submission["status"] == "failed"
    # A builtin ConnectionError is unanticipated (not a ConnectorError), so only its
    # type is transmitted — enough to diagnose, nothing that could carry content.
    assert api.submission["error"] == "ConnectionError"
    assert "unreachable" not in api.submission["error"]


def test_a_rejected_credential_is_reported_as_failed() -> None:
    registry.clear()
    registry.register(FakeConnector(spaces={"DOCS": []}, expected_credential="the-real-token"))
    api = Api(_lease(credential="the-wrong-token"))

    run_task(TASK_ID, client=_client(api), pack=PACK)

    assert api.submission["status"] == "failed"
    assert api.submission["error"] == "CredentialError: permission_denied"
    assert api.submission["coverage"]["reasons"] == [
        {"outcome": "scope_gap", "reason": "permission_denied", "count": 1}
    ]


def test_rate_limit_exhaustion_is_a_stable_task_coverage_reason() -> None:
    canary = "sensitive-resource-name-AKIAIOSFODNN7EXAMPLE"

    class Throttled(FakeConnector):
        def fetch(self, *args: Any, **kwargs: Any) -> Iterator[Any]:
            raise RateLimitError(canary)

    registry.clear()
    registry.register(Throttled())
    api = Api()

    with capture_logs() as events:
        run_task(TASK_ID, client=_client(api), pack=PACK)

    coverage = api.submission["coverage"]
    assert api.submission["status"] == "failed"
    assert api.submission["error"] == "RateLimitError: rate_limited"
    assert canary not in json.dumps(api.submission)
    assert canary not in json.dumps(events)
    assert coverage["counts"] == {
        "requested": 0,
        "discovered": 0,
        "scanned": 0,
        "skipped": 0,
        "failed": 0,
    }
    assert coverage["scope"]["gaps"] == 1
    assert coverage["reasons"] == [{"outcome": "scope_gap", "reason": "rate_limited", "count": 1}]


def test_a_source_type_this_engine_cannot_scan_fails_the_task() -> None:
    """A mixed fleet, or a source for a connector that has not shipped."""
    api = Api(_lease(source_type="confluence"))

    run_task(TASK_ID, client=_client(api), pack=PACK)

    assert api.submission["status"] == "failed"
    assert api.submission["error"] == "UnknownConnectorError: connector_error"


def test_a_lease_without_a_pepper_fails_rather_than_scanning() -> None:
    """Fingerprints computed unpeppered match nothing stored, so every finding
    would ingest as new and reconciliation would auto-resolve the real ones —
    losing triage state no scan can rebuild (ADR 0006/0007)."""
    api = Api(_lease(fingerprint_pepper=None))

    run_task(TASK_ID, client=_client(api), pack=PACK)

    assert api.submission["status"] == "failed"
    assert api.submission["error"] == "ConnectorError: connector_error"
    assert api.submission["findings"] == []


def test_an_unreadable_pepper_fails_the_same_way() -> None:
    api = Api(_lease(fingerprint_pepper="not base64!!"))

    run_task(TASK_ID, client=_client(api), pack=PACK)

    assert api.submission["status"] == "failed"


def test_an_unexpected_bug_is_still_reported() -> None:
    """An unreported task is one the API can only settle by waiting out the lease."""

    class Exploding(FakeConnector):
        def fetch(self, *args: Any, **kwargs: Any) -> Iterator[Any]:
            raise RuntimeError("something nobody anticipated")

    registry.clear()
    registry.register(Exploding())
    api = Api()

    report = run_task(TASK_ID, client=_client(api), pack=PACK)

    assert report is not None and report.status == "failed"
    # Only the exception type crosses the wire: the message could quote whatever the
    # buggy code was handling, up to and including a secret (ADR 0004).
    assert api.submission["error"] == "RuntimeError"
    assert "something nobody anticipated" not in api.submission["error"]


def test_unreadable_requested_content_fails_closed_without_dropping_findings() -> None:
    """A partial result may be useful, but it is never proof that missing secrets
    were remediated.  The failed task keeps findings from readable units while its
    scan status prevents reconciliation and notifications (ADR 0009 §4)."""
    registry.clear()
    registry.register(
        FakeConnector(
            spaces={"DOCS": [FakePage("page-1", LEAKY), FakePage("page-2", "", unreadable=True)]}
        )
    )
    api = Api()

    run_task(TASK_ID, client=_client(api), pack=PACK)

    assert api.submission["status"] == "failed"
    assert api.submission["error"] == "1 requested content unit could not be read"
    assert api.submission["counts"]["units_failed"] == 1
    assert len(api.submission["findings"]) == 1


def test_detection_truncation_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    """A detector cap keeps work bounded, but content past the cap remains unread
    and therefore cannot justify reconciliation."""
    from iceberg_detect import DetectionResult

    monkeypatch.setattr(
        "iceberg_engine.runner.detect",
        lambda *_args, **_kwargs: DetectionResult(truncated=True),
    )
    api = Api()

    report = run_task(TASK_ID, client=_client(api), pack=PACK)

    assert report is not None and report.status == "failed"
    assert api.submission["counts"]["units_truncated"] == 2
    assert api.submission["status"] == "failed"
    assert api.submission["error"] == "2 requested content units were truncated"
    coverage = api.submission["coverage"]
    assert coverage["counts"] == {
        "requested": 3,
        "discovered": 3,
        "scanned": 0,
        "skipped": 1,
        "failed": 2,
    }
    assert coverage["reasons"] == [
        {"outcome": "failed", "reason": "output_limit", "count": 2},
        {"outcome": "skipped", "reason": "unsupported_type", "count": 1},
    ]


def test_a_cancelled_task_is_abandoned_without_reporting() -> None:
    """The API already moved the task to `cancelled` and is not waiting for
    anything; submitting would be answered with a 409 (ADR 0009 §4)."""
    from iceberg_engine.heartbeat import TaskRegistry

    tasks = TaskRegistry()
    api = Api()

    with tasks.holding(TASK_ID):
        tasks.note_cancelled([TASK_ID])
        report = run_task(TASK_ID, client=_client(api), pack=PACK, tasks=tasks)

    assert report is None
    assert api.submissions == []


def test_cancellation_stops_provider_validation_after_a_collected_candidate(
    source: FakeConnector,
) -> None:
    """Once cancellation is observed, previously detected plaintext is not sent."""
    from contextlib import nullcontext

    source.spaces["DOCS"] = [
        FakePage("page-1", GITHUB_SECRET),
        FakePage("page-2", "ordinary text"),
    ]
    api = Api(
        _lease(
            validation_policies=[
                {
                    "policy_id": "55555555-5555-5555-5555-555555555555",
                    "rule_id": "github-fine-grained-pat",
                    "validator_id": "github-token-v1",
                    "timeout_seconds": 1,
                    "requests_per_minute": 10,
                    "max_attempts_per_task": 1,
                }
            ]
        )
    )

    class Provider:
        validator_id = "github-token-v1"
        provider = "github"
        contract_version = "1"
        supported_rule_ids = frozenset({"github-fine-grained-pat"})

        def __init__(self) -> None:
            self.calls = 0

        def validate(
            self, credential: OpaqueCredential, *, timeout_seconds: float
        ) -> ValidationOutcome:
            self.calls += 1
            raise AssertionError("provider must not be called after cancellation")

    class CancellingRegistry:
        def __init__(self) -> None:
            self.checks = 0

        def holding(self, _task_id: object) -> object:
            return nullcontext()

        def is_cancelled(self, _task_id: object) -> bool:
            self.checks += 1
            return self.checks == 2

    provider = Provider()
    executor = ValidationExecutor.from_payloads(
        api.lease_body["validation_policies"],
        validators={provider.validator_id: provider},
    )

    report = run_task(
        TASK_ID,
        client=_client(api),
        pack=PACK,
        tasks=CancellingRegistry(),  # type: ignore[arg-type]
        validation_executor=executor,
    )

    assert report is None
    assert provider.calls == 0
    assert api.submissions == []


def test_an_uncancelled_task_reports_normally_with_a_registry() -> None:
    """The registry must not change the happy path — it only adds a way to stop."""
    from iceberg_engine.heartbeat import TaskRegistry

    tasks = TaskRegistry()
    api = Api()

    report = run_task(TASK_ID, client=_client(api), pack=PACK, tasks=tasks)

    assert report is not None and report.status == "completed"
    assert len(api.submission["findings"]) == 1


def test_findings_from_before_a_mid_fetch_failure_are_still_reported() -> None:
    """A source that gives out halfway — a pagination cap, retries exhausted
    against a blipping Confluence — used to take every unit before it down with
    it. `complete_task(FAILED)` is terminal, so a secret found on page one would
    surface only if an operator re-ran the whole scan (#115)."""

    class GivingUp(FakeConnector):
        def fetch(self, *args: Any, **kwargs: Any) -> Iterator[Any]:
            yield from super().fetch(*args, **kwargs)
            raise ConnectorError("pagination cap reached")

    registry.clear()
    registry.register(GivingUp(spaces={"DOCS": [FakePage("page-1", LEAKY)]}))
    api = Api()

    report = run_task(TASK_ID, client=_client(api), pack=PACK)

    assert report is not None and report.status == "failed"
    assert [f["rule_id"] for f in api.submission["findings"]] == ["aws-access-key-id"]
    assert api.submission["counts"]["units"] == 1


def test_an_interrupted_task_reports_what_it_had_before_it_dies() -> None:
    """Dramatiq's time limit raises a `BaseException`, so neither the connector nor
    the catch-all handler sees it and the task would end without reporting — the
    API waits out the lease and redelivers a task that dies at the same point every
    time (#106). The interrupt still kills the thread; it just says so first."""

    class OutOfTime(FakeConnector):
        def fetch(self, *args: Any, **kwargs: Any) -> Iterator[Any]:
            yield from super().fetch(*args, **kwargs)
            raise TimeLimitExceeded

    registry.clear()
    registry.register(OutOfTime(spaces={"DOCS": [FakePage("page-1", LEAKY)]}))
    api = Api()

    with pytest.raises(TimeLimitExceeded):
        run_task(TASK_ID, client=_client(api), pack=PACK)

    assert api.submission["status"] == "failed"
    assert api.submission["error"] == "TimeLimitExceeded"
    assert len(api.submission["findings"]) == 1


def test_a_token_rejected_at_report_time_is_a_warning_not_a_routine_lease_loss() -> None:
    """A 403 says the lease moved on, which is routine. A 401 says this engine's
    token was rotated out from under a task that ran for minutes — re-registering
    an engine does exactly that — and every in-flight result is being discarded. An
    engine with no id has no heartbeat to fail either, so this is the only place an
    operator can see it (#131)."""
    api = Api(results_status=401)

    with capture_logs() as events:
        report = run_task(TASK_ID, client=_client(api), pack=PACK)

    assert report is None
    rejected = [event for event in events if event["event"] == "scan_task_token_rejected"]
    assert [event["log_level"] for event in rejected] == ["warning"]


# ─── The engine's own metrics ─────────────────────────────────────────────────


def _counter(name: str, **labels: str) -> float:
    """A counter's current value, or zero before its first observation."""
    return REGISTRY.get_sample_value(name, labels) or 0.0


def test_a_reported_task_moves_the_engines_own_counters() -> None:
    """An engine's metrics endpoint serves the API's series too, and those sit at
    zero there however busy the engine is — a dashboard keyed to them reads a
    healthy engine as a dead one (#132)."""
    before = _counter("iceberg_engine_tasks_run_total", kind="fetch", outcome="completed")
    findings_before = _counter("iceberg_engine_findings_reported_total")
    api = Api()

    run_task(TASK_ID, client=_client(api), pack=PACK)

    assert _counter("iceberg_engine_tasks_run_total", kind="fetch", outcome="completed") == (
        before + 1
    )
    assert _counter("iceberg_engine_findings_reported_total") == findings_before + 1


def test_a_source_failure_is_counted_apart_from_an_engine_one() -> None:
    """Which of the two is failing a scan is the first question an operator asks."""
    before = _counter("iceberg_engine_connector_failures_total", source_type="fake")
    api = Api(_lease(kind="reindex"))

    run_task(TASK_ID, client=_client(api), pack=PACK)

    assert _counter("iceberg_engine_connector_failures_total", source_type="fake") == before + 1


def test_a_running_task_is_registered_so_the_heartbeat_can_renew_it() -> None:
    """Without this the heartbeat names no tasks and every lease lapses."""
    from iceberg_engine.heartbeat import TaskRegistry

    tasks = TaskRegistry()
    seen: list[list[Any]] = []

    class Observing(FakeConnector):
        def fetch(self, *args: Any, **kwargs: Any) -> Iterator[Any]:
            seen.append(tasks.held())
            yield from super().fetch(*args, **kwargs)

    registry.clear()
    registry.register(Observing(spaces={"DOCS": [FakePage("page-1", LEAKY)]}))

    run_task(TASK_ID, client=_client(Api()), pack=PACK, tasks=tasks)

    assert seen == [[TASK_ID]]
    assert tasks.held() == []  # ...and released once done


# ─── Connector-declared scope naming (#144) ───────────────────────────────────


def test_several_specs_for_one_scope_count_as_one_discovered_scope() -> None:
    """A connector may split one scope into many fetch specs.

    Jira windows a project by `created`, so three specs can cover one project.
    Counting each as a discovered scope would make discovered exceed requested, and
    the API nulls the whole manifest's `scope.requested` when the equation does not
    balance — silently losing "you asked for one project and we enumerated it".
    """

    class Windowed(FakeConnector):
        scope_key = "projects"
        scope_param = "project_key"

        def discover(self, *args: Any, **kwargs: Any) -> Iterator[TaskSpec]:
            for window in range(3):
                yield TaskSpec(
                    label=f"ENG window {window}",
                    params={"project_key": "ENG", "window": window},
                )

    registry.clear()
    registry.register(Windowed())
    api = Api(_lease(kind="discovery", spec={}, connection={"projects": ["ENG"]}))

    run_task(TASK_ID, client=_client(api), pack=PACK)

    assert len(api.submission["task_specs"]) == 3
    assert api.submission["coverage"]["scope"] == {"requested": 1, "discovered": 1, "gaps": 0}


def test_a_missing_configured_scope_is_found_under_the_connectors_own_param() -> None:
    """The gap attribution has to read the same key the connector writes."""

    class Windowed(FakeConnector):
        scope_key = "projects"
        scope_param = "project_key"

        def discover(self, *args: Any, **kwargs: Any) -> Iterator[TaskSpec]:
            yield TaskSpec(label="ENG", params={"project_key": "ENG"})
            raise ConnectorError("configured Jira projects were not found")

    registry.clear()
    registry.register(Windowed())
    api = Api(_lease(kind="discovery", spec={}, connection={"projects": ["ENG", "OPS"]}))

    run_task(TASK_ID, client=_client(api), pack=PACK)

    coverage = api.submission["coverage"]
    assert coverage["scope"] == {"requested": 2, "discovered": 1, "gaps": 1}
    assert "OPS" not in json.dumps(api.submission)


def test_a_connector_that_names_no_scope_keys_keeps_the_confluence_defaults() -> None:
    """Every connector predating #144 meant "spaces"/"space_key"."""
    api = Api(_lease(kind="discovery", spec={}, connection={"spaces": ["DOCS"]}))

    run_task(TASK_ID, client=_client(api), pack=PACK)

    assert api.submission["coverage"]["scope"] == {"requested": 1, "discovered": 1, "gaps": 0}


def test_a_body_units_coverage_kind_is_the_connectors_word() -> None:
    """The kind is domain-separated into a gap's HMAC.

    A Jira issue the connector counted as `record` but the runner marked incomplete
    as `page` still reconciles numerically, while growing a phantom `page` gap on a
    source that has no pages.
    """
    from iceberg_connectors.units import ContentOrigin, ContentUnit
    from iceberg_core.enums import CoverageObjectKind
    from iceberg_core.fingerprint import CoarseLocator
    from iceberg_engine.runner import _coverage_kind

    unit = ContentUnit(
        locator=CoarseLocator(connector_type="jira", resource_id="10001"),
        text="x",
        origin=ContentOrigin.BODY,
    )

    class Recorded(FakeConnector):
        body_kind = CoverageObjectKind.RECORD

    assert _coverage_kind(unit, Recorded()) is CoverageObjectKind.RECORD
    assert _coverage_kind(unit, FakeConnector()) is CoverageObjectKind.PAGE
    assert _coverage_kind(unit, None) is CoverageObjectKind.PAGE
