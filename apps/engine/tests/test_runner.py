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
from iceberg_connectors import ConnectorError, FakeConnector, FakePage, registry
from iceberg_detect import load_named_pack
from iceberg_engine.api_client import EngineClient
from iceberg_engine.runner import run_task
from prometheus_client import REGISTRY
from structlog.testing import capture_logs

PACK = load_named_pack()
PEPPER = b"0123456789abcdef0123456789abcdef"
TASK_ID = uuid.UUID("11111111-1111-1111-1111-111111111111")

#: AWS's own documented example key — it has never authenticated anything.
LEAKY = "Deployment notes: set aws access key AKIAIOSFODNN7EXAMPLE in the runbook."
CLEAN = "The fix landed in commit 3f2b1c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b on main."


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


def test_no_plaintext_reaches_the_api() -> None:
    """ADR 0004, asserted against the bytes actually sent."""
    api = Api()

    run_task(TASK_ID, client=_client(api), pack=PACK)

    assert "AKIAIOSFODNN7EXAMPLE" not in json.dumps(api.submission)


def test_a_discovery_task_reports_specs_rather_than_findings() -> None:
    api = Api(_lease(kind="discovery", spec={}))

    run_task(TASK_ID, client=_client(api), pack=PACK)

    submission = api.submission
    assert [spec["params"]["space"] for spec in submission["task_specs"]] == ["DOCS"]
    assert submission["findings"] == []
    assert submission["status"] == "completed"


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
    assert "unsupported task kind" in api.submission["error"]


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
    assert "CredentialError" in api.submission["error"]


def test_a_source_type_this_engine_cannot_scan_fails_the_task() -> None:
    """A mixed fleet, or a source for a connector that has not shipped."""
    api = Api(_lease(source_type="confluence"))

    run_task(TASK_ID, client=_client(api), pack=PACK)

    assert api.submission["status"] == "failed"
    assert "no connector for source type" in api.submission["error"]


def test_a_lease_without_a_pepper_fails_rather_than_scanning() -> None:
    """Fingerprints computed unpeppered match nothing stored, so every finding
    would ingest as new and reconciliation would auto-resolve the real ones —
    losing triage state no scan can rebuild (ADR 0006/0007)."""
    api = Api(_lease(fingerprint_pepper=None))

    run_task(TASK_ID, client=_client(api), pack=PACK)

    assert api.submission["status"] == "failed"
    assert "pepper" in api.submission["error"]
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


def test_a_page_the_source_could_not_read_is_counted_not_fatal() -> None:
    """One bad page must not fail a scan of fifty thousand."""
    registry.clear()
    registry.register(
        FakeConnector(
            spaces={"DOCS": [FakePage("page-1", LEAKY), FakePage("page-2", "", unreadable=True)]}
        )
    )
    api = Api()

    run_task(TASK_ID, client=_client(api), pack=PACK)

    assert api.submission["status"] == "completed"
    assert api.submission["counts"]["units_failed"] == 1
    assert len(api.submission["findings"]) == 1


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
