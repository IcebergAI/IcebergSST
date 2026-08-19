"""Flushing findings and resume points mid-fetch (#143).

The runner's half of batched submission. What matters is not that batches happen
but *where they are cut*: a batch must carry exactly the findings the checkpoint it
ships with covers. Cut it one unit early and a resumed attempt re-reports; cut it
one unit late and a resumed attempt skips a secret.

`fetch` is a generator, so the two ledgers move at different times — coverage for a
unit is recorded before it is yielded, its checkpoint only after. Most of these
tests exist to pin that the runner reconciles them rather than assuming they agree.
"""

import base64
import json
import uuid
from collections.abc import Iterator
from typing import Any

import httpx2
import pytest
from dramatiq.middleware import TimeLimitExceeded
from iceberg_connectors import FakeConnector, FakePage, RateLimitError, registry
from iceberg_detect import load_named_pack
from iceberg_engine import runner
from iceberg_engine.api_client import EngineClient
from iceberg_engine.runner import run_task

PACK = load_named_pack()
PEPPER = b"0123456789abcdef0123456789abcdef"
TASK_ID = uuid.UUID("11111111-1111-1111-1111-111111111111")
LEAKY = "Deployment notes: set aws access key AKIAIOSFODNN7EXAMPLE in the runbook."


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
    """Records batches and the terminal submission separately."""

    def __init__(self, lease: dict[str, Any] | None = None, *, progress_status: int = 200) -> None:
        self.lease_body = lease if lease is not None else _lease()
        self.progress_status = progress_status
        self.batches: list[dict[str, Any]] = []
        self.submissions: list[dict[str, Any]] = []

    def __call__(self, request: httpx2.Request) -> httpx2.Response:
        if request.url.path.endswith("/lease"):
            return httpx2.Response(200, json=self.lease_body)
        body = json.loads(request.content)
        if request.url.path.endswith("/progress"):
            self.batches.append(body)
            if self.progress_status != 200:
                return httpx2.Response(self.progress_status)
            return httpx2.Response(
                200, json={"task_id": str(TASK_ID), "sequence": body["sequence"]}
            )
        self.submissions.append(body)
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


@pytest.fixture(autouse=True)
def _clean_registry() -> Any:
    registry.clear()
    yield
    registry.clear()


@pytest.fixture(autouse=True)
def _flush_every_unit(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make every boundary due, so a three-page fixture exercises real batching.

    The shipped thresholds are 500 findings or 30 seconds — deliberately coarse,
    because a batch costs a round trip. Driving them from a fixture would mean
    either a huge fixture or a fake clock, and neither would test anything the
    threshold constant does not already say.
    """
    monkeypatch.setattr(runner, "CHECKPOINT_BATCH_FINDINGS", 1)


def _pages(count: int) -> list[FakePage]:
    return [FakePage(f"page-{n}", LEAKY, revision=n + 1) for n in range(count)]


def _register(**kwargs: Any) -> FakeConnector:
    connector = FakeConnector(spaces={"DOCS": _pages(kwargs.pop("pages", 3))}, **kwargs)
    registry.register(connector, replace=True)
    return connector


# ─── Batching only engages for a connector that can resume ────────────────────


def test_a_connector_without_checkpoints_still_makes_exactly_one_submission() -> None:
    """The compatibility gate. Flushing for a connector that ignores checkpoints
    would leave the API holding a position the next attempt never honours, so it
    would re-read from the top and re-report everything the batch delivered."""
    _register(pages=3)
    api = Api()

    report = run_task(TASK_ID, client=_client(api), pack=PACK)

    assert api.batches == []
    assert report is not None
    assert api.submission["checkpoint_sequence"] == 0


def test_a_resumable_connector_flushes_as_it_goes() -> None:
    _register(pages=3, resumable=True)
    api = Api()

    run_task(TASK_ID, client=_client(api), pack=PACK)

    assert [batch["sequence"] for batch in api.batches] == [1, 2]
    assert api.submission["checkpoint_sequence"] == 2


# ─── Where the cut lands ──────────────────────────────────────────────────────


def test_a_batch_carries_the_findings_its_checkpoint_covers_and_no_more() -> None:
    """The property the whole mechanism rests on.

    Batch N ships the checkpoint published after page N-1, so it must carry the
    findings of pages 0..N-1 — no more, or a resumed attempt would skip one; no
    fewer, or it would re-report one.
    """
    _register(pages=3, resumable=True)
    api = Api()

    run_task(TASK_ID, client=_client(api), pack=PACK)

    first, second = api.batches
    assert first["checkpoint"]["position"] == {"after": "page-0"}
    assert len(first["findings"]) == 1
    assert second["checkpoint"]["position"] == {"after": "page-1"}
    assert len(second["findings"]) == 1


def test_coverage_is_split_across_batches_and_the_remainder_totals_the_task() -> None:
    """Every page counted exactly once across the batches plus the final body."""
    _register(pages=3, resumable=True)
    api = Api()

    run_task(TASK_ID, client=_client(api), pack=PACK)

    scanned = [batch["coverage"]["counts"]["scanned"] for batch in api.batches]
    scanned.append(api.submission["coverage"]["counts"]["scanned"])
    assert scanned == [1, 1, 1]


def test_the_final_submission_reports_only_what_the_batches_did_not() -> None:
    _register(pages=3, resumable=True)
    api = Api()

    run_task(TASK_ID, client=_client(api), pack=PACK)

    assert len(api.submission["findings"]) == 1
    assert api.submission["counts"]["units"] == 1


def test_every_finding_is_reported_exactly_once_across_the_whole_task() -> None:
    _register(pages=3, resumable=True)
    api = Api()

    run_task(TASK_ID, client=_client(api), pack=PACK)

    reported = [
        finding["resource_locator"]["resource_id"]
        for message in (*api.batches, api.submission)
        for finding in message["findings"]
    ]
    assert sorted(reported) == ["page-0", "page-1", "page-2"]


# ─── Failure of a batch must not lose work ────────────────────────────────────


def test_a_refused_batch_leaves_its_findings_for_the_final_submission() -> None:
    """Losing a batch costs a re-read after a reclaim. Dropping the findings would
    cost the findings."""
    _register(pages=3, resumable=True)
    api = Api(progress_status=500)

    report = run_task(TASK_ID, client=_client(api), pack=PACK)

    assert report is not None
    assert len(api.submission["findings"]) == 3
    assert api.submission["checkpoint_sequence"] == 0


def test_a_refused_batch_does_not_raise_out_of_the_task() -> None:
    _register(pages=3, resumable=True)
    api = Api(progress_status=503)

    assert run_task(TASK_ID, client=_client(api), pack=PACK) is not None


# ─── A task-wide failure is reported by both kinds of connector ───────────────


class _Throttled(FakeConnector):
    """Gives out after the units it could read — a real pagination cap, a source
    that stops answering. The units before it are still reported; what the task
    never got to is a blind spot the manifest has to show."""

    def fetch(self, *args: Any, **kwargs: Any) -> Iterator[Any]:
        yield from super().fetch(*args, **kwargs)
        raise RateLimitError("retries exhausted against space DOCS")


def _throttled(*, resumable: bool) -> Api:
    registry.register(
        _Throttled(spaces={"DOCS": _pages(3)}, resumable=resumable),
        replace=True,
    )
    api = Api()
    run_task(TASK_ID, client=_client(api), pack=PACK)
    return api


def test_a_task_wide_gap_reaches_the_api_after_the_batches_that_went_before_it() -> None:
    """The remainder is a delta, and a scope gap has to travel in one (#193).

    The gap says "this task did not read everything it was asked to", which is
    what stops the manifest reporting a known scope size the scan never
    established. It is recorded after the fetch ends, so a design that froze the
    remainder while the fetch was unwinding dropped it — silently, and only for
    connectors that batch."""
    api = _throttled(resumable=True)
    coverage = api.submission["coverage"]

    assert api.batches, "fixture must actually batch for this to test anything"
    assert api.submission["status"] == "failed"
    assert coverage["scope"]["gaps"] == 1
    assert coverage["reasons"] == [{"outcome": "scope_gap", "reason": "rate_limited", "count": 1}]
    assert [gap["reason"] for gap in coverage["gaps"]] == ["rate_limited"]
    # Still a delta: the pages the batches carried are not counted a second time.
    assert coverage["counts"]["scanned"] == 1


def test_a_failing_task_reports_the_same_gap_whether_or_not_it_batched() -> None:
    """Two connectors, one failure, one story. Whether a source can resume is a
    performance property of the source; it must not change what the scan says it
    read. The counts legitimately differ — one submission is a remainder — but the
    blind spot is the whole task's either way, down to the reference operators
    correlate on."""
    plain = _throttled(resumable=False).submission["coverage"]
    batched = _throttled(resumable=True).submission["coverage"]

    assert plain["scope"]["gaps"] == batched["scope"]["gaps"]
    assert plain["reasons"] == batched["reasons"]
    assert plain["gaps"] == batched["gaps"]


def test_an_interrupted_batching_task_still_reports_where_it_ran_out_of_time() -> None:
    """The time limit is a `BaseException`, submitted from its own handler — the
    other path onto the same seam, and the one where a blind spot matters most: a
    task killed mid-source has read some unknowable fraction of it."""

    class _OutOfTime(FakeConnector):
        def fetch(self, *args: Any, **kwargs: Any) -> Iterator[Any]:
            yield from super().fetch(*args, **kwargs)
            raise TimeLimitExceeded

    registry.register(_OutOfTime(spaces={"DOCS": _pages(3)}, resumable=True), replace=True)
    api = Api()

    with pytest.raises(TimeLimitExceeded):
        run_task(TASK_ID, client=_client(api), pack=PACK)

    coverage = api.submission["coverage"]
    assert api.batches
    assert coverage["scope"]["gaps"] == 1
    assert coverage["reasons"] == [{"outcome": "scope_gap", "reason": "timeout", "count": 1}]


# ─── Resuming ─────────────────────────────────────────────────────────────────


def test_a_lease_carrying_a_position_resumes_there() -> None:
    _register(pages=4, resumable=True)
    api = Api(
        _lease(
            checkpoint={"version": "1", "position": {"after": "page-1"}},
            checkpoint_sequence=2,
        )
    )

    run_task(TASK_ID, client=_client(api), pack=PACK)

    reported = [
        finding["resource_locator"]["resource_id"]
        for message in (*api.batches, api.submission)
        for finding in message["findings"]
    ]
    assert sorted(reported) == ["page-2", "page-3"]


def test_a_resumed_task_continues_the_batch_sequence_rather_than_restarting_it() -> None:
    """Restarting it would let a replayed batch from the previous attempt through."""
    _register(pages=4, resumable=True)
    api = Api(
        _lease(
            checkpoint={"version": "1", "position": {"after": "page-1"}},
            checkpoint_sequence=2,
        )
    )

    run_task(TASK_ID, client=_client(api), pack=PACK)

    assert [batch["sequence"] for batch in api.batches] == [3]
    assert api.submission["checkpoint_sequence"] == 3


def test_a_resumed_task_does_not_recount_coverage_an_earlier_attempt_reported() -> None:
    _register(pages=4, resumable=True)
    api = Api(
        _lease(
            checkpoint={"version": "1", "position": {"after": "page-1"}},
            checkpoint_sequence=2,
        )
    )

    run_task(TASK_ID, client=_client(api), pack=PACK)

    total = sum(batch["coverage"]["counts"]["scanned"] for batch in api.batches)
    total += api.submission["coverage"]["counts"]["scanned"]
    assert total == 2


def test_an_empty_checkpoint_on_the_lease_starts_from_the_top() -> None:
    """What the API sends when it judged a stored position no longer valid."""
    _register(pages=3, resumable=True)
    api = Api(_lease(checkpoint={}, checkpoint_sequence=2))

    run_task(TASK_ID, client=_client(api), pack=PACK)

    reported = [
        finding["resource_locator"]["resource_id"]
        for message in (*api.batches, api.submission)
        for finding in message["findings"]
    ]
    assert sorted(reported) == ["page-0", "page-1", "page-2"]


# ─── Nothing sensitive rides along ────────────────────────────────────────────


def test_no_plaintext_reaches_the_api_in_a_batch() -> None:
    _register(pages=3, resumable=True)
    api = Api()

    run_task(TASK_ID, client=_client(api), pack=PACK)

    assert "AKIAIOSFODNN7EXAMPLE" not in json.dumps(api.batches)


def test_a_cursor_proposal_rides_on_the_terminal_submission_only() -> None:
    """A cursor claims a scope is fully read, which a batch can never establish."""
    _register(pages=3, resumable=True, incremental=True)
    api = Api()

    run_task(TASK_ID, client=_client(api), pack=PACK)

    assert all("cursor" not in batch for batch in api.batches)
    assert api.submission["cursor"] == {
        "scope": "DOCS",
        "version": "1",
        "position": {"revision": 3},
    }


# ─── A lost response must not strand findings (review #160) ───────────────────


class LosesOneResponse(Api):
    """Commits a batch, then loses every response to it until the client gives up.

    The API has the batch. The engine does not know that, and — crucially — its own
    transport retries are exhausted, so recovery is the *engine's* problem rather
    than the client's. That is the only path on which the batcher has to decide
    what a later replay answer means, and a fixture that drops one response is
    quietly resolved by `EngineClient`'s four attempts without ever reaching it.
    """

    def __init__(self, lease: dict[str, Any] | None = None) -> None:
        super().__init__(lease)
        #: One more than the client's own attempt budget, so its retries run out.
        self.drop_first = 4
        self.dropped = 0
        self.sequence = 0
        #: Every progress request, accepted or not — what the engine actually put
        #: on the wire, which is the thing under test.
        self.attempts: list[dict[str, Any]] = []

    def __call__(self, request: httpx2.Request) -> httpx2.Response:
        if request.url.path.endswith("/lease"):
            return httpx2.Response(200, json=self.lease_body)
        body = json.loads(request.content)
        if request.url.path.endswith("/progress"):
            self.attempts.append(body)
            if body["sequence"] == self.sequence + 1:
                self.sequence = body["sequence"]
                self.batches.append(body)
            if self.dropped < self.drop_first:
                # Committed, then the response never arrives — repeatedly.
                self.dropped += 1
                return httpx2.Response(503)
            return httpx2.Response(200, json={"task_id": str(TASK_ID), "sequence": self.sequence})
        self.submissions.append(body)
        return httpx2.Response(200, json={"task_id": str(TASK_ID)})


def _retry_immediately(monkeypatch: pytest.MonkeyPatch) -> None:
    """Arm the next flush the moment one fails, so the retry happens in-test.

    In production a failed batch waits out the 30-second interval before it is
    retried; a test that waited would be a test of `sleep`.
    """
    monkeypatch.setattr(runner, "CHECKPOINT_BATCH_SECONDS", 0.0)


def test_a_lost_batch_response_does_not_strand_the_findings_after_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The blocker from the #160 review.

    A sequence number is bound to the payload it was first sent with. If the
    engine retried that number with a *larger* payload, the API would answer
    "replay" — it already holds the smaller one — and taking that as
    acknowledgement would advance the sent ledger past findings the API never
    received. The terminal submission then omits them: silent data loss.
    """
    _retry_immediately(monkeypatch)
    _register(pages=4, resumable=True)
    api = LosesOneResponse()

    run_task(TASK_ID, client=_client(api), pack=PACK)

    reported = [
        finding["resource_locator"]["resource_id"]
        for message in (*api.batches, api.submission)
        for finding in message["findings"]
    ]
    assert sorted(set(reported)) == ["page-0", "page-1", "page-2", "page-3"]


def test_a_retried_batch_is_the_same_payload_under_the_same_sequence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """What makes acting on a replay answer safe.

    The engine keeps going while the response is outstanding, so by the time it
    retries it has more findings to hand. It must still send the original bytes:
    a bigger payload wearing an already-accepted number is answered as a replay of
    the smaller one, and there is no way to tell those apart from the response.
    """
    _retry_immediately(monkeypatch)
    _register(pages=4, resumable=True)
    api = LosesOneResponse()

    run_task(TASK_ID, client=_client(api), pack=PACK)

    at_one = [attempt for attempt in api.attempts if attempt["sequence"] == 1]
    assert len(at_one) > 1, "the fixture did not exercise a retry"
    assert all(attempt == at_one[0] for attempt in at_one)


# ─── Discovery is narrowed when the API says so (review #160) ─────────────────


def _discovery_lease(**overrides: Any) -> dict[str, Any]:
    return _lease(kind="discovery", spec={}, **overrides)


def test_an_incremental_lease_narrows_discovery_with_its_cursors() -> None:
    """The API committing cursors is worth nothing until they reach `discover`."""
    connector = FakeConnector(spaces={"DOCS": _pages(2), "OPS": _pages(2)}, incremental=True)
    registry.register(connector, replace=True)
    api = Api(
        _discovery_lease(mode="incremental", cursors={"DOCS": {"revision": 99}}),
    )

    run_task(TASK_ID, client=_client(api), pack=PACK)

    scopes = [spec["params"]["space"] for spec in api.submission["task_specs"]]
    assert scopes == ["OPS"]


def test_a_full_lease_withholds_cursors_even_when_the_source_has_them() -> None:
    """A connector handed positions during a full scan could narrow without the
    control plane intending it — and that scan *does* auto-resolve."""
    connector = FakeConnector(spaces={"DOCS": _pages(2), "OPS": _pages(2)}, incremental=True)
    registry.register(connector, replace=True)
    api = Api(_discovery_lease(mode="full", cursors={"DOCS": {"revision": 99}}))

    run_task(TASK_ID, client=_client(api), pack=PACK)

    scopes = [spec["params"]["space"] for spec in api.submission["task_specs"]]
    assert scopes == ["DOCS", "OPS"]


def test_a_connector_without_the_capability_is_never_handed_cursors() -> None:
    """It would raise on the keyword; SDK 1.0 connectors must keep working."""
    registry.register(FakeConnector(spaces={"DOCS": _pages(2)}), replace=True)
    api = Api(_discovery_lease(mode="incremental", cursors={"DOCS": {"revision": 99}}))

    report = run_task(TASK_ID, client=_client(api), pack=PACK)

    assert report is not None
    assert report.status == "completed"
