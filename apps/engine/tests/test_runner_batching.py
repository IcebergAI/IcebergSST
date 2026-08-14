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
from typing import Any

import httpx2
import pytest
from iceberg_connectors import FakeConnector, FakePage, registry
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
