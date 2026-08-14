"""Resume and re-scan end to end, with faults injected (#143).

The issue's own validation asks for fault injection around checkpoints, duplicate
pages, expired cursors, content deletion and engine restarts, compared against a
clean full scan. That comparison is the point: a resumed run and an uninterrupted
one must produce the *same finding set*, or resume is a way to lose secrets.

Everything is real except the two ends. Jira is the in-process fixture site and the
control plane is a scripted transport; between them the actual connector, rule pack
and `run_task` do the work. Lives in the root suite because it spans
`iceberg_connectors`, `iceberg_detect` and `iceberg_engine` at once.
"""

import base64
import json
import sys
import uuid
from pathlib import Path
from typing import Any

import httpx2
import pytest
from iceberg_connectors import JiraConnector, registry
from iceberg_detect import load_named_pack
from iceberg_engine import runner
from iceberg_engine.api_client import EngineClient
from iceberg_engine.runner import run_task

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "packages/connectors/tests"))

from jira_server import (  # after the path insert, necessarily
    API_TOKEN,
    EMAIL,
    SEEDED_SECRET,
    SITE,
    FakeJira,
    Issue,
    Project,
    leaky_description,
)

PACK = load_named_pack()
PEPPER = b"0123456789abcdef0123456789abcdef"
TASK_ID = uuid.UUID("11111111-1111-1111-1111-111111111111")


def _issues(count: int, *, updated: str = "") -> list[Issue]:
    return [
        Issue(
            f"1000{n}",
            f"ENG-{n}",
            created=f"2024-01-{n + 1:02d}T00:00",
            updated=updated,
            description=leaky_description(),
        )
        for n in range(count)
    ]


def _site(issues: list[Issue]) -> FakeJira:
    return FakeJira(projects=[Project("10000", "ENG", issues=issues)])


def _lease(**overrides: Any) -> dict[str, Any]:
    return {
        "task_id": str(TASK_ID),
        "scan_id": "33333333-3333-3333-3333-333333333333",
        "source_id": "44444444-4444-4444-4444-444444444444",
        "source_type": "jira",
        "kind": "fetch",
        "attempt": 1,
        "lease_expires_at": "2026-07-30T00:00:00Z",
        "spec": {"label": "ENG", "params": {"project_key": "ENG"}},
        "connection": {"base_url": SITE, "email": EMAIL},
        "credential": API_TOKEN,
        "fingerprint_pepper": base64.b64encode(PEPPER).decode(),
        "suppressions": [],
        "confidence_threshold": 0.5,
    } | overrides


class ControlPlane:
    """A scripted API that behaves like the real one for batches.

    In particular it enforces the same monotonic-sequence rule, so a replayed or
    out-of-order batch is refused here exactly as it would be in Postgres.
    """

    def __init__(self, lease: dict[str, Any], *, fail_batches_after: int | None = None) -> None:
        self.lease_body = lease
        self.fail_batches_after = fail_batches_after
        self.sequence = int(lease.get("checkpoint_sequence", 0))
        self.batches: list[dict[str, Any]] = []
        self.submissions: list[dict[str, Any]] = []

    def __call__(self, request: httpx2.Request) -> httpx2.Response:
        if request.url.path.endswith("/lease"):
            return httpx2.Response(200, json=self.lease_body)
        body = json.loads(request.content)
        if request.url.path.endswith("/progress"):
            if self.fail_batches_after is not None and len(self.batches) >= self.fail_batches_after:
                return httpx2.Response(503)
            if body["sequence"] != self.sequence + 1:
                return httpx2.Response(200, json={"sequence": self.sequence})
            self.sequence = body["sequence"]
            self.batches.append(body)
            return httpx2.Response(200, json={"sequence": self.sequence})
        self.submissions.append(body)
        return httpx2.Response(200, json={"task_id": str(TASK_ID)})

    def fingerprints(self, *, durable_only: bool = False) -> set[str]:
        """Every finding the control plane accepted.

        ``durable_only`` models an engine that *died*: it never sent a terminal
        submission, so only what its batches had already made durable survives.
        That is the whole point of batching, and counting the terminal submission
        of a "crashed" attempt would test nothing.
        """
        messages = self.batches if durable_only else (*self.batches, *self.submissions)
        return {finding["fingerprint"] for message in messages for finding in message["findings"]}

    def scanned(self, *, durable_only: bool = False) -> int:
        messages = self.batches if durable_only else (*self.batches, *self.submissions)
        return sum(
            message["coverage"]["counts"]["scanned"]
            for message in messages
            if message.get("coverage")
        )


def _client(api: ControlPlane) -> EngineClient:
    return EngineClient(
        base_url="http://api.test",
        token="engine-token",
        transport=httpx2.MockTransport(api),
        sleep=lambda _seconds: None,
    )


def _run(site: FakeJira, api: ControlPlane) -> Any:
    registry.register(
        JiraConnector(transport=site.transport(), sleep=lambda _s: None, sandbox_factory=None),
        replace=True,
    )
    return run_task(TASK_ID, client=_client(api), pack=PACK)


@pytest.fixture(autouse=True)
def _clean_registry() -> Any:
    registry.clear()
    yield
    registry.clear()


@pytest.fixture(autouse=True)
def _flush_every_issue(monkeypatch: pytest.MonkeyPatch) -> None:
    """Batch per issue, so a six-issue fixture exercises real batching."""
    monkeypatch.setattr(runner, "CHECKPOINT_BATCH_FINDINGS", 1)


def _spec_for(site: FakeJira) -> dict[str, Any]:
    connector = JiraConnector(
        transport=site.transport(), sleep=lambda _s: None, sandbox_factory=None
    )
    return next(
        iter(connector.discover({"base_url": SITE, "email": EMAIL}, API_TOKEN))
    ).as_payload()


# ─── A resumed run equals an uninterrupted one ────────────────────────────────


def test_an_interrupted_scan_resumed_finds_exactly_what_one_clean_run_finds() -> None:
    """The comparison the issue's validation section asks for."""
    site = _site(_issues(6))
    spec = _spec_for(site)

    clean = ControlPlane(_lease(spec=spec))
    _run(site, clean)

    # Now the same work, killed after two batches and resumed from where the
    # control plane says it actually got to.
    first = ControlPlane(_lease(spec=spec), fail_batches_after=2)
    _run(site, first)
    resumed = ControlPlane(
        _lease(
            spec=spec,
            attempt=2,
            checkpoint=first.batches[-1]["checkpoint"],
            checkpoint_sequence=first.sequence,
        )
    )
    _run(site, resumed)

    assert first.fingerprints(durable_only=True) | resumed.fingerprints() == clean.fingerprints()
    assert clean.fingerprints()  # the fixture really does leak something


def test_a_resumed_scan_counts_every_issue_exactly_once() -> None:
    """Coverage from both attempts is merged, so a re-count inflates the manifest
    and claims content the source does not have."""
    site = _site(_issues(6))
    spec = _spec_for(site)

    first = ControlPlane(_lease(spec=spec), fail_batches_after=2)
    _run(site, first)
    resumed = ControlPlane(
        _lease(
            spec=spec,
            attempt=2,
            checkpoint=first.batches[-1]["checkpoint"],
            checkpoint_sequence=first.sequence,
        )
    )
    _run(site, resumed)

    clean = ControlPlane(_lease(spec=spec))
    _run(site, clean)
    # The two attempts together read the project once, not once and a bit.
    assert first.scanned(durable_only=True) + resumed.scanned() == clean.scanned()


def test_a_replayed_batch_is_refused_and_ingests_nothing_twice() -> None:
    """Duplicate pages, per the issue's validation list."""
    site = _site(_issues(4))
    api = ControlPlane(_lease(spec=_spec_for(site)))
    _run(site, api)

    replayed = api.batches[0]
    before = api.sequence
    response = _client(api).submit_progress(TASK_ID, replayed)

    assert response["sequence"] == before
    assert len(api.batches) == before


# ─── Deleted content and expired positions ────────────────────────────────────


def test_an_issue_deleted_between_attempts_does_not_strand_the_resume() -> None:
    """Content deletion, per the issue's validation list.

    The boundary issue is gone when the task is re-leased. The window query is
    bounded by a date rather than by that issue's identity, so the rest of the
    project is still read.
    """
    site = _site(_issues(6))
    spec = _spec_for(site)
    first = ControlPlane(_lease(spec=spec), fail_batches_after=3)
    _run(site, first)

    boundary = first.batches[-1]["checkpoint"]["position"]["issue_id"]
    project = site.projects[0]
    project.issues = [issue for issue in project.issues if issue.id != boundary]

    resumed = ControlPlane(
        _lease(
            spec=spec,
            attempt=2,
            checkpoint=first.batches[-1]["checkpoint"],
            checkpoint_sequence=first.sequence,
        )
    )
    report = _run(site, resumed)

    assert report is not None
    assert resumed.scanned() > 0


def test_a_position_the_connector_no_longer_understands_restarts_the_spec() -> None:
    """Expired cursors, per the issue's validation list. Restarting costs a
    re-read; acting on a position whose meaning has changed costs coverage."""
    site = _site(_issues(4))
    spec = _spec_for(site)

    api = ControlPlane(
        _lease(
            spec=spec,
            checkpoint={"version": "99", "position": {"issue_id": "10002"}},
            checkpoint_sequence=2,
        )
    )
    _run(site, api)

    clean = ControlPlane(_lease(spec=spec))
    _run(site, clean)
    assert api.fingerprints() == clean.fingerprints()


# ─── Incremental narrowing ────────────────────────────────────────────────────


def test_an_incremental_window_reads_only_what_changed() -> None:
    site = _site(_issues(4, updated="2024-05-01T09:00"))
    connector = JiraConnector(
        transport=site.transport(), sleep=lambda _s: None, sandbox_factory=None
    )
    connection = {"base_url": SITE, "email": EMAIL}

    full = list(connector.discover(connection, API_TOKEN))
    narrowed = list(
        connector.discover(connection, API_TOKEN, cursors={"ENG": {"updated": "2024-06-01 00:00"}})
    )

    assert full
    assert narrowed == []


def test_no_plaintext_crosses_the_wire_in_any_message() -> None:
    site = _site(_issues(4))
    api = ControlPlane(_lease(spec=_spec_for(site)))

    _run(site, api)

    everything = json.dumps({"batches": api.batches, "submissions": api.submissions})
    assert SEEDED_SECRET not in everything
    assert API_TOKEN not in everything
