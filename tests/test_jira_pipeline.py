"""A seeded secret in Jira becomes a redacted finding (#144).

The Confluence pipeline test's sibling, and the thing that proves the connector SDK
published in #149 is real: a second connector runs the *same* engine loop with no
engine change beyond how it names its scopes.

    lease → Jira REST → ADF→text → detect → fingerprint → redact → pre-filter →
    the submission the API ingests

Everything is real except the two ends. Jira is the in-process fixture site
(`packages/connectors/tests/jira_server.py`) and the control plane is a scripted
transport; between them the actual `JiraConnector`, the actual rule pack, and the
actual `run_task` do the work. So this fails if the shapes stop fitting — which is
the only thing the per-package suites cannot tell us.

It lives in the root suite for that reason: it is the only kind of test that spans
`iceberg_connectors`, `iceberg_detect`, and `iceberg_engine` at once, and importing
the engine from a connector test would be an undeclared dependency.
"""

import base64
import json
import sys
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx2
import pytest
from iceberg_connectors import JiraConnector, registry
from iceberg_detect import load_named_pack
from iceberg_engine.api_client import EngineClient
from iceberg_engine.runner import run_task

# The fixture site lives beside the connector tests, which is where it belongs —
# it is a Jira stand-in, not a cross-package fixture.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "packages/connectors/tests"))

from jira_server import (  # after the path insert, necessarily
    API_TOKEN,
    EMAIL,
    SEEDED_SECRET,
    SITE,
    Attachment,
    Change,
    Comment,
    FakeJira,
    Issue,
    Project,
    adf,
    leaky_description,
)

PACK = load_named_pack()
PEPPER = b"0123456789abcdef0123456789abcdef"
TASK_ID = uuid.UUID("11111111-1111-1111-1111-111111111111")


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
    """The API side: hands out one lease, records the submission."""

    def __init__(self, lease: dict[str, Any] | None = None) -> None:
        self.lease_body = lease if lease is not None else _lease()
        self.submissions: list[dict[str, Any]] = []

    def __call__(self, request: httpx2.Request) -> httpx2.Response:
        if request.url.path.endswith("/lease"):
            return httpx2.Response(200, json=self.lease_body)
        self.submissions.append(json.loads(request.content))
        return httpx2.Response(200, json={"task_id": str(TASK_ID)})

    @property
    def submission(self) -> dict[str, Any]:
        assert len(self.submissions) == 1, f"expected one submission, got {len(self.submissions)}"
        return self.submissions[0]


def _client(api: ControlPlane) -> EngineClient:
    return EngineClient(
        base_url="http://api.test",
        token="engine-token",  # a fixture, not a credential
        transport=httpx2.MockTransport(api),
        sleep=lambda _seconds: None,
    )


@pytest.fixture(name="site")
def site_fixture() -> Iterator[FakeJira]:
    """A project with a secret in every place one can hide."""
    site = FakeJira(
        projects=[
            Project(
                "10000",
                "ENG",
                issues=[
                    Issue(
                        "10001",
                        "ENG-1",
                        summary="Deployment runbook",
                        description=leaky_description(),
                        comments=[Comment("c1", adf(f"the key is {SEEDED_SECRET} by the way"))],
                        attachments=[
                            Attachment(
                                "55", "deploy.env", f"AWS_ACCESS_KEY_ID={SEEDED_SECRET}".encode()
                            )
                        ],
                        changes=[Change("77", to_string=f"old key {SEEDED_SECRET}")],
                    ),
                    Issue("10002", "ENG-2", description=adf("Nothing sensitive on this issue.")),
                ],
            )
        ]
    )
    registry.clear()
    registry.register(
        # In-process parsing: the child-process isolation has its own tests against
        # real hostile parsers (`test_sandbox.py`), and a spawn per test buys nothing.
        JiraConnector(transport=site.transport(), sleep=lambda _s: None, sandbox_factory=None)
    )
    yield site
    registry.clear()


def test_a_seeded_secret_becomes_a_redacted_finding(site: FakeJira) -> None:
    api = ControlPlane()

    run_task(TASK_ID, client=_client(api), pack=PACK)

    submission = api.submission
    assert submission["findings"], "the seeded secret produced no finding"
    serialized = json.dumps(submission)
    # ADR 0004: only a masked snippet and a salted hash ever leave the engine.
    assert SEEDED_SECRET not in serialized
    assert API_TOKEN not in serialized


def test_a_secret_is_found_in_the_body_the_comment_and_the_attachment(site: FakeJira) -> None:
    api = ControlPlane()

    run_task(TASK_ID, client=_client(api), pack=PACK)

    origins = {finding["resource_locator"].get("origin") for finding in api.submission["findings"]}
    assert {"body", "comment", "attachment"} <= origins


def test_history_is_scanned_only_when_the_source_asks_for_it(site: FakeJira) -> None:
    without = ControlPlane()
    run_task(TASK_ID, client=_client(without), pack=PACK)

    with_history = ControlPlane(
        _lease(connection={"base_url": SITE, "email": EMAIL, "include_history": True})
    )
    run_task(TASK_ID, client=_client(with_history), pack=PACK)

    def histories(api: ControlPlane) -> list[Any]:
        return [
            finding
            for finding in api.submission["findings"]
            if str(finding["resource_locator"].get("sub_resource") or "").startswith("history:")
        ]

    assert histories(without) == []
    assert histories(with_history)


def test_a_rescan_reports_the_same_fingerprints(site: FakeJira) -> None:
    """Identity across rescans is the acceptance criterion the locator exists for."""
    first, second = ControlPlane(), ControlPlane()

    run_task(TASK_ID, client=_client(first), pack=PACK)
    run_task(TASK_ID, client=_client(second), pack=PACK)

    assert {f["fingerprint"] for f in first.submission["findings"]} == {
        f["fingerprint"] for f in second.submission["findings"]
    }


def test_a_restricted_issue_does_not_stop_the_scan(site: FakeJira) -> None:
    """The Jira-specific behaviour, end to end: 403 is one object, not the site."""
    site.forbidden_paths = ("/comment",)
    api = ControlPlane()

    run_task(TASK_ID, client=_client(api), pack=PACK)

    submission = api.submission
    # The bodies and the attachment still produced findings...
    assert submission["findings"]
    # ...and the unreadable comment collections are recorded rather than ignored.
    assert submission["coverage"]["scope"]["gaps"] > 0
    assert submission["status"] == "failed"


def test_the_coverage_manifest_counts_issues_as_records(site: FakeJira) -> None:
    api = ControlPlane()

    run_task(TASK_ID, client=_client(api), pack=PACK)

    coverage = api.submission["coverage"]
    assert coverage["counts"]["discovered"] == (
        coverage["counts"]["scanned"] + coverage["counts"]["skipped"] + coverage["counts"]["failed"]
    )
