"""A seeded secret in Confluence becomes a redacted finding (#10, #71).

Epic #10's acceptance criterion, and the first test that runs a *real* connector
through the engine's whole loop:

    lease → Confluence REST → storage→text → detect → fingerprint → redact →
    pre-filter → the submission the API ingests

Everything is real except the two ends. Confluence is the in-process fixture site
(`packages/connectors/tests/confluence_server.py`, #71) and the control plane is a
scripted transport; between them the actual `ConfluenceConnector`, the actual rule
pack, and the actual `run_task` do the work. So this fails if the shapes stop
fitting — which is the only thing the per-package suites cannot tell us.

It lives in the root suite for that reason: it is the only test that spans
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
from iceberg_connectors import ConfluenceConnector, registry
from iceberg_detect import load_named_pack
from iceberg_engine.api_client import EngineClient
from iceberg_engine.runner import run_task

# The fixture site lives beside the connector tests, which is where it belongs —
# it is a Confluence stand-in, not a cross-package fixture.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "packages/connectors/tests"))

from confluence_server import (  # after the path insert, necessarily
    API_TOKEN,
    EMAIL,
    SEEDED_SECRET,
    SITE,
    Attachment,
    Comment,
    FakeConfluence,
    Page,
    Space,
    leaky_page_storage,
    storage_page,
)

PACK = load_named_pack()
PEPPER = b"0123456789abcdef0123456789abcdef"
TASK_ID = uuid.UUID("11111111-1111-1111-1111-111111111111")


def _lease(**overrides: Any) -> dict[str, Any]:
    return {
        "task_id": str(TASK_ID),
        "scan_id": "33333333-3333-3333-3333-333333333333",
        "source_id": "44444444-4444-4444-4444-444444444444",
        "source_type": "confluence",
        "kind": "fetch",
        "attempt": 1,
        "lease_expires_at": "2026-07-30T00:00:00Z",
        "spec": {
            "label": "space DOCS",
            "params": {"space_id": "s1", "space_key": "DOCS", "space_name": "Documentation"},
        },
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
def site_fixture() -> Iterator[FakeConfluence]:
    """A space with a secret in every place one can hide: body, comment, attachment."""
    site = FakeConfluence(
        spaces=[
            Space(
                "s1",
                "DOCS",
                "Documentation",
                pages=[
                    Page(
                        "p1",
                        "Deployment runbook",
                        leaky_page_storage(),
                        comments=[
                            Comment("c1", storage_page(f"the key is {SEEDED_SECRET} by the way"))
                        ],
                        attachments=[
                            Attachment("deploy.env", f"AWS_ACCESS_KEY_ID={SEEDED_SECRET}".encode())
                        ],
                    ),
                    Page("p2", "Changelog", storage_page("Nothing sensitive on this page.")),
                ],
            )
        ]
    )
    registry.clear()
    registry.register(
        # In-process parsing: the child-process isolation has its own tests against
        # real hostile parsers (`test_sandbox.py`), and a spawn per test buys nothing.
        ConfluenceConnector(transport=site.transport(), sleep=lambda _s: None, sandbox_factory=None)
    )
    yield site
    registry.clear()


# ─── The acceptance criterion ─────────────────────────────────────────────────


def test_a_seeded_secret_surfaces_as_a_redacted_finding(site: FakeConfluence) -> None:
    """Epic #10, stated as a test: a secret in a Confluence page comes back as a
    finding the API can ingest, with the secret gone."""
    api = ControlPlane()

    report = run_task(TASK_ID, client=_client(api), pack=PACK)

    assert report is not None and report.status == "completed"
    findings = api.submission["findings"]
    assert [finding["rule_id"] for finding in findings] == ["aws-access-key-id"] * 3
    assert SEEDED_SECRET not in json.dumps(api.submission)


def test_no_plaintext_and_no_credential_reach_the_api(site: FakeConfluence) -> None:
    """ADR 0004 for the secret; ADR 0007 for the token that read it. Asserted over
    the bytes actually sent, not over an intermediate object."""
    api = ControlPlane()

    run_task(TASK_ID, client=_client(api), pack=PACK)
    serialised = json.dumps(api.submission)

    assert SEEDED_SECRET not in serialised
    assert API_TOKEN not in serialised


def test_each_place_a_secret_can_hide_is_found_separately(site: FakeConfluence) -> None:
    """Body, comment, and attachment are three things an analyst has to fix, so they
    are three findings with three identities — not one deduplicated by content."""
    api = ControlPlane()

    run_task(TASK_ID, client=_client(api), pack=PACK)
    findings = api.submission["findings"]

    origins = sorted(finding["resource_locator"]["origin"] for finding in findings)
    assert origins == ["attachment", "body", "comment"]
    assert len({finding["fingerprint"] for finding in findings}) == 3
    # ...while the secret is demonstrably the same one in all three.
    assert len({finding["secret_hash"] for finding in findings}) == 1


def test_the_counts_distinguish_scanned_from_skipped(site: FakeConfluence) -> None:
    """ "Found nothing" and "could not read anything" look identical in a findings
    list, and the counts are the only place they differ."""
    api = ControlPlane()

    run_task(TASK_ID, client=_client(api), pack=PACK)

    # Two bodies, one comment, one attachment.
    assert api.submission["counts"]["units"] == 4
    assert api.submission["counts"]["units_failed"] == 0


def test_discovery_returns_the_specs_the_api_will_persist(site: FakeConfluence) -> None:
    """Phase one. The API turns each spec into a fetch task in the same transaction
    that completes this one, so a crash cannot record discovery as done yet lose
    what it found (ADR 0009)."""
    api = ControlPlane(_lease(kind="discovery", spec={}))

    run_task(TASK_ID, client=_client(api), pack=PACK)

    specs = api.submission["task_specs"]
    assert [spec["params"]["space_key"] for spec in specs] == ["DOCS"]
    assert api.submission["findings"] == []


# ─── Identity survives a re-scan (ADR 0006) ───────────────────────────────────


def test_a_rescan_of_unchanged_content_reproduces_the_fingerprints(
    site: FakeConfluence,
) -> None:
    """What triage survival rests on. If a second scan produced different
    fingerprints, every re-scan would raise the findings again as new and
    auto-resolve the analyst's decisions."""
    first, second = ControlPlane(), ControlPlane()

    run_task(TASK_ID, client=_client(first), pack=PACK)
    run_task(TASK_ID, client=_client(second), pack=PACK)

    assert [f["fingerprint"] for f in first.submission["findings"]] == [
        f["fingerprint"] for f in second.submission["findings"]
    ]


def test_editing_the_page_around_a_secret_keeps_its_fingerprint(
    site: FakeConfluence,
) -> None:
    """The reason a title and a version are display-only. Someone adding a paragraph
    above a secret must not orphan the finding for it."""
    before = ControlPlane()
    run_task(TASK_ID, client=_client(before), pack=PACK)

    page = site.spaces[0].pages[0]
    page.title = "Deployment runbook (revised)"
    page.storage = storage_page("A new opening paragraph.") + page.storage

    after = ControlPlane()
    run_task(TASK_ID, client=_client(after), pack=PACK)

    body_before = next(
        f for f in before.submission["findings"] if f["resource_locator"]["origin"] == "body"
    )
    body_after = next(
        f for f in after.submission["findings"] if f["resource_locator"]["origin"] == "body"
    )
    assert body_before["fingerprint"] == body_after["fingerprint"]
    # ...and the title, which did change, travels as display context.
    assert body_after["resource_locator"]["title"] == "Deployment runbook (revised)"


# ─── The connector's own failures reach the API ────────────────────────────────


def test_a_rejected_confluence_token_fails_the_task_with_the_reason(
    site: FakeConfluence,
) -> None:
    """An empty result would read as "this space is clean". `CredentialError` names
    the fix instead: rotate the credential (ADR 0007)."""
    api = ControlPlane(_lease(credential="a-revoked-token"))

    report = run_task(TASK_ID, client=_client(api), pack=PACK)

    assert report is not None and report.status == "failed"
    assert "CredentialError" in api.submission["error"]
    assert api.submission["findings"] == []


def test_being_rate_limited_does_not_fail_the_scan(site: FakeConfluence) -> None:
    """A scan is exactly the workload that trips a Confluence rate limit, so a 429
    mid-task has to be a pause rather than a failure (#49)."""
    site.throttle_first, site.retry_after = 4, 0.01
    api = ControlPlane()

    report = run_task(TASK_ID, client=_client(api), pack=PACK)

    assert report is not None and report.status == "completed"
    assert len(api.submission["findings"]) == 3


def test_a_suppression_from_the_lease_is_applied_before_reporting(
    site: FakeConfluence,
) -> None:
    """Bandwidth saved locally, and the keys the connector populates are what make an
    analyst's `path_glob` matchable at all (#44)."""
    api = ControlPlane(
        _lease(
            suppressions=[
                {"id": str(uuid.uuid4()), "scope": "path_glob", "pattern": "*/pages/p1/*"}
            ]
        )
    )

    run_task(TASK_ID, client=_client(api), pack=PACK)

    assert api.submission["findings"] == []
    assert api.submission["counts"]["prefiltered"] == 3
