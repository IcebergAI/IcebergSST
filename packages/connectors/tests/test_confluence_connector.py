"""The Confluence connector against a Confluence-shaped site (#47, #48, #49).

Driven through the real client and the fixture server in `confluence_server.py`, so
discovery really pages, fetches really follow cursors, and attachments really go
through extraction. The connector is never given a stubbed client — a double that
could not paginate or refuse a credential would only prove the happy path.

Two things get more attention than their line count suggests. **Locators**, because
they decide whether an analyst's triage decision survives a re-scan (ADR 0006) and
getting them wrong fails quietly. And **skips versus failures**, because "the scan
found nothing" and "the scan could not read anything" look identical in a findings
list.
"""

from typing import Any

import pytest
from confluence_server import (
    API_TOKEN,
    SEEDED_SECRET,
    SITE,
    Attachment,
    Comment,
    FakeConfluence,
    Page,
    Space,
    leaky_page_storage,
    recorded_clients,
    storage_page,
)
from iceberg_connectors.confluence import ConfluenceConnector
from iceberg_connectors.confluence.client import RateLimited, RateLimitPolicy
from iceberg_connectors.extraction import ExtractionLimits
from iceberg_connectors.protocol import ConnectorError, CredentialError, FetchOutcome, TaskSpec
from iceberg_connectors.units import ContentOrigin, ContentUnit
from structlog.testing import capture_logs


def _connector(site: FakeConfluence, **overrides: Any) -> ConfluenceConnector:
    """A connector wired to `site`, parsing in-process.

    `sandbox_factory=None` because these tests are about the connector, not the
    isolation — `test_sandbox.py` covers that against real hostile parsers, and
    spawning a child per test would cost seconds for nothing. The default is a real
    sandbox; `test_the_sandbox_is_per_fetch` covers the wiring.
    """
    defaults: dict[str, Any] = {
        "transport": site.transport(),
        "sleep": lambda _seconds: None,
        "sandbox_factory": None,
    }
    return ConfluenceConnector(**(defaults | overrides))


def _site(**overrides: Any) -> FakeConfluence:
    """A small site: one space, one leaky page, one comment, one attachment."""
    defaults: dict[str, Any] = {
        "spaces": [
            Space(
                "s1",
                "DOCS",
                "Documentation",
                pages=[
                    Page(
                        "p1",
                        "Deployment runbook",
                        leaky_page_storage(),
                        comments=[Comment("c1", storage_page("thanks, fixed"))],
                        attachments=[Attachment("notes.txt", b"nothing interesting here")],
                    ),
                    Page("p2", "Changelog", storage_page("nothing to see")),
                ],
            )
        ]
    }
    return FakeConfluence(**(defaults | overrides))


def _fetch(
    connector: ConfluenceConnector, site: FakeConfluence, **params: Any
) -> tuple[list[ContentUnit], FetchOutcome]:
    outcome = FetchOutcome()
    spec = TaskSpec(label="space DOCS", params={"space_id": "s1", "space_key": "DOCS", **params})
    units = list(connector.fetch(site.connection, spec, API_TOKEN, outcome))
    return units, outcome


# ─── Discovery (#47) ──────────────────────────────────────────────────────────


def test_discovery_returns_one_spec_per_space() -> None:
    """One space per task, not one page: discovering every page of every space
    before scanning any would turn the fastest part of a scan into a serial
    prologue, and produce a task table with a row per page."""
    site = FakeConfluence(
        spaces=[Space("s1", "DOCS", "Documentation"), Space("s2", "OPS", "Operations")]
    )

    specs = list(_connector(site).discover(site.connection, API_TOKEN))

    assert [spec.params["space_key"] for spec in specs] == ["DOCS", "OPS"]
    assert specs[0].label == "space DOCS"


def test_unfiltered_discovery_fails_when_a_space_has_no_stable_id() -> None:
    site = FakeConfluence(spaces=[Space("", "DOCS", "Documentation")])

    with pytest.raises(ConnectorError, match="malformed or duplicate"):
        list(_connector(site).discover(site.connection, API_TOKEN))


def test_duplicate_discovery_space_preserves_one_spec_then_fails_closed() -> None:
    site = FakeConfluence(
        spaces=[
            Space("s1", "DOCS", "Documentation"),
            Space("s1", "DOCS", "Repeated documentation"),
        ]
    )
    stream = _connector(site).discover(site.connection | {"spaces": ["DOCS"]}, API_TOKEN)

    assert next(stream).params["space_id"] == "s1"
    with pytest.raises(ConnectorError, match="malformed or duplicate"):
        next(stream)


def test_a_spec_carries_what_fetch_needs_and_nothing_secret() -> None:
    """A spec crosses the wire twice and is persisted by the API (ADR 0009), so it
    must be plain JSON and must not carry the credential."""
    site = FakeConfluence(spaces=[Space("s1", "DOCS", "Documentation")])

    spec = next(iter(_connector(site).discover(site.connection, API_TOKEN)))

    assert spec.params["space_id"] == "s1"
    assert API_TOKEN not in str(spec.as_payload())


def test_the_scope_filter_narrows_discovery() -> None:
    site = FakeConfluence(spaces=[Space("s1", "DOCS", "Docs"), Space("s2", "OPS", "Ops")])
    connection = site.connection | {"spaces": ["OPS"]}

    specs = list(_connector(site).discover(connection, API_TOKEN))

    assert [spec.params["space_key"] for spec in specs] == ["OPS"]


def test_the_scope_filter_ignores_the_case_the_operator_typed() -> None:
    """Space keys are conventionally uppercase and an operator types what they saw.
    Matching case-sensitively gave `["docs"]` zero task specs and a scan that
    completed looking clean — the silent empty scan (#133)."""
    site = FakeConfluence(spaces=[Space("s1", "DOCS", "Docs"), Space("s2", "OPS", "Ops")])
    connection = site.connection | {"spaces": ["docs", "Ops"]}

    specs = list(_connector(site).discover(connection, API_TOKEN))

    assert [spec.params["space_key"] for spec in specs] == ["DOCS", "OPS"]


def test_a_scope_entry_that_matches_no_space_fails_discovery() -> None:
    """An explicitly requested space is part of the coverage contract.  Silently
    omitting it would let an incomplete scan reconcile as clean."""
    site = FakeConfluence(spaces=[Space("s1", "DOCS", "Docs")])
    connection = site.connection | {"spaces": ["DOCS", "typo"]}

    with capture_logs() as events:
        discovered = _connector(site).discover(connection, API_TOKEN)
        first = next(discovered)
        with pytest.raises(ConnectorError, match="typo"):
            next(discovered)

    assert first.params["space_key"] == "DOCS"
    warned = [event for event in events if event["event"] == "confluence_spaces_not_found"]
    assert warned == [
        {"event": "confluence_spaces_not_found", "log_level": "warning", "spaces": ["typo"]}
    ]


def test_personal_spaces_are_excluded_unless_asked_for() -> None:
    """Every user's drafts. They dominate the space count on a large site, and
    scanning them should be a deliberate decision rather than an inherited one."""
    site = FakeConfluence(
        spaces=[Space("s1", "DOCS", "Docs"), Space("s2", "~alice", "Alice", type="personal")]
    )

    default = list(_connector(site).discover(site.connection, API_TOKEN))
    opted_in = list(
        _connector(site).discover(site.connection | {"include_personal_spaces": True}, API_TOKEN)
    )

    assert [spec.params["space_key"] for spec in default] == ["DOCS"]
    assert len(opted_in) == 2


def test_discovery_pages_through_every_space() -> None:
    site = FakeConfluence(
        spaces=[Space(f"s{n}", f"S{n}", f"Space {n}") for n in range(5)], page_size=2
    )

    specs = list(_connector(site).discover(site.connection, API_TOKEN))

    assert len(specs) == 5
    assert site.cursors_followed() == ["cursor-2", "cursor-4"]


def test_an_empty_site_discovers_nothing_without_failing() -> None:
    """A legitimate answer. The scan completes having scanned nothing, and
    reconciliation refuses to auto-resolve on that evidence alone (ADR 0009 §4)."""
    site = FakeConfluence(spaces=[])

    assert list(_connector(site).discover(site.connection, API_TOKEN)) == []


def test_a_source_without_a_base_url_fails_loudly() -> None:
    site = _site()

    with pytest.raises(ConnectorError, match="base_url"):
        list(_connector(site).discover({}, API_TOKEN))


def test_a_rejected_credential_fails_discovery_rather_than_returning_nothing() -> None:
    """An empty result would read as "this site has no spaces"."""
    site = _site()

    with pytest.raises(CredentialError):
        list(_connector(site).discover(site.connection, "the-wrong-token"))


# ─── Bodies and comments (#48) ────────────────────────────────────────────────


def test_a_page_body_becomes_a_content_unit() -> None:
    site = _site()

    units, outcome = _fetch(_connector(site), site)

    bodies = [unit for unit in units if unit.origin is ContentOrigin.BODY]
    assert [unit.locator.resource_id for unit in bodies] == ["p1", "p2"]
    assert SEEDED_SECRET in bodies[0].text
    assert outcome.failed == 0


def test_the_body_is_flattened_storage_not_markup() -> None:
    """Detection reads text. Tags between a keyword and a secret cost the proximity
    signal that scores it (ADR 0003)."""
    site = _site()

    units, _ = _fetch(_connector(site), site)

    assert "<ac:structured-macro" not in units[0].text
    assert "aws access key" in units[0].text


def test_a_comment_is_its_own_unit_with_its_own_locator() -> None:
    """Separate things to fix: a secret in a comment is deleted by its author, one
    in the body is edited out of the page. Merging them would also let one person's
    comment change the body's fingerprint."""
    site = _site()

    units, _ = _fetch(_connector(site), site)

    comments = [unit for unit in units if unit.origin is ContentOrigin.COMMENT]
    assert len(comments) == 1
    assert comments[0].locator.resource_id == "p1"
    assert comments[0].locator.sub_resource == "comment:c1"


def test_inline_and_footer_comments_are_both_scanned() -> None:
    """An inline comment on a paragraph is where someone answers "what's the
    staging password?"."""
    site = _site(
        spaces=[
            Space(
                "s1",
                "DOCS",
                "Docs",
                pages=[
                    Page(
                        "p1",
                        "Runbook",
                        storage_page("body"),
                        comments=[
                            Comment("c1", storage_page("footer note")),
                            Comment("c2", storage_page("inline note"), inline=True),
                        ],
                    )
                ],
            )
        ]
    )

    units, _ = _fetch(_connector(site), site)

    texts = [unit.text for unit in units if unit.origin is ContentOrigin.COMMENT]
    assert sorted(texts) == ["footer note", "inline note"]


def test_paginated_footer_and_inline_replies_are_scanned_recursively() -> None:
    """Page comment collections contain roots only. Replies live on separate,
    cursor-paginated children endpoints for both comment types."""
    footer = Comment(
        "f0",
        storage_page("footer root"),
        replies=[
            Comment(
                "f1",
                storage_page("footer reply one"),
                replies=[Comment("f1a", storage_page("footer nested reply"))],
            ),
            Comment("f2", storage_page("footer reply two")),
            Comment("f3", storage_page("footer reply three")),
        ],
    )
    inline = Comment(
        "i0",
        storage_page("inline root"),
        inline=True,
        replies=[
            Comment("i1", storage_page("inline reply one"), inline=True),
            Comment("i2", storage_page("inline reply two"), inline=True),
            Comment("i3", storage_page("inline reply three"), inline=True),
        ],
    )
    site = _site(
        spaces=[
            Space(
                "s1",
                "DOCS",
                "Docs",
                pages=[Page("p1", "Runbook", storage_page("body"), comments=[footer, inline])],
            )
        ],
        page_size=2,
    )

    units, outcome = _fetch(_connector(site), site)

    comment_ids = {
        unit.display["comment_id"] for unit in units if unit.origin is ContentOrigin.COMMENT
    }
    assert comment_ids == {"f0", "f1", "f1a", "f2", "f3", "i0", "i1", "i2", "i3"}
    requested = [str(request.url) for request in site.requests]
    assert any(
        "/footer-comments/f0/children?" in url and "cursor=cursor-2" in url for url in requested
    )
    assert any(
        "/inline-comments/i0/children?" in url and "cursor=cursor-2" in url for url in requested
    )
    assert outcome.failed == 0


def test_comments_can_be_switched_off() -> None:
    site = _site()
    connection = site.connection | {"include_comments": False}
    outcome = FetchOutcome()

    units = list(
        _connector(site).fetch(
            connection,
            TaskSpec(label="space DOCS", params={"space_id": "s1", "space_key": "DOCS"}),
            API_TOKEN,
            outcome,
        )
    )

    assert not any(unit.origin is ContentOrigin.COMMENT for unit in units)


def test_a_page_whose_list_entry_carries_no_body_is_fetched_individually() -> None:
    """An older deployment answering without bodies must not silently skip the most
    likely place for a secret."""
    site = _site(
        spaces=[
            Space(
                "s1",
                "DOCS",
                "Docs",
                pages=[Page("p1", "Runbook", leaky_page_storage(), body_in_list=False)],
            )
        ]
    )

    units, _ = _fetch(_connector(site), site)

    assert SEEDED_SECRET in units[0].text
    assert "/wiki/api/v2/pages/p1" in site.paths_requested()


def test_a_page_with_no_text_is_a_skip_not_a_failure() -> None:
    site = _site(spaces=[Space("s1", "DOCS", "Docs", pages=[Page("p1", "Empty", "")])])

    units, outcome = _fetch(_connector(site), site)

    assert units == []
    assert (outcome.skipped, outcome.failed) == (1, 0)
    assert outcome.as_coverage()["counts"] == {
        "requested": 1,
        "discovered": 1,
        "scanned": 0,
        "skipped": 1,
        "failed": 0,
    }
    assert outcome.as_coverage()["reasons"] == [
        {"outcome": "skipped", "reason": "empty_content", "count": 1}
    ]


def test_an_empty_comment_has_one_skipped_disposition() -> None:
    site = _site(
        spaces=[
            Space(
                "s1",
                "DOCS",
                "Docs",
                pages=[
                    Page(
                        "p1",
                        "Runbook",
                        storage_page("readable body"),
                        comments=[Comment("c1", storage_page(""))],
                    )
                ],
            )
        ]
    )

    units, outcome = _fetch(_connector(site), site)

    assert [unit.origin for unit in units] == [ContentOrigin.BODY]
    coverage = outcome.as_coverage()
    assert coverage["counts"] == {
        "requested": 2,
        "discovered": 2,
        "scanned": 1,
        "skipped": 1,
        "failed": 0,
    }
    assert coverage["reasons"] == [{"outcome": "skipped", "reason": "empty_content", "count": 1}]


@pytest.mark.parametrize(
    "page",
    [
        Page(
            "p2",
            "Missing",
            storage_page("unreadable"),
            body_in_list=False,
            body_in_detail=False,
        ),
        Page(
            "p2",
            "Unsupported",
            storage_page("unreadable"),
            body_representation="atlas_doc_format",
        ),
    ],
)
def test_a_successful_page_response_without_supported_content_is_incomplete(
    page: Page,
) -> None:
    """A malformed HTTP 200 is unread content, not evidence that a page is clean."""
    site = _site(
        spaces=[
            Space(
                "s1",
                "DOCS",
                "Docs",
                pages=[Page("p1", "Readable", storage_page("visible")), page],
            )
        ]
    )

    units, outcome = _fetch(_connector(site), site)

    assert [unit.locator.resource_id for unit in units] == ["p1"]
    assert (outcome.units, outcome.failed) == (1, 1)


@pytest.mark.parametrize(
    "comment",
    [
        Comment("c2", storage_page("unreadable"), include_body=False),
        Comment(
            "c2",
            storage_page("unreadable"),
            body_representation="atlas_doc_format",
        ),
    ],
)
def test_a_comment_without_supported_content_is_incomplete(comment: Comment) -> None:
    """Malformed comments fail coverage while readable page content still survives."""
    site = _site(
        spaces=[
            Space(
                "s1",
                "DOCS",
                "Docs",
                pages=[Page("p1", "Runbook", storage_page("visible"), comments=[comment])],
            )
        ]
    )

    units, outcome = _fetch(_connector(site), site)

    assert [unit.text for unit in units] == ["visible"]
    assert (outcome.units, outcome.failed) == (1, 1)


def test_fetch_pages_through_a_large_space() -> None:
    site = _site(
        spaces=[
            Space(
                "s1",
                "DOCS",
                "Docs",
                pages=[Page(f"p{n}", f"Page {n}", storage_page(f"body {n}")) for n in range(5)],
            )
        ],
        page_size=2,
    )

    units, outcome = _fetch(_connector(site), site)

    assert [unit.locator.resource_id for unit in units] == ["p0", "p1", "p2", "p3", "p4"]
    assert outcome.units == 5


def test_a_fetch_spec_without_a_space_id_fails_rather_than_scanning_nothing() -> None:
    site = _site()
    outcome = FetchOutcome()

    with pytest.raises(ConnectorError, match="space_id"):
        list(
            _connector(site).fetch(
                site.connection, TaskSpec(label="broken", params={}), API_TOKEN, outcome
            )
        )


# ─── Locators and display (#48 — ADR 0006) ────────────────────────────────────


def test_the_locator_holds_only_stable_identity() -> None:
    """The title, the URL, and the version all change when someone edits a page. Any
    of them in the coarse half means every re-scan produces "new" findings while the
    old ones auto-resolve, silently discarding triage history."""
    site = _site()

    units, _ = _fetch(_connector(site), site)
    locator = units[0].locator

    assert (locator.connector_type, locator.resource_id) == ("confluence", "p1")
    assert locator.sub_resource is None


def test_renaming_a_page_does_not_change_its_locator() -> None:
    """The property triage survival rests on."""
    site = _site()
    before = _fetch(_connector(site), site)[0][0].locator

    site.spaces[0].pages[0].title = "Deployment runbook (2026 edition)"
    after = _fetch(_connector(site), site)[0][0].locator

    assert before == after


def test_display_carries_the_keys_a_path_glob_can_match() -> None:
    """`GLOB_FRIENDLY_KEYS`. A connector populating none of them leaves analysts
    unable to write a `path_glob` suppression for this source at all."""
    site = _site()

    units, _ = _fetch(_connector(site), site)
    display = units[0].display

    assert display["space"] == "DOCS"
    assert display["title"] == "Deployment runbook"
    assert display["url"].startswith(f"{SITE}/wiki/spaces/")
    assert display["path"].startswith("/spaces/")


def test_everything_on_a_page_shares_the_pages_path() -> None:
    """A comment and an attachment have no `webui` link of their own. Giving them a
    synthetic path would mean a `path_glob` an analyst wrote against a page silently
    missed the comments and attachments on it — suppressing one finding out of three
    and looking correct (#44)."""
    site = _site()

    units, _ = _fetch(_connector(site), site)
    on_page_1 = [unit for unit in units if unit.locator.resource_id == "p1"]

    assert len({unit.display["path"] for unit in on_page_1}) == 1
    assert {unit.origin for unit in on_page_1} == {
        ContentOrigin.BODY,
        ContentOrigin.COMMENT,
        ContentOrigin.ATTACHMENT,
    }
    # ...while each still says which part of the page it is.
    assert on_page_1[1].display["comment_id"] == "c1"
    assert on_page_1[2].display["filename"] == "notes.txt"


def test_a_page_fetched_individually_still_gets_a_real_path() -> None:
    """The fallback fetch is also where the `webui` link comes from, so a page whose
    list entry carried no body must not end up with a synthetic path either."""
    site = _site(
        spaces=[
            Space(
                "s1",
                "DOCS",
                "Docs",
                pages=[Page("p1", "Runbook", storage_page("text"), body_in_list=False)],
            )
        ]
    )

    units, _ = _fetch(_connector(site), site)

    assert units[0].display["path"].startswith("/spaces/")


def test_the_finding_locator_flattens_both_halves() -> None:
    site = _site()

    units, _ = _fetch(_connector(site), site)
    blob = units[0].resource_locator()

    assert blob["connector_type"] == "confluence"
    assert blob["resource_id"] == "p1"
    assert blob["origin"] == "body"
    assert blob["space"] == "DOCS"


# ─── Attachments (#49) ────────────────────────────────────────────────────────


def test_a_text_attachment_is_extracted_into_a_unit() -> None:
    site = _site(
        spaces=[
            Space(
                "s1",
                "DOCS",
                "Docs",
                pages=[
                    Page(
                        "p1",
                        "Runbook",
                        storage_page("see attached"),
                        attachments=[
                            Attachment("deploy.env", f"AWS_ACCESS_KEY_ID={SEEDED_SECRET}".encode())
                        ],
                    )
                ],
            )
        ]
    )

    units, _ = _fetch(_connector(site), site)

    attachments = [unit for unit in units if unit.origin is ContentOrigin.ATTACHMENT]
    assert len(attachments) == 1
    assert SEEDED_SECRET in attachments[0].text
    assert attachments[0].locator.sub_resource == "attachment:deploy.env"


def test_an_attachment_locator_uses_the_filename_not_its_id() -> None:
    """Replacing an attachment with a corrected version gives it a new id. Keying on
    that would orphan the old finding and raise a new one for the same file."""
    site = _site()

    units, _ = _fetch(_connector(site), site)
    attachment = next(unit for unit in units if unit.origin is ContentOrigin.ATTACHMENT)

    assert attachment.locator.sub_resource == "attachment:notes.txt"


def test_an_image_is_skipped_rather_than_scanned() -> None:
    """No OCR in MVP, and decoding a PNG as text would feed entropy rules megabytes
    of replacement characters."""
    site = _site(
        spaces=[
            Space(
                "s1",
                "DOCS",
                "Docs",
                pages=[
                    Page(
                        "p1",
                        "Diagram",
                        storage_page("architecture"),
                        attachments=[
                            Attachment("diagram.png", b"\x89PNG\r\n\x1a\n", media_type="image/png")
                        ],
                    )
                ],
            )
        ]
    )

    units, outcome = _fetch(_connector(site), site)

    assert not any(unit.origin is ContentOrigin.ATTACHMENT for unit in units)
    assert outcome.skipped == 1
    assert outcome.as_coverage()["reasons"] == [
        {"outcome": "skipped", "reason": "unsupported_type", "count": 1}
    ]


def test_an_attachment_that_declares_a_huge_size_is_incomplete_without_download() -> None:
    """Checked against the declared size first so an obviously oversized file is
    never downloaded."""
    site = _site(
        spaces=[
            Space(
                "s1",
                "DOCS",
                "Docs",
                pages=[
                    Page(
                        "p1",
                        "Dump",
                        storage_page("attached"),
                        attachments=[Attachment("dump.txt", b"small", declared_size=10**9)],
                    )
                ],
            )
        ]
    )

    _, outcome = _fetch(_connector(site), site)

    assert (outcome.skipped, outcome.failed) == (0, 1)
    assert not any("/download/" in path for path in site.paths_requested())
    assert outcome.as_coverage()["reasons"] == [
        {"outcome": "failed", "reason": "size_limit", "count": 1}
    ]


def test_an_attachment_that_lies_about_its_size_fails_closed_mid_download() -> None:
    """The declaration comes from the same place the file does, so the bytes are
    counted as they arrive too."""
    site = _site(
        spaces=[
            Space(
                "s1",
                "DOCS",
                "Docs",
                pages=[
                    Page(
                        "p1",
                        "Dump",
                        storage_page("attached"),
                        attachments=[Attachment("dump.txt", b"x" * 5000, declared_size=10)],
                    )
                ],
            )
        ]
    )
    connector = _connector(site, extraction_limits=ExtractionLimits(max_input_bytes=1000))

    _, outcome = _fetch(connector, site)

    assert (outcome.skipped, outcome.failed) == (0, 1)


def test_a_malformed_attachment_is_incomplete_not_an_ordinary_skip() -> None:
    site = _site(
        spaces=[
            Space(
                "s1",
                "DOCS",
                "Docs",
                pages=[
                    Page(
                        "p1",
                        "Runbook",
                        storage_page("attached"),
                        attachments=[Attachment("broken.docx", b"not a zip archive")],
                    )
                ],
            )
        ]
    )

    units, outcome = _fetch(_connector(site), site)

    assert not any(unit.origin is ContentOrigin.ATTACHMENT for unit in units)
    assert (outcome.skipped, outcome.failed) == (0, 1)


def test_parser_exception_text_never_reaches_connector_logs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A parser may echo attacker-controlled document plaintext in its exception."""
    canary = "plaintext-canary-must-not-log"

    def raises_with_plaintext(_data: bytes, _limits: ExtractionLimits) -> Any:
        raise ValueError(canary)

    extraction = __import__("iceberg_connectors.extraction", fromlist=["_EXTRACTORS"])
    monkeypatch.setitem(extraction._EXTRACTORS, "text", raises_with_plaintext)
    site = _site()

    with capture_logs() as events:
        _, outcome = _fetch(_connector(site), site)

    assert outcome.failed == 1
    assert canary not in str(events)
    rejected = [event for event in events if event["event"] == "confluence_attachment_rejected"]
    assert rejected == [
        {
            "event": "confluence_attachment_rejected",
            "log_level": "warning",
            "name": "notes.txt",
            "outcome": "failed_parse",
        }
    ]


def test_a_truncated_attachment_keeps_its_partial_unit_but_fails_closed() -> None:
    site = _site(
        spaces=[
            Space(
                "s1",
                "DOCS",
                "Docs",
                pages=[
                    Page(
                        "p1",
                        "Runbook",
                        storage_page("attached"),
                        attachments=[Attachment("large.txt", b"useful text " * 100)],
                    )
                ],
            )
        ]
    )
    connector = _connector(site, extraction_limits=ExtractionLimits(max_output_chars=64))

    units, outcome = _fetch(connector, site)

    attachment = next(unit for unit in units if unit.origin is ContentOrigin.ATTACHMENT)
    assert attachment.display["truncated"] is True
    assert outcome.failed == 1
    coverage = outcome.as_coverage()
    assert coverage["counts"] == {
        "requested": 2,
        "discovered": 2,
        "scanned": 1,
        "skipped": 0,
        "failed": 1,
    }
    assert coverage["reasons"] == [{"outcome": "failed", "reason": "output_limit", "count": 1}]
    assert coverage["counts"]["requested"] == sum(
        coverage["counts"][outcome] for outcome in ("scanned", "skipped", "failed")
    )


def test_an_attachment_is_downloaded_from_the_context_base_the_site_reported() -> None:
    """`downloadLink` and `webui` come from the same `_links` family. Splicing `/wiki`
    onto one and resolving the other against the bare site root gives an analyst a
    page link that works beside an attachment URL that 404s on every file (#124)."""
    site = _site()

    units, outcome = _fetch(_connector(site), site)

    attachment = next(unit for unit in units if unit.origin is ContentOrigin.ATTACHMENT)
    assert "/wiki/download/attachments/p1-0/notes.txt" in site.paths_requested()
    assert attachment.display["url"].startswith(f"{SITE}/wiki/spaces/")
    assert outcome.failed == 0


def test_a_deployment_without_a_context_base_downloads_from_the_site_root() -> None:
    """Server/DC mounts at the root and reports no `_links.base`. A hardcoded `/wiki`
    would break every download there in exchange for fixing Cloud."""
    site = _site()
    site.link_base = None

    units, outcome = _fetch(_connector(site), site)

    assert "/download/attachments/p1-0/notes.txt" in site.paths_requested()
    assert any(unit.origin is ContentOrigin.ATTACHMENT for unit in units)
    assert outcome.failed == 0


def test_an_attachment_that_will_not_download_keeps_scanning_but_is_incomplete() -> None:
    """An unreadable file preserves the page finding and fails reconciliation."""
    site = _site(
        spaces=[
            Space(
                "s1",
                "DOCS",
                "Docs",
                pages=[
                    Page(
                        "p1",
                        "Runbook",
                        leaky_page_storage(),
                        attachments=[Attachment("gone.txt", b"", download_status=404)],
                    )
                ],
            )
        ]
    )

    units, outcome = _fetch(_connector(site), site)

    assert outcome.failed == 1
    assert SEEDED_SECRET in units[0].text  # ...and the page was still scanned


@pytest.mark.parametrize(
    "attachment",
    [
        Attachment("", b"content"),
        Attachment("notes.txt", b"content", include_download_link=False),
    ],
)
def test_an_attachment_missing_download_metadata_is_incomplete(
    attachment: Attachment,
) -> None:
    site = _site(
        spaces=[
            Space(
                "s1",
                "DOCS",
                "Docs",
                pages=[
                    Page(
                        "p1",
                        "Runbook",
                        storage_page("attached"),
                        attachments=[attachment],
                    )
                ],
            )
        ]
    )

    _, outcome = _fetch(_connector(site), site)

    assert (outcome.skipped, outcome.failed) == (0, 1)


def test_attachments_can_be_switched_off() -> None:
    site = _site()
    outcome = FetchOutcome()

    units = list(
        _connector(site).fetch(
            site.connection | {"include_attachments": False},
            TaskSpec(label="space DOCS", params={"space_id": "s1", "space_key": "DOCS"}),
            API_TOKEN,
            outcome,
        )
    )

    assert not any(unit.origin is ContentOrigin.ATTACHMENT for unit in units)
    assert not any("/download/" in path for path in site.paths_requested())


# ─── Failure handling ─────────────────────────────────────────────────────────


def test_a_page_that_errors_mid_space_keeps_scanning_but_is_incomplete() -> None:
    """A scan of fifty thousand pages will meet one that 404s or 500s. It is counted
    and stepped over; the pages on either side of it are still scanned."""
    site = _site(
        spaces=[
            Space(
                "s1",
                "DOCS",
                "Docs",
                pages=[
                    Page("p1", "Fine", leaky_page_storage()),
                    # No body in the list response, and the individual fetch is
                    # refused — so this page cannot be read at all.
                    Page("p2", "Broken", storage_page("hidden"), body_in_list=False),
                    Page("p3", "Also fine", storage_page("clean")),
                ],
            )
        ]
    )
    site.failing_paths = ("/pages/p2",)

    units, outcome = _fetch(_connector(site), site)

    assert [unit.locator.resource_id for unit in units] == ["p1", "p3"]
    assert outcome.failed == 1


def test_a_credential_rejected_mid_fetch_fails_the_task() -> None:
    """Site-wide, not per-page — the per-page handler must not swallow it. Skipping
    would report an auth problem as a scan that found nothing, and every remaining
    page would fail the same way anyway."""
    site = _site()
    site.unauthorized_paths = ("/footer-comments",)

    with pytest.raises(CredentialError):
        _fetch(_connector(site), site)


def test_rate_limiting_mid_scan_is_waited_out() -> None:
    """A scan is exactly the workload that trips a rate limit, so being throttled
    part-way through is the normal case, not a failure."""
    site = _site()
    site.throttle_first, site.retry_after = 3, 0.1
    slept: list[float] = []
    connector = _connector(site, sleep=slept.append)

    _, outcome = _fetch(connector, site)

    assert slept == [0.1, 0.1, 0.1]
    assert outcome.units >= 2


@pytest.mark.parametrize("endpoint", ["/footer-comments", "/download/"])
def test_throttling_past_the_wait_budget_fails_the_task_rather_than_the_page(
    endpoint: str,
) -> None:
    """Comments, attachments, and the body fallback are most of the requests in a
    fetch, and all of them run inside the per-page handler. Counting `RateLimited`
    there as one failed page burns the whole `max_wait_seconds` budget again on the
    next page and the next — a task holding its lease for hours on a site whose
    answer was "come back with fewer engines" (#109)."""
    site = _site()
    site.throttled_paths, site.retry_after = (endpoint,), 30.0
    connector = _connector(
        site, rate_limit=RateLimitPolicy(max_wait_seconds=60.0), sleep=lambda _seconds: None
    )

    with pytest.raises(RateLimited, match="reduce engine concurrency"):
        _fetch(connector, site)


# ─── Extraction isolation (#46) ───────────────────────────────────────────────


def test_the_sandbox_is_per_fetch_and_closed_afterwards() -> None:
    """One connector is shared by every worker thread and an `ExtractionSandbox` is
    not thread-safe, so it cannot live on the connector. Closing matters too: a leaked
    child process per space would accumulate for the life of the worker."""
    made: list[_RecordingSandbox] = []

    def factory() -> Any:
        made.append(_RecordingSandbox())
        return made[-1]

    site = _site()
    connector = _connector(site, sandbox_factory=factory)

    _fetch(connector, site)
    _fetch(connector, site)

    assert len(made) == 2  # ...one per fetch, not one per connector
    assert all(sandbox.closed for sandbox in made)


@pytest.mark.parametrize("phase", ["discover", "fetch"])
def test_one_connection_pool_per_call_released_when_it_ends(
    phase: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A pool per request means a TCP and TLS handshake per page, comment, and
    attachment, and a pool that outlives its call leaks a connection per space for
    the life of the worker (#130)."""
    made = recorded_clients(monkeypatch)
    site = _site()
    connector = _connector(site)

    if phase == "discover":
        list(connector.discover(site.connection, API_TOKEN))
    else:
        _fetch(connector, site)

    assert len(made) == 1
    assert made[0].is_closed


def test_no_child_is_spawned_for_a_space_without_attachments() -> None:
    """A process spawn is ~200ms. Paying it for a space of plain pages is pure cost."""
    made: list[_RecordingSandbox] = []

    def factory() -> Any:
        made.append(_RecordingSandbox())
        return made[-1]

    site = _site(
        spaces=[Space("s1", "DOCS", "Docs", pages=[Page("p1", "Plain", storage_page("text"))])]
    )

    _fetch(_connector(site, sandbox_factory=factory), site)

    assert made == []


class _RecordingSandbox:
    """Stands in for an `ExtractionSandbox`, recording that it was closed."""

    def __init__(self) -> None:
        self.closed = False

    def run(self, function: Any, *args: Any, timeout: float) -> Any:
        return function(*args)

    def close(self) -> None:
        self.closed = True
