"""Confluence checkpoints and watermark-narrowed enumeration (#143).

Confluence resumes on worse terms than Jira does, and the tests say so rather than
hiding it. Its v2 cursor is opaque and followed verbatim, so a position cannot be
stored and replayed; what is stored is the last page id, and resuming means
re-enumerating the listing until it turns up. The listing calls are paid again; the
bodies, comments and attachments are not.

There is also no ``lastModified`` on a v2 page. ``version.createdAt`` is the only
"when did this change" signal the API offers, which means a page whose ``version``
is absent has an *unknown* revision — and unknown must always mean scan it.
"""

from typing import Any

from confluence_server import API_TOKEN, EMAIL, SITE, FakeConfluence, Page, Space
from iceberg_connectors import (
    Checkpoint,
    ConformanceCase,
    FetchOutcome,
    SourceCursor,
    TaskSpec,
    assert_checkpoint_resume,
    assert_incremental_contract,
)
from iceberg_connectors.confluence import ConfluenceConnector
from iceberg_connectors.confluence.connector import CONFLUENCE_CHECKPOINT_VERSION

REFERENCE_KEY = b"confluence-conformance-reference-key"
LEAKY = "<p>aws_access_key_id = AKIAIOSFODNN7EXAMPLE</p>"


def _connector(site: FakeConfluence) -> ConfluenceConnector:
    return ConfluenceConnector(
        transport=site.transport(), sleep=lambda _seconds: None, sandbox_factory=None
    )


def _connection(**extra: Any) -> dict[str, Any]:
    return {"base_url": f"{SITE}/wiki", "email": EMAIL, **extra}


def _pages(count: int, *, day: int = 1) -> list[Page]:
    return [
        Page(
            id=f"page-{n}",
            title=f"Page {n}",
            storage=LEAKY,
            version_created_at=f"2024-01-{day + n:02d}T00:00:00.000Z",
        )
        for n in range(count)
    ]


def _site(pages: list[Page]) -> FakeConfluence:
    return FakeConfluence(spaces=[Space(id="1", key="DOCS", name="Docs", pages=pages)])


def _discover(site: FakeConfluence, cursors: dict[str, Any] | None = None) -> list[TaskSpec]:
    return list(_connector(site).discover(_connection(), API_TOKEN, cursors=cursors))


def _fetch(site: FakeConfluence, spec: TaskSpec, **kwargs: Any) -> tuple[list[Any], FetchOutcome]:
    outcome = FetchOutcome(reference_key=REFERENCE_KEY, **kwargs)
    units = list(_connector(site).fetch(_connection(), spec, API_TOKEN, outcome))
    return units, outcome


# ─── The watermark reaches the server ─────────────────────────────────────────


def test_a_full_scan_asks_for_no_ordering_at_all() -> None:
    """It reads everything either way, so an order it does not need is one more
    thing the site could refuse."""
    site = _site(_pages(3))

    _fetch(site, _discover(site)[0])

    assert site.sorts_requested == []


def test_a_watermarked_scan_asks_the_server_to_sort() -> None:
    """The opt-in has to reach the server: a page enumeration the site returned in
    its own order cannot be stopped early, because "older" would mean nothing."""
    site = _site(_pages(3))
    spec = _discover(site, {"DOCS": {"modified": "2024-01-02T00:00:00.000Z"}})[0]

    _fetch(site, spec)

    assert set(site.sorts_requested) == {"-modified-date"}


def test_enumeration_stops_at_the_watermark() -> None:
    site = _site(_pages(4))
    spec = _discover(site, {"DOCS": {"modified": "2024-01-02T00:00:00.000Z"}})[0]

    _units, outcome = _fetch(site, spec)

    # Pages 2 and 3 are newer than the watermark; 0 and 1 are at or below it.
    assert outcome.as_coverage()["counts"]["scanned"] == 2


def test_a_page_the_site_will_not_date_abandons_the_narrowing_entirely() -> None:
    """Unknown is not evidence that a page is unchanged.

    Stopping early relies on the ordering meaning "newest first", and a page with
    no revision has no place in that order — so the rest of the space could be
    anywhere in it. The connector gives up the narrowing and reads all of it.
    Paying for a full scan is a bad trade; skipping content silently is worse.
    """
    pages = _pages(2)
    # Dated by the site (so it sorts first) but not reported to us, which is the
    # realistic shape of the problem: the site knows, and will not say.
    pages.insert(
        0,
        Page(
            id="page-9",
            title="Undated",
            storage=LEAKY,
            version_created_at="2024-12-01T00:00:00.000Z",
            include_version=False,
        ),
    )
    site = _site(pages)
    spec = _discover(site, {"DOCS": {"modified": "2024-09-01T00:00:00.000Z"}})[0]

    _units, outcome = _fetch(site, spec)

    assert outcome.as_coverage()["counts"]["scanned"] == 3


def test_a_space_with_no_watermark_carries_no_since_on_its_spec() -> None:
    specs = _discover(_site(_pages(2)))

    assert "since" not in specs[0].params


def test_incremental_discovery_is_deterministic_and_a_subset_of_a_full_scan() -> None:
    site = _site(_pages(3))

    assert_incremental_contract(
        ConformanceCase(
            connector=_connector(site),
            connection=_connection(),
            credential=API_TOKEN,
            reference_key=REFERENCE_KEY,
            secret_sentinels=(API_TOKEN,),
        ),
        {"DOCS": {"modified": "2024-01-02T00:00:00.000Z"}},
    )


# ─── Cursor proposals ─────────────────────────────────────────────────────────


def test_a_scanned_space_proposes_its_newest_revision() -> None:
    site = _site(_pages(3))

    _units, outcome = _fetch(site, _discover(site)[0])

    assert outcome.cursor == SourceCursor(
        "DOCS", CONFLUENCE_CHECKPOINT_VERSION, {"modified": "2024-01-03T00:00:00.000Z"}
    )


def test_a_space_whose_pages_carry_no_version_proposes_nothing() -> None:
    """Nothing to compare against next time, so claiming a watermark would be a
    claim the connector cannot honour."""
    site = _site([Page(id="page-0", title="P", storage=LEAKY, include_version=False)])

    _units, outcome = _fetch(site, _discover(site)[0])

    assert outcome.cursor is None


# ─── Checkpoints ──────────────────────────────────────────────────────────────


def test_a_checkpoint_is_published_only_once_a_page_is_finished() -> None:
    site = _site(_pages(2))
    spec = _discover(site)[0]
    outcome = FetchOutcome(reference_key=REFERENCE_KEY)

    first = next(iter(_connector(site).fetch(_connection(), spec, API_TOKEN, outcome)))

    assert first.locator.resource_id == "page-0"
    assert outcome.checkpoint is None


def test_resuming_re_enumerates_but_re_reads_nothing() -> None:
    """The listing calls are paid again because the cursor cannot be replayed. The
    bodies are not, which is what the position is actually worth."""
    site = _site(_pages(4))
    spec = _discover(site)[0]

    _units, outcome = _fetch(
        site,
        spec,
        resume_from=Checkpoint(CONFLUENCE_CHECKPOINT_VERSION, {"after_page": "page-1"}),
    )

    assert outcome.as_coverage()["counts"]["scanned"] == 2


def test_a_resume_page_that_no_longer_exists_is_a_scope_gap() -> None:
    """The page was deleted between attempts, so the enumeration ran to the end
    and scanned nothing. Reporting that as a clean space would auto-resolve every
    finding in it."""
    site = _site(_pages(3))
    spec = _discover(site)[0]

    _units, outcome = _fetch(
        site,
        spec,
        resume_from=Checkpoint(CONFLUENCE_CHECKPOINT_VERSION, {"after_page": "page-gone"}),
    )

    assert outcome.as_coverage()["counts"]["scanned"] == 0
    assert outcome.as_coverage()["scope"]["gaps"] == 1
    assert outcome.cursor is None


def test_a_checkpoint_from_an_unknown_version_restarts_the_space() -> None:
    site = _site(_pages(3))
    spec = _discover(site)[0]

    _units, outcome = _fetch(site, spec, resume_from=Checkpoint("99", {"after_page": "page-1"}))

    assert outcome.as_coverage()["counts"]["scanned"] == 3


def test_the_connector_satisfies_the_published_resume_contract() -> None:
    site = _site(_pages(6))

    assert_checkpoint_resume(
        ConformanceCase(
            connector=_connector(site),
            connection=_connection(),
            credential=API_TOKEN,
            reference_key=REFERENCE_KEY,
            secret_sentinels=(API_TOKEN,),
        )
    )
