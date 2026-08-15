"""Jira checkpoints and `updated`-narrowed discovery (#143).

Two distinct properties, and they fail in opposite directions.

A **checkpoint** must never let a resumed task skip an issue — a skipped issue is a
secret nobody reports. Re-reading one is merely wasteful, so every tie is broken
towards re-reading.

A **cursor** must never let a scan claim to have read more than it did, because the
API mints the next watermark from it. That is why the bound is probed before the
window bounds, and why a project with no issues proposes nothing at all.
"""

from typing import Any

from iceberg_connectors import (
    Checkpoint,
    ConformanceCase,
    FetchOutcome,
    SourceCursor,
    TaskSpec,
    assert_checkpoint_resume,
    assert_incremental_contract,
)
from iceberg_connectors.jira import JiraConnector
from iceberg_connectors.jira.connector import JIRA_CHECKPOINT_VERSION
from jira_server import API_TOKEN, SITE, Comment, FakeJira, Issue, Project, adf, leaky_description

REFERENCE_KEY = b"jira-conformance-reference-key"


def _connector(site: FakeJira, **overrides: Any) -> JiraConnector:
    defaults: dict[str, Any] = {
        "transport": site.transport(),
        "sleep": lambda _seconds: None,
        "sandbox_factory": None,
    }
    return JiraConnector(**(defaults | overrides))


def _connection(**extra: Any) -> dict[str, Any]:
    return {"base_url": SITE, "email": "scanner@example.test", **extra}


def _site(issues: list[Issue]) -> FakeJira:
    return FakeJira(projects=[Project("10000", "ENG", issues=issues)])


def _issues(count: int, *, day: int = 1, updated: str = "") -> list[Issue]:
    return [
        Issue(
            f"1000{n}",
            f"ENG-{n}",
            created=f"2024-01-{day + n:02d}T00:00",
            updated=updated,
            description=leaky_description(),
        )
        for n in range(count)
    ]


def _discover(site: FakeJira, cursors: dict[str, Any] | None = None) -> list[TaskSpec]:
    return list(_connector(site).discover(_connection(), API_TOKEN, cursors=cursors))


def _fetch(site: FakeJira, spec: TaskSpec, **kwargs: Any) -> tuple[list[Any], FetchOutcome]:
    outcome = FetchOutcome(reference_key=REFERENCE_KEY, **kwargs)
    units = list(_connector(site).fetch(_connection(), spec, API_TOKEN, outcome))
    return units, outcome


# ─── Discovery without a watermark is unchanged ───────────────────────────────


def test_a_full_scan_still_windows_on_created() -> None:
    specs = _discover(_site(_issues(3)))

    assert all(spec.params["window"]["field"] == "created" for spec in specs)


def test_every_spec_of_a_project_carries_the_same_cursor_bound() -> None:
    """So whichever task reports last proposes the same watermark as the rest.

    Discovery slices a project into many windows; each of their fetch tasks ends
    by proposing a cursor. If they proposed different values the stored watermark
    would depend on completion order, and an earlier window winning would silently
    under-advance it.
    """
    specs = _discover(_site(_issues(3, day=1)))

    bounds = {spec.params["cursor_at"] for spec in specs}
    assert len(bounds) == 1


def test_a_project_with_no_issues_proposes_no_watermark() -> None:
    """There is nothing to have read, so there is nothing to claim."""
    specs = _discover(_site([]))

    assert [spec.params.get("cursor_at") for spec in specs] == [None]


# ─── Discovery with a watermark ───────────────────────────────────────────────


def test_a_watermark_narrows_a_project_to_one_updated_window() -> None:
    site = _site(_issues(3, updated="2024-05-01T09:00"))

    specs = _discover(site, {"ENG": {"updated": "2024-03-01 00:00"}})

    assert len(specs) == 1
    assert specs[0].params["window"] == {
        "field": "updated",
        "from": "2024-03-01 00:00",
        "to": "2024-05-01 09:01",
    }


def test_a_project_with_nothing_edited_since_the_watermark_yields_no_spec() -> None:
    """The point of an incremental scan, and the reason it must never reconcile."""
    site = _site(_issues(3, updated="2024-01-05T09:00"))

    assert _discover(site, {"ENG": {"updated": "2024-06-01 00:00"}}) == []


def test_a_project_with_no_watermark_is_still_covered_in_full() -> None:
    """A project added between scans has never been read; nothing says otherwise."""
    site = FakeJira(
        projects=[
            Project("10000", "ENG", issues=_issues(2)),
            Project("10001", "OPS", issues=_issues(2)),
        ]
    )

    specs = _discover(site, {"ENG": {"updated": "2024-06-01 00:00"}})

    assert {spec.params["project_key"] for spec in specs} == {"OPS"}
    assert all(spec.params["window"]["field"] == "created" for spec in specs)


def test_incremental_discovery_is_deterministic_and_a_subset_of_a_full_scan() -> None:
    site = _site(_issues(3, updated="2024-05-01T09:00"))

    assert_incremental_contract(
        ConformanceCase(
            connector=_connector(site),
            connection=_connection(),
            credential=API_TOKEN,
            reference_key=REFERENCE_KEY,
            secret_sentinels=(API_TOKEN,),
        ),
        {"ENG": {"updated": "2024-03-01 00:00"}},
    )


def test_a_malformed_watermark_is_ignored_rather_than_trusted() -> None:
    """Scanning everything is always correct. Splicing junk into JQL is not."""
    site = _site(_issues(3))

    junk: list[dict[str, Any]] = [{"ENG": "not a mapping"}, {"ENG": {}}, {"ENG": {"updated": 7}}]
    for cursors in junk:
        specs = _discover(site, cursors)
        assert all(spec.params["window"]["field"] == "created" for spec in specs)


# ─── Fetch: the cursor proposal ───────────────────────────────────────────────


def test_the_proposed_watermark_sits_a_minute_behind_the_window_end() -> None:
    """JQL resolves to the minute, so an edit at 09:00:45 is indistinguishable from
    one at 09:00:10. The window must *end* at 09:01 for the newest issue to be
    inside it; the next scan must *start* at 09:00 and re-read that minute, or an
    edit landing after the probe falls between the two scans and neither reads it.
    """
    site = _site(_issues(2, updated="2024-05-01T09:00"))
    spec = _discover(site)[0]

    _units, outcome = _fetch(site, spec)

    assert outcome.cursor == SourceCursor(
        "ENG", JIRA_CHECKPOINT_VERSION, {"updated": "2024-05-01 09:00"}
    )


def test_the_next_scan_re_reads_the_watermark_minute() -> None:
    """Which is what makes the overlap above worth having."""
    site = _site(_issues(2, updated="2024-05-01T09:00"))

    narrowed = _discover(site, {"ENG": {"updated": "2024-05-01 09:00"}})

    assert len(narrowed) == 1
    assert narrowed[0].params["window"] == {
        "field": "updated",
        "from": "2024-05-01 09:00",
        "to": "2024-05-01 09:01",
    }


def test_a_spec_without_a_bound_proposes_nothing() -> None:
    _units, outcome = _fetch(
        _site(_issues(1)), TaskSpec(label="ENG", params={"project_key": "ENG"})
    )

    assert outcome.cursor is None


# ─── Fetch: checkpoints ───────────────────────────────────────────────────────


def test_a_checkpoint_is_published_only_once_an_issue_is_finished() -> None:
    """Comments and attachments belong to the issue that owns them.

    A boundary between an issue's body and its comments would let a resumed
    attempt start at the next issue and never read those comments.
    """
    site = _site(
        [
            Issue(
                "10001",
                "ENG-1",
                created="2024-01-01T00:00",
                description=leaky_description(),
                comments=[Comment("900", adf("a comment"))],
            )
        ]
    )
    spec = _discover(site)[0]
    outcome = FetchOutcome(reference_key=REFERENCE_KEY)

    seen = [
        (unit.origin.value, outcome.checkpoint)
        for unit in _connector(site).fetch(_connection(), spec, API_TOKEN, outcome)
    ]

    assert [origin for origin, _ in seen] == ["body", "comment"]
    assert all(point is None for _origin, point in seen)
    assert outcome.checkpoint is not None
    assert outcome.checkpoint.position["seen"] == ["10001"]


def test_resuming_skips_the_issues_the_last_attempt_finished() -> None:
    site = _site(_issues(3))
    spec = _discover(site)[0]

    _units, outcome = _fetch(
        site,
        spec,
        resume_from=Checkpoint(
            JIRA_CHECKPOINT_VERSION,
            {"field": "created", "at": "2024-01-02 00:00", "seen": ["10001"]},
        ),
    )

    assert outcome.as_coverage()["counts"]["scanned"] == 1


def test_an_unread_issue_in_the_boundary_minute_is_not_skipped_by_its_id() -> None:
    """The tie-break must rest on evidence, not on an ordering Jira never promises.

    An earlier version compared numeric ids, assuming a lower id was read first.
    JQL orders on the date alone, so within a minute the order is unspecified: the
    issue with the *lower* id here is delivered second and was never read, yet an
    id comparison would skip it. Only the ids the attempt recorded finishing are
    evidence of anything.
    """
    site = _site(
        [
            Issue("10009", "ENG-9", created="2024-01-01T00:00", description=leaky_description()),
            Issue("10001", "ENG-1", created="2024-01-01T00:00", description=leaky_description()),
        ]
    )
    spec = _discover(site)[0]

    _units, outcome = _fetch(
        site,
        spec,
        # The attempt finished 10009 only. 10001 sorts lower but was never read.
        resume_from=Checkpoint(
            JIRA_CHECKPOINT_VERSION,
            {"field": "created", "at": "2024-01-01 00:00", "seen": ["10009"]},
        ),
    )

    scanned = [unit.locator.resource_id for unit in _units]
    assert "10001" in scanned
    assert outcome.as_coverage()["counts"]["scanned"] == 1


def test_the_boundary_minute_is_re_queried_so_its_unfinished_issues_return() -> None:
    """Both issues share a minute; one was finished, one was not."""
    site = _site(
        [
            Issue("10001", "ENG-1", created="2024-01-01T00:00", description=leaky_description()),
            Issue("10002", "ENG-2", created="2024-01-01T00:00", description=leaky_description()),
        ]
    )
    spec = _discover(site)[0]

    _units, _outcome = _fetch(
        site,
        spec,
        resume_from=Checkpoint(
            JIRA_CHECKPOINT_VERSION,
            {"field": "created", "at": "2024-01-01 00:00", "seen": ["10001"]},
        ),
    )

    assert [unit.locator.resource_id for unit in _units] == ["10002"]


def test_a_checkpoint_from_the_other_date_field_is_refused() -> None:
    """A `created` position cannot bound an `updated` window: the two orderings
    have nothing to do with each other, so resuming across them would skip
    whatever sorts earlier under the new field."""
    site = _site(_issues(3, updated="2024-05-01T09:00"))
    spec = _discover(site, {"ENG": {"updated": "2024-03-01 00:00"}})[0]

    _units, outcome = _fetch(
        site,
        spec,
        resume_from=Checkpoint(
            JIRA_CHECKPOINT_VERSION,
            {"field": "created", "at": "2024-01-02 00:00", "seen": ["10001"]},
        ),
    )

    assert outcome.as_coverage()["counts"]["scanned"] == 3


def test_a_checkpoint_from_an_unknown_version_restarts_the_spec() -> None:
    site = _site(_issues(3))
    spec = _discover(site)[0]

    _units, outcome = _fetch(
        site,
        spec,
        resume_from=Checkpoint(
            "99", {"field": "created", "at": "2024-01-02 00:00", "seen": ["10001"]}
        ),
    )

    assert outcome.as_coverage()["counts"]["scanned"] == 3


def test_the_connector_satisfies_the_published_resume_contract() -> None:
    site = _site(_issues(6))

    assert_checkpoint_resume(
        ConformanceCase(
            connector=_connector(site),
            connection=_connection(),
            credential=API_TOKEN,
            reference_key=REFERENCE_KEY,
            secret_sentinels=(API_TOKEN,),
        )
    )
