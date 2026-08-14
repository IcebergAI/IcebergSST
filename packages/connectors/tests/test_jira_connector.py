"""The Jira connector: windows, dispositions, and being refused (#144).

Driven against the fixture site in `jira_server.py`, so discovery really probes for
window bounds and fetch really pages. The recurring themes are **every enumerated
object gets exactly one disposition**, **unread is never empty**, and **one
restricted issue does not end the scan**.
"""

from typing import Any

import pytest
from iceberg_connectors import ConformanceCase, assert_connector_conformance
from iceberg_connectors.jira import JiraConnector
from iceberg_connectors.jira.connector import MAX_HISTORY_ENTRIES
from iceberg_connectors.protocol import ConnectorError, CredentialError, FetchOutcome, TaskSpec
from iceberg_connectors.units import GLOB_FRIENDLY_KEYS
from jira_server import (
    API_TOKEN,
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


def _fetch(site: FakeJira, spec: TaskSpec, **connection: Any) -> tuple[list[Any], FetchOutcome]:
    outcome = FetchOutcome(reference_key=REFERENCE_KEY)
    units = list(_connector(site).fetch(_connection(**connection), spec, API_TOKEN, outcome))
    return units, outcome


def _spec(key: str = "ENG") -> TaskSpec:
    return TaskSpec(label=key, params={"project_key": key})


def _one_issue(**issue: Any) -> FakeJira:
    return FakeJira(projects=[Project("10000", "ENG", issues=[Issue("10001", "ENG-1", **issue)])])


# ─── Discovery ────────────────────────────────────────────────────────────────


def test_a_project_becomes_one_spec_per_created_window() -> None:
    site = FakeJira(
        projects=[
            Project(
                "10000",
                "ENG",
                issues=[
                    Issue(f"1{n:04d}", f"ENG-{n}", created=f"2024-01-{n + 1:02d}T00:00")
                    for n in range(30)
                ],
            )
        ]
    )

    specs = list(_connector(site).discover(_connection(), API_TOKEN))

    # A 30-day span at the ladder's first rung of 7 days.
    assert len(specs) == 5
    assert all(spec.params["project_key"] == "ENG" for spec in specs)
    # Contiguous and half-open, so a boundary shift cannot open a hole.
    edges = [spec.params["window"] for spec in specs]
    assert edges[0]["from"] is None
    assert all(edges[n]["to"] == edges[n + 1]["from"] for n in range(len(edges) - 1))


def test_discovery_is_deterministic_for_an_unchanged_site() -> None:
    """The conformance kit runs discover twice and compares payloads.

    Window bounds therefore come from the project's own oldest and newest issue,
    never from the clock.
    """
    site = FakeJira(
        projects=[
            Project(
                "10000",
                "ENG",
                issues=[Issue("1", "ENG-1", created="2020-03-04T05:06")],
            )
        ]
    )
    connector = _connector(site)

    first = [spec.as_payload() for spec in connector.discover(_connection(), API_TOKEN)]
    second = [spec.as_payload() for spec in connector.discover(_connection(), API_TOKEN)]

    assert first == second


def test_the_upper_bound_is_pinned_to_the_minute_discovery_saw() -> None:
    """Rounding up to the next midnight would readmit the rest of that day."""
    site = FakeJira(
        projects=[Project("10000", "ENG", issues=[Issue("1", "ENG-1", created="2024-05-06T09:00")])]
    )

    specs = list(_connector(site).discover(_connection(), API_TOKEN))

    assert specs[-1].params["window"]["to"] == "2024-05-06 09:01"


def test_an_issue_filed_after_discovery_does_not_join_a_frozen_spec() -> None:
    """A spec is persisted and fetched later, so its bound must mean what it said.

    The failure this guards is a scan reporting content it never planned to cover,
    under a window an operator was told was point-in-time.
    """
    site = FakeJira(
        projects=[Project("10000", "ENG", issues=[Issue("1", "ENG-1", created="2024-05-06T09:00")])]
    )
    spec = list(_connector(site).discover(_connection(), API_TOKEN))[-1]

    # Filed the same day, after discovery froze the spec.
    site.projects[0].issues.append(Issue("2", "ENG-2", created="2024-05-06T14:00"))

    outcome = FetchOutcome(reference_key=REFERENCE_KEY)
    list(_connector(site).fetch(_connection(), spec, API_TOKEN, outcome))

    assert outcome.coverage.discovered == 1


def test_a_project_with_no_issues_still_produces_one_enumerated_scope() -> None:
    site = FakeJira(projects=[Project("10000", "ENG")])

    specs = list(_connector(site).discover(_connection(), API_TOKEN))

    assert len(specs) == 1
    assert specs[0].params["project_key"] == "ENG"


def test_a_configured_project_that_is_not_there_fails_closed() -> None:
    """Otherwise a scan of a mistyped project silently auto-resolves its findings."""
    site = FakeJira(projects=[Project("10000", "ENG", issues=[Issue("1", "ENG-1")])])

    with pytest.raises(ConnectorError, match="were not found"):
        list(_connector(site).discover(_connection(projects=["ENG", "NOPE"]), API_TOKEN))


def test_a_malformed_project_key_fails_closed_rather_than_reaching_jql() -> None:
    site = FakeJira(projects=[Project("10000", 'ENG" OR project = "OPS')])

    with pytest.raises(ConnectorError, match="malformed or duplicate"):
        list(_connector(site).discover(_connection(), API_TOKEN))


def test_archived_projects_are_out_of_scope_unless_asked_for() -> None:
    site = FakeJira(
        projects=[
            Project("10000", "ENG", issues=[Issue("1", "ENG-1")]),
            Project("10001", "OLD", archived=True, issues=[Issue("2", "OLD-1")]),
        ]
    )

    keys = {s.params["project_key"] for s in _connector(site).discover(_connection(), API_TOKEN)}

    assert keys == {"ENG"}


def test_archived_projects_are_discovered_when_the_operator_opts_in() -> None:
    """Jira's project search defaults to live-only, so archived projects have to be
    *asked* for. Filtering the response locally cannot include what was never sent."""
    site = FakeJira(
        projects=[
            Project("10000", "ENG", issues=[Issue("1", "ENG-1")]),
            Project("10001", "OLD", archived=True, issues=[Issue("2", "OLD-1")]),
        ]
    )

    specs = _connector(site).discover(_connection(include_archived_projects=True), API_TOKEN)

    assert {s.params["project_key"] for s in specs} == {"ENG", "OLD"}


def test_project_discovery_always_states_which_statuses_it_wants() -> None:
    """Relying on the server's default would make the scope depend on the server."""
    site = FakeJira(projects=[Project("10000", "ENG", issues=[Issue("1", "ENG-1")])])

    list(_connector(site).discover(_connection(), API_TOKEN))

    search = next(r for r in site.requests if "/project/search" in r.url.path)
    assert search.url.params.get_list("status") == ["live"]


def test_a_spec_never_carries_a_credential() -> None:
    site = FakeJira(projects=[Project("10000", "ENG", issues=[Issue("1", "ENG-1")])])

    payloads = [s.as_payload() for s in _connector(site).discover(_connection(), API_TOKEN)]

    assert API_TOKEN not in str(payloads)


# ─── Bodies ───────────────────────────────────────────────────────────────────


def test_summary_description_and_environment_become_one_scanned_unit() -> None:
    site = _one_issue(summary="deploy notes", description=leaky_description())

    units, outcome = _fetch(site, _spec())

    assert len(units) == 1
    assert SEEDED_SECRET in units[0].text
    assert "deploy notes" in units[0].text
    assert outcome.as_counts()["units"] == 1


def test_an_unread_body_field_fails_the_issue_and_yields_nothing() -> None:
    """A partial body would let the missing part reconcile an older finding."""
    site = _one_issue(include_description=False, summary="has a summary")

    units, outcome = _fetch(site, _spec())

    assert units == []
    assert outcome.as_counts()["units_failed"] == 1


def test_an_explicitly_empty_issue_is_skipped_not_failed() -> None:
    site = _one_issue(summary="", description=None, environment=None)

    units, outcome = _fetch(site, _spec())

    assert units == []
    assert outcome.as_counts()["units_skipped"] == 1


def test_a_body_locator_is_the_numeric_issue_id_so_a_move_keeps_the_finding() -> None:
    """The key changes when an issue moves project; the id does not (ADR 0006)."""
    site = _one_issue(description=adf(SEEDED_SECRET))

    units, _ = _fetch(site, _spec())

    assert units[0].locator.connector_type == "jira"
    assert units[0].locator.resource_id == "10001"
    assert units[0].locator.sub_resource is None


def test_display_carries_a_glob_friendly_path_so_a_suppression_can_scope_it() -> None:
    site = _one_issue(description=adf(SEEDED_SECRET))

    units, _ = _fetch(site, _spec())

    assert any(key in units[0].display for key in GLOB_FRIENDLY_KEYS)
    assert units[0].display["path"] == "ENG/ENG-1"


# ─── Comments, attachments, history ───────────────────────────────────────────


def test_comments_are_scanned_under_a_stable_sub_resource() -> None:
    site = _one_issue(description=adf("x"), comments=[Comment("900", adf(SEEDED_SECRET))])

    units, _ = _fetch(site, _spec())

    comment = next(u for u in units if u.origin.value == "comment")
    assert comment.locator.sub_resource == "comment:900"
    assert SEEDED_SECRET in comment.text


def test_a_comment_without_a_body_is_failed_rather_than_treated_as_empty() -> None:
    site = _one_issue(description=adf("x"), comments=[Comment("900", include_body=False)])

    _units, outcome = _fetch(site, _spec())

    assert outcome.as_counts()["units_failed"] == 1


def test_an_attachment_is_extracted_under_its_filename() -> None:
    site = _one_issue(
        description=adf("x"),
        attachments=[Attachment("55", "creds.txt", body=f"key={SEEDED_SECRET}".encode())],
    )

    units, _ = _fetch(site, _spec())

    attachment = next(u for u in units if u.origin.value == "attachment")
    assert attachment.locator.sub_resource == "attachment:creds.txt"
    assert SEEDED_SECRET in attachment.text


def test_an_attachment_larger_than_the_cap_is_failed_without_downloading_it() -> None:
    site = _one_issue(
        description=adf("x"),
        attachments=[Attachment("55", "huge.txt", body=b"x", declared_size=10**12)],
    )

    _units, outcome = _fetch(site, _spec())

    assert outcome.as_counts()["units_failed"] == 1
    assert not any("/secure/attachment/" in path for path in site.paths_requested())


def test_history_is_off_unless_the_operator_opts_in() -> None:
    site = _one_issue(
        description=adf("x"),
        changes=[Change("77", to_string=SEEDED_SECRET)],
    )

    units, _ = _fetch(site, _spec())

    assert all("history" not in str(u.locator.sub_resource) for u in units)


def test_history_scans_a_value_that_was_set_and_later_removed() -> None:
    """The reason history is worth an opt-in at all."""
    site = _one_issue(
        description=adf("clean now"),
        changes=[Change("77", to_string=SEEDED_SECRET), Change("78", from_string=SEEDED_SECRET)],
    )

    units, _ = _fetch(site, _spec(), include_history=True)

    history = [u for u in units if str(u.locator.sub_resource).startswith("history:")]
    assert history
    assert any(SEEDED_SECRET in u.text for u in history)


def test_a_value_is_not_reported_twice_from_both_sides_of_a_transition() -> None:
    """Entry N's `fromString` repeats entry N-1's `toString`.

    Scanning both would mint two findings under two locators for one credential.
    """
    site = _one_issue(
        description=adf("clean"),
        changes=[Change("77", to_string=SEEDED_SECRET), Change("78", from_string=SEEDED_SECRET)],
    )

    units, _ = _fetch(site, _spec(), include_history=True)

    carrying = [u for u in units if SEEDED_SECRET in u.text]
    assert len(carrying) == 1


def test_the_creation_time_value_is_still_covered_by_the_first_from_string() -> None:
    site = _one_issue(
        description=adf("clean"),
        changes=[Change("77", from_string=SEEDED_SECRET, to_string="redacted")],
    )

    units, _ = _fetch(site, _spec(), include_history=True)

    assert any(SEEDED_SECRET in u.text for u in units)


def test_history_past_the_entry_cap_becomes_a_gap_rather_than_a_silent_truncation() -> None:
    site = _one_issue(
        description=adf("x"),
        changes=[Change(str(n), to_string=f"v{n}") for n in range(MAX_HISTORY_ENTRIES + 5)],
    )

    _units, outcome = _fetch(site, _spec(), include_history=True)

    assert outcome.coverage.scope_gaps == 1


# ─── Being refused ────────────────────────────────────────────────────────────


def test_one_forbidden_comment_collection_becomes_a_gap_and_the_scan_continues() -> None:
    """The behaviour that separates Jira from Confluence.

    Per-issue permissions make this routine; aborting would make an ordinary Jira
    permanently partial and it would never reconcile.
    """
    site = FakeJira(
        projects=[
            Project(
                "10000",
                "ENG",
                issues=[
                    Issue("10001", "ENG-1", description=leaky_description()),
                    Issue("10002", "ENG-2", description=adf("second")),
                ],
            )
        ],
        forbidden_paths=("/comment",),
    )

    units, outcome = _fetch(site, _spec())

    # Both issue bodies still scanned.
    assert len([u for u in units if u.origin.value == "body"]) == 2
    assert outcome.coverage.scope_gaps == 2


def test_a_rejected_credential_stops_the_task_rather_than_being_counted_per_issue() -> None:
    site = FakeJira(
        projects=[Project("10000", "ENG", issues=[Issue("10001", "ENG-1")])],
        unauthorized_paths=("/search",),
    )
    outcome = FetchOutcome(reference_key=REFERENCE_KEY)

    with pytest.raises(CredentialError):
        list(_connector(site).fetch(_connection(), _spec(), API_TOKEN, outcome))


def test_a_fetch_spec_without_a_usable_project_key_is_refused() -> None:
    site = _one_issue()
    outcome = FetchOutcome(reference_key=REFERENCE_KEY)

    with pytest.raises(ConnectorError, match="no usable project key"):
        list(
            _connector(site).fetch(
                _connection(),
                TaskSpec(label="x", params={"project_key": 'A" OR "1'}),
                None,
                outcome,
            )
        )


# ─── Conformance ──────────────────────────────────────────────────────────────


def test_the_jira_connector_satisfies_the_published_sdk_contract() -> None:
    site = FakeJira(
        projects=[
            Project(
                "10000",
                "ENG",
                issues=[
                    Issue(
                        "10001",
                        "ENG-1",
                        description=leaky_description(),
                        comments=[Comment("900", adf("a comment"))],
                    ),
                    Issue("10002", "ENG-2", include_description=False),
                ],
            )
        ]
    )

    payload = assert_connector_conformance(
        ConformanceCase(
            connector=_connector(site),
            connection=_connection(),
            credential=API_TOKEN,
            reference_key=REFERENCE_KEY,
            secret_sentinels=(API_TOKEN, SEEDED_SECRET),
        )
    )

    metadata = payload["metadata"]
    assert isinstance(metadata, dict)
    assert metadata["connector_type"] == "jira"
    # Reserved for #143 until the resumable-scan contract exists.
    assert "checkpoints" not in metadata["capabilities"]
