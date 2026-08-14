"""The Jira REST client: auth, two paginations, and being refused (#144).

Driven against the fixture site in `jira_server.py` rather than a mock, so the real
header building, token following, and backoff all run. `sleep` is injected, so a
test of five throttled attempts costs no wall-clock.

The recurring theme is **what the client must not assume**: that a page token
advances, that `isLast` is honest, that a 403 means the credential, that an
offset-shaped answer can be paged anyway.
"""

from typing import Any

import pytest
from iceberg_connectors.http import Credential, PermissionDenied, RateLimitPolicy
from iceberg_connectors.jira.client import JiraClient
from iceberg_connectors.protocol import ConnectorError, CredentialError
from jira_server import (
    API_TOKEN,
    EMAIL,
    PAT,
    SITE,
    Change,
    Comment,
    FakeJira,
    Issue,
    Project,
)

ALL_ISSUES = 'project = "ENG" ORDER BY created ASC'


def _client(site: FakeJira, **overrides: Any) -> tuple[JiraClient, list[float]]:
    slept: list[float] = []
    defaults: dict[str, Any] = {
        "base_url": SITE,
        "credential": Credential(token=API_TOKEN, email=EMAIL),
        "transport": site.transport(),
        "sleep": slept.append,
    }
    return JiraClient(**(defaults | overrides)), slept


def _site(issues: int = 5, **overrides: Any) -> FakeJira:
    return FakeJira(
        projects=[
            Project(
                "10000",
                "ENG",
                issues=[
                    Issue(f"1{n:04d}", f"ENG-{n}", created=f"2024-01-{n + 1:02d}T00:00")
                    for n in range(issues)
                ],
            )
        ],
        **overrides,
    )


# ─── Credentials ──────────────────────────────────────────────────────────────


def test_a_cloud_api_token_authenticates_as_basic_with_the_account_email() -> None:
    site = _site()
    client, _ = _client(site)

    list(client.search(ALL_ISSUES))

    assert site.requests[0].headers["authorization"].startswith("Basic ")


def test_a_data_center_pat_authenticates_as_a_bearer() -> None:
    """The Server/DC seam: no email in the blob means the token is a bearer."""
    site = _site(accept_bearer=True)
    client, _ = _client(site, credential=Credential(token=PAT))

    list(client.search(ALL_ISSUES))

    assert site.requests[0].headers["authorization"] == f"Bearer {PAT}"


def test_a_rejected_credential_is_site_wide_and_stops_the_task() -> None:
    site = _site(require_credential=True)
    client, _ = _client(site, credential=Credential(token="wrong", email=EMAIL))

    with pytest.raises(CredentialError, match="rejected the credential"):
        list(client.search(ALL_ISSUES))


def test_the_credential_never_reaches_a_log_line_or_a_repr() -> None:
    credential = Credential(token=API_TOKEN, email=EMAIL)

    assert API_TOKEN not in repr(credential)
    assert API_TOKEN not in str(credential)


# ─── 403 is not 401 ───────────────────────────────────────────────────────────


def test_one_forbidden_issue_raises_permission_denied_not_a_credential_error() -> None:
    """The whole reason Jira needs its own status split.

    Per-project and per-issue permission schemes make a 403 routine. Treating it as
    a credential failure would abort the task and make an ordinary Jira permanently
    partial, which never reconciles.
    """
    site = _site(forbidden_paths=("/comment",))
    client, _ = _client(site)

    with pytest.raises(PermissionDenied, match="refused access"):
        list(client.paginate("/issue/ENG-0/comment", key="comments"))


def test_permission_denied_is_a_connector_error_so_a_connector_can_count_it() -> None:
    assert issubclass(PermissionDenied, ConnectorError)


# ─── Token pagination ─────────────────────────────────────────────────────────


def test_every_issue_arrives_across_pages() -> None:
    site = _site(issues=5)
    client, _ = _client(site)

    found = [issue["key"] for issue in client.search(ALL_ISSUES)]

    assert found == [f"ENG-{n}" for n in range(5)]


def test_the_last_page_is_the_one_without_a_token() -> None:
    site = _site(issues=4, never_last=True)
    client, _ = _client(site)

    # `isLast` is false on every page here, including the last. Absence of a token
    # is the signal that is actually trustworthy.
    assert len(list(client.search(ALL_ISSUES))) == 4


def test_a_page_token_that_never_advances_fails_rather_than_looping() -> None:
    """JRACLOUD-94632: a fresh-looking token that returns page one forever.

    Looping would re-report the same issues until the lease expired; stopping
    quietly would report a clean scan of content never read.
    """
    site = _site(issues=6, repeat_page_token=True)
    client, _ = _client(site)

    with pytest.raises(ConnectorError, match="repeated a search page token"):
        list(client.search(ALL_ISSUES))


def test_the_data_center_offset_shape_is_refused_rather_than_paged_blindly() -> None:
    site = _site(offset_shaped_search=True)
    client, _ = _client(site)

    with pytest.raises(ConnectorError, match="Data Center offset shape"):
        list(client.search(ALL_ISSUES))


def test_search_one_returns_a_single_issue_for_a_window_bound() -> None:
    site = _site(issues=5)
    client, _ = _client(site)

    oldest = client.search_one('project = "ENG" ORDER BY created ASC')
    newest = client.search_one('project = "ENG" ORDER BY created DESC')

    assert oldest is not None and oldest["key"] == "ENG-0"
    assert newest is not None and newest["key"] == "ENG-4"


def test_a_window_bounds_the_issues_returned() -> None:
    site = _site(issues=5)
    client, _ = _client(site)

    windowed = list(
        client.search(
            'project = "ENG" AND created >= "2024-01-02 00:00" '
            'AND created < "2024-01-04 00:00" ORDER BY created ASC'
        )
    )

    assert [issue["key"] for issue in windowed] == ["ENG-1", "ENG-2"]


# ─── Offset pagination ────────────────────────────────────────────────────────


def test_comments_arrive_across_offset_pages() -> None:
    issue = Issue("10001", "ENG-1", comments=[Comment(str(n)) for n in range(5)])
    site = FakeJira(projects=[Project("10000", "ENG", issues=[issue])])
    client, _ = _client(site)

    found = [comment["id"] for comment in client.paginate("/issue/ENG-1/comment", key="comments")]

    assert found == ["0", "1", "2", "3", "4"]


def test_an_offset_collection_terminates_even_when_is_last_never_flips() -> None:
    """JRACLOUD-94648, on the collection shape: `total` and an empty page both end it."""
    issue = Issue("10001", "ENG-1", changes=[Change(str(n)) for n in range(3)])
    site = FakeJira(projects=[Project("10000", "ENG", issues=[issue])], never_last=True)
    client, _ = _client(site)

    assert len(list(client.paginate("/issue/ENG-1/changelog", key="values"))) == 3


def test_an_unexpected_collection_shape_is_refused() -> None:
    site = _site()
    client, _ = _client(site)

    with pytest.raises(ConnectorError, match="unexpected collection shape"):
        list(client.paginate("/myself", key="values"))


# ─── Rate limiting ────────────────────────────────────────────────────────────


def test_a_throttle_is_waited_out_rather_than_failed() -> None:
    site = _site(throttle_first=2, retry_after=3.0)
    client, slept = _client(site)

    assert len(list(client.search(ALL_ISSUES))) == 5
    assert slept == [3.0, 3.0]


def test_a_throttle_does_not_spend_a_retry_attempt() -> None:
    """Otherwise a run of throttles fails with the wrong error long before the wait
    budget is up."""
    site = _site(throttle_first=6, retry_after=1.0)
    client, _ = _client(site, rate_limit=RateLimitPolicy(attempts=2, max_wait_seconds=300.0))

    assert len(list(client.search(ALL_ISSUES))) == 5


def test_a_throttle_past_the_wait_budget_says_to_reduce_concurrency() -> None:
    site = _site(throttled_paths=("/search",), retry_after=30.0)
    client, _ = _client(site, rate_limit=RateLimitPolicy(attempts=20, max_wait_seconds=60.0))

    with pytest.raises(ConnectorError, match="reduce engine concurrency"):
        list(client.search(ALL_ISSUES))


def test_a_failing_endpoint_gives_up_after_the_attempt_budget() -> None:
    site = _site(failing_paths=("/search",))
    client, _ = _client(site, rate_limit=RateLimitPolicy(attempts=3, base_delay_seconds=0.5))

    with pytest.raises(ConnectorError, match="after 3 attempts"):
        list(client.search(ALL_ISSUES))


def test_an_error_never_carries_the_query_string() -> None:
    """JQL and page tokens are content and position; neither belongs in a stored
    error message shown in the UI."""
    site = _site(failing_paths=("/search",))
    client, _ = _client(site, rate_limit=RateLimitPolicy(attempts=1))

    with pytest.raises(ConnectorError) as caught:
        list(client.search(ALL_ISSUES))

    assert "ENG" not in str(caught.value)
    assert "/rest/api/3/search/jql" in str(caught.value)


# ─── Same origin ──────────────────────────────────────────────────────────────


def test_an_off_site_url_is_refused_rather_than_followed() -> None:
    site = _site()
    client, _ = _client(site)

    with pytest.raises(ConnectorError, match="off-site"):
        client.get_json("https://evil.test/rest/api/3/myself")
