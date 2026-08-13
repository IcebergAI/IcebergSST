"""The cluster screens (#140): explicit-query redirect, grouping, and the badge.

The web invariants (no ORM in `iceberg_api.web`, CSRF, CSP) are asserted by the
shared suites; this file covers what is specific to these two screens.
"""

import secrets
from collections.abc import Callable
from typing import Any

import pytest
from fastapi.testclient import TestClient
from iceberg_core.correlation import correlation_id
from iceberg_core.enums import FindingState, UserRole
from iceberg_core.models import Finding, Source, User

KEY = secrets.token_bytes(32)
HASH = "d4" * 32
CLUSTER = correlation_id(HASH, key=KEY)


@pytest.fixture(name="spread")
def spread_fixture(
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
) -> dict[str, Any]:
    wiki = make_source(name="confluence-wiki")
    share = make_source(name="finance-share")
    return {
        "in_wiki": make_finding(wiki, secret_hash=HASH, correlation_id=CLUSTER),
        "in_share": make_finding(
            share, secret_hash=HASH, correlation_id=CLUSTER, state=FindingState.RESOLVED
        ),
        "alone": make_finding(wiki, correlation_id=correlation_id("e5" * 32, key=KEY)),
    }


@pytest.fixture(name="as_analyst")
def as_analyst_fixture(
    make_user: Callable[..., User], login_as: Callable[[User], dict[str, str]]
) -> dict[str, str]:
    return login_as(make_user(UserRole.ANALYST))


def test_the_bare_url_redirects_into_an_explicit_query(
    client: TestClient, as_analyst: dict[str, str]
) -> None:
    """The default view is a redirect, not a hidden server-side filter — the URL
    always says what the table shows (docs/web.md)."""
    response = client.get("/clusters", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/clusters?min_findings=2"


def test_the_spread_view_lists_only_multi_finding_clusters(
    client: TestClient, spread: dict[str, Any], as_analyst: dict[str, str]
) -> None:
    body = client.get("/clusters?min_findings=2").text

    assert CLUSTER[:12] in body
    assert spread["alone"].correlation_id[:12] not in body

    everything = client.get("/clusters?min_findings=1").text
    assert spread["alone"].correlation_id[:12] in everything


def test_the_detail_groups_members_by_source_with_states(
    client: TestClient, spread: dict[str, Any], as_analyst: dict[str, str]
) -> None:
    body = client.get(f"/clusters/{CLUSTER}").text

    assert "confluence-wiki" in body
    assert "finance-share" in body
    # Per-location remediation state is the point of the topology view.
    assert "state-open" in body
    assert "state-resolved" in body
    assert f"/api/v1/correlation/clusters/{CLUSTER}/export" in body


def test_no_secret_material_reaches_the_page(
    client: TestClient, spread: dict[str, Any], as_analyst: dict[str, str]
) -> None:
    for path in ("/clusters?min_findings=1", f"/clusters/{CLUSTER}"):
        body = client.get(path).text
        assert HASH not in body, path
        assert "secret_hash" not in body, path


def test_finding_detail_links_an_analyst_to_the_cluster(
    client: TestClient, spread: dict[str, Any], as_analyst: dict[str, str]
) -> None:
    body = client.get(f"/findings/{spread['in_wiki'].id}").text

    assert f'href="/clusters/{CLUSTER}"' in body
    assert "same secret in 2 findings" in body


def test_finding_detail_shows_no_badge_to_a_viewer(
    client: TestClient,
    spread: dict[str, Any],
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    """The API sends viewers correlation=null; the template renders nothing."""
    login_as(make_user(UserRole.VIEWER))

    body = client.get(f"/findings/{spread['in_wiki'].id}").text

    assert "/clusters/" not in body
    assert "same secret in" not in body


def test_a_source_off_the_end_of_the_page_still_appears(
    client: TestClient,
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
    as_analyst: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The topology's whole job is to show where the secret reached.

    Building the sections from the member page meant a source with nothing
    among the first `MAX_DETAIL_MEMBERS` rows disappeared from the page, and
    each badge counted page rows while reading as a source total.
    """
    from iceberg_api.correlation import service

    wiki = make_source(name="confluence-wiki")
    share = make_source(name="finance-share")
    make_finding(wiki, secret_hash=HASH, correlation_id=CLUSTER)
    make_finding(wiki, secret_hash=HASH, correlation_id=CLUSTER)
    make_finding(share, secret_hash=HASH, correlation_id=CLUSTER)

    # Order is `(created_at, id)`, so a one-row page holds only the wiki's first.
    monkeypatch.setattr(service, "MAX_DETAIL_MEMBERS", 1)
    body = client.get(f"/clusters/{CLUSTER}").text

    assert "finance-share" in body  # the source with no row on this page
    assert "2 findings" in body  # the wiki's cluster count, not its page count
    assert "Listing 1 of 2" in body  # …and the page says which it is showing
