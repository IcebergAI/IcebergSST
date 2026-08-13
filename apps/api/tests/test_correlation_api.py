"""The cluster API (ADR 0011, #140): analyst-scoped reads and an audited export.

What is pinned here: clustering answers "same secret elsewhere" for analysts
and nobody below; the aggregates describe whole clusters; the export is
byte-stable, allowlisted, and leaves a trail row; and no response — finding or
cluster — ever carries ``secret_hash``.
"""

import secrets
from collections.abc import Callable
from typing import Any

import pytest
from fastapi.testclient import TestClient
from iceberg_core.correlation import correlation_id
from iceberg_core.enums import FindingState, Severity, UserRole
from iceberg_core.models import (
    AUDIT_CORRELATION_CLUSTER_EXPORTED,
    AuditEvent,
    Finding,
    Source,
    User,
)
from sqlmodel import Session, col, select

KEY = secrets.token_bytes(32)

#: Stored hashes for two distinct secret values.
HASH_A = "a1" * 32
HASH_B = "b2" * 32

CLUSTER_A = correlation_id(HASH_A, key=KEY)
CLUSTER_B = correlation_id(HASH_B, key=KEY)


@pytest.fixture(name="clustered")
def clustered_fixture(
    make_source: Callable[..., Source],
    make_finding: Callable[..., Finding],
) -> dict[str, Any]:
    """Secret A in two sources (three findings), secret B in one."""
    wiki = make_source(name="confluence-wiki")
    share = make_source(name="finance-share")
    return {
        "wiki": wiki,
        "share": share,
        "a1": make_finding(
            wiki, secret_hash=HASH_A, correlation_id=CLUSTER_A, severity=Severity.HIGH
        ),
        "a2": make_finding(
            wiki,
            secret_hash=HASH_A,
            correlation_id=CLUSTER_A,
            severity=Severity.CRITICAL,
            state=FindingState.RESOLVED,
        ),
        "a3": make_finding(share, secret_hash=HASH_A, correlation_id=CLUSTER_A),
        "b1": make_finding(share, secret_hash=HASH_B, correlation_id=CLUSTER_B),
    }


@pytest.fixture(name="analyst_headers")
def analyst_headers_fixture(
    make_user: Callable[..., User], login_as: Callable[[User], dict[str, str]]
) -> dict[str, str]:
    return login_as(make_user(UserRole.ANALYST))


@pytest.fixture(name="viewer_headers")
def viewer_headers_fixture(
    make_user: Callable[..., User], login_as: Callable[[User], dict[str, str]]
) -> dict[str, str]:
    return login_as(make_user(UserRole.VIEWER))


def test_the_same_value_forms_one_cluster_across_sources(
    client: TestClient, api: str, clustered: dict[str, Any], analyst_headers: dict[str, str]
) -> None:
    response = client.get(f"{api}/correlation/clusters", headers=analyst_headers)

    assert response.status_code == 200, response.text
    by_id = {item["correlation_id"]: item for item in response.json()["items"]}
    assert by_id[CLUSTER_A]["finding_count"] == 3
    assert by_id[CLUSTER_A]["source_count"] == 2
    assert by_id[CLUSTER_A]["open_count"] == 2  # a2 is resolved
    assert by_id[CLUSTER_A]["max_severity"] == "critical"
    assert by_id[CLUSTER_B]["finding_count"] == 1


def test_min_findings_is_an_explicit_filter(
    client: TestClient, api: str, clustered: dict[str, Any], analyst_headers: dict[str, str]
) -> None:
    """Absent means 1 — the endpoint hides nothing by default."""
    everything = client.get(f"{api}/correlation/clusters", headers=analyst_headers)
    spread = client.get(
        f"{api}/correlation/clusters", params={"min_findings": 2}, headers=analyst_headers
    )

    assert len(everything.json()["items"]) == 2
    assert [item["correlation_id"] for item in spread.json()["items"]] == [CLUSTER_A]


def test_the_list_paginates_in_correlation_id_order(
    client: TestClient, api: str, clustered: dict[str, Any], analyst_headers: dict[str, str]
) -> None:
    first = client.get(f"{api}/correlation/clusters", params={"limit": 1}, headers=analyst_headers)

    page = first.json()
    assert len(page["items"]) == 1
    assert page["next_cursor"] is not None

    second = client.get(
        f"{api}/correlation/clusters",
        params={"limit": 1, "cursor": page["next_cursor"]},
        headers=analyst_headers,
    )
    ids = [page["items"][0]["correlation_id"], second.json()["items"][0]["correlation_id"]]
    assert ids == sorted([CLUSTER_A, CLUSTER_B])
    assert second.json()["next_cursor"] is None


def test_cluster_detail_groups_members_by_source(
    client: TestClient, api: str, clustered: dict[str, Any], analyst_headers: dict[str, str]
) -> None:
    response = client.get(f"{api}/correlation/clusters/{CLUSTER_A}", headers=analyst_headers)

    assert response.status_code == 200, response.text
    detail = response.json()
    groups = {group["source_name"]: group for group in detail["sources"]}
    assert groups["confluence-wiki"]["finding_count"] == 2
    assert groups["confluence-wiki"]["open_count"] == 1
    assert groups["finance-share"]["finding_count"] == 1
    # Members are the findings-API shape: per-location remediation state rides
    # along, which is what makes the cluster a work list.
    assert {member["state"] for member in detail["members"]} == {"open", "resolved"}


def test_an_unknown_cluster_is_a_404_and_a_malformed_id_a_422(
    client: TestClient, api: str, analyst_headers: dict[str, str]
) -> None:
    unknown = client.get(f"{api}/correlation/clusters/{'0' * 64}", headers=analyst_headers)
    malformed = client.get(f"{api}/correlation/clusters/not-a-cluster", headers=analyst_headers)

    assert unknown.status_code == 404
    assert malformed.status_code == 422


def test_viewers_get_403_from_every_cluster_route(
    client: TestClient, api: str, clustered: dict[str, Any], viewer_headers: dict[str, str]
) -> None:
    """The comparison capability is scoped to the roles that remediate."""
    for path in (
        "/correlation/clusters",
        f"/correlation/clusters/{CLUSTER_A}",
        f"/correlation/clusters/{CLUSTER_A}/export",
    ):
        assert client.get(f"{api}{path}", headers=viewer_headers).status_code == 403, path


def test_no_cluster_response_carries_the_secret_hash(
    client: TestClient, api: str, clustered: dict[str, Any], analyst_headers: dict[str, str]
) -> None:
    for path in (
        "/correlation/clusters",
        f"/correlation/clusters/{CLUSTER_A}",
        f"/correlation/clusters/{CLUSTER_A}/export",
    ):
        body = client.get(f"{api}{path}", headers=analyst_headers).text
        assert HASH_A not in body, path
        assert HASH_B not in body, path
        assert "secret_hash" not in body, path


def test_the_export_is_byte_stable_and_audited(
    client: TestClient,
    api: str,
    session: Session,
    clustered: dict[str, Any],
    analyst_headers: dict[str, str],
) -> None:
    first = client.get(f"{api}/correlation/clusters/{CLUSTER_A}/export", headers=analyst_headers)
    second = client.get(f"{api}/correlation/clusters/{CLUSTER_A}/export", headers=analyst_headers)

    assert first.status_code == 200, first.text
    assert first.content == second.content
    assert first.headers["cache-control"] == "no-store"
    assert first.headers["content-disposition"].startswith("attachment;")
    manifest = first.json()
    assert manifest["manifest_version"] == 1
    assert manifest["finding_count"] == 3
    # Narrower than the findings API on purpose: an export travels.
    assert all("redacted_snippet" not in member for member in manifest["members"])
    assert all("notes" not in member for member in manifest["members"])

    events = session.exec(
        select(AuditEvent).where(col(AuditEvent.action) == AUDIT_CORRELATION_CLUSTER_EXPORTED)
    ).all()
    assert len(events) == 2  # one per download — that is the point of the trail
    assert events[0].detail["correlation_id"] == CLUSTER_A


def test_finding_detail_shows_the_cluster_to_analysts_only(
    client: TestClient,
    api: str,
    clustered: dict[str, Any],
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
) -> None:
    finding_id = clustered["a1"].id

    # Sequential logins: the test client holds one session cookie at a time.
    headers = login_as(make_user(UserRole.ANALYST))
    analyst_view = client.get(f"{api}/findings/{finding_id}", headers=headers).json()
    headers = login_as(make_user(UserRole.VIEWER))
    viewer_view = client.get(f"{api}/findings/{finding_id}", headers=headers).json()

    assert analyst_view["correlation"] == {
        "correlation_id": CLUSTER_A,
        "finding_count": 3,
        "source_count": 2,
    }
    # Role-shaped: same field, null — a viewer cannot learn "same as that one".
    assert viewer_view["correlation"] is None


def test_a_finding_without_an_id_has_a_null_cluster(
    client: TestClient,
    api: str,
    make_finding: Callable[..., Finding],
    analyst_headers: dict[str, str],
) -> None:
    finding = make_finding(correlation_id=None)

    detail = client.get(f"{api}/findings/{finding.id}", headers=analyst_headers).json()

    assert detail["correlation"] is None


def test_no_engine_facing_schema_mentions_correlation() -> None:
    """The key never leaves the API, so nothing an engine sends or receives may
    grow a correlation field — this is what keeps ids unmintable outside."""
    from iceberg_api.engines import schemas as engine_schemas
    from iceberg_core.config import EngineSettings
    from pydantic import BaseModel

    for name in dir(engine_schemas):
        model = getattr(engine_schemas, name)
        if isinstance(model, type) and issubclass(model, BaseModel):
            offenders = [f for f in model.model_fields if "correlation" in f.lower()]
            assert offenders == [], f"{name} carries {offenders}"
    assert [f for f in EngineSettings.model_fields if "correlation" in f.lower()] == []


def test_the_export_counts_what_it_had_to_leave_out(
    client: TestClient,
    api: str,
    clustered: dict[str, Any],
    analyst_headers: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A truncated export must say so in the file. `finding_count` describes the
    whole cluster, so without `members_omitted` a reader cannot tell a complete
    export from one that silently stopped at the ceiling."""
    from iceberg_api.correlation import service

    # The route reads the ceiling off the module at call time, so patching it
    # here is the same knob a deployment-sized cluster would hit.
    monkeypatch.setattr(service, "MAX_EXPORT_MEMBERS", 2)

    manifest = client.get(
        f"{api}/correlation/clusters/{CLUSTER_A}/export", headers=analyst_headers
    ).json()

    assert manifest["finding_count"] == 3  # the cluster is still described whole
    assert len(manifest["members"]) == 2  # …but only two rows fitted
    assert manifest["members_omitted"] == 1


def test_a_complete_export_omits_nothing(
    client: TestClient, api: str, clustered: dict[str, Any], analyst_headers: dict[str, str]
) -> None:
    manifest = client.get(
        f"{api}/correlation/clusters/{CLUSTER_A}/export", headers=analyst_headers
    ).json()

    assert len(manifest["members"]) == manifest["finding_count"] == 3
    assert manifest["members_omitted"] == 0


def test_the_export_ceiling_is_larger_than_the_screens(
    client: TestClient, api: str, analyst_headers: dict[str, str]
) -> None:
    """The screen's cap is a rendering budget; the export's is a work-order
    budget. Sharing one was how a 501-member cluster exported 500 rows under a
    header claiming 501."""
    from iceberg_api.correlation import service

    assert service.MAX_EXPORT_MEMBERS > service.MAX_DETAIL_MEMBERS
