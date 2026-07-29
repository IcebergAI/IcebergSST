import pytest
from fastapi.testclient import TestClient
from iceberg_api.app import (
    REQUEST_ID_HEADER,
    REQUEST_ID_MAX_LENGTH,
    REQUEST_ID_RE,
    create_app,
)


def make_client() -> TestClient:
    return TestClient(create_app())


def test_healthz() -> None:
    response = make_client().get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_metrics_exposes_core_series() -> None:
    response = make_client().get("/metrics")
    assert response.status_code == 200
    body = response.text
    for series in (
        "iceberg_findings_ingested_total",
        "iceberg_lease_reclaims_total",
        "iceberg_scans_started",
        "iceberg_scan_tasks_completed",
        "iceberg_queue_depth",
    ):
        assert series in body


def test_request_id_generated_and_echoed() -> None:
    response = make_client().get("/healthz")
    assert response.headers[REQUEST_ID_HEADER]


def test_request_id_from_caller_is_preserved() -> None:
    response = make_client().get("/healthz", headers={REQUEST_ID_HEADER: "abc-42"})
    assert response.headers[REQUEST_ID_HEADER] == "abc-42"


@pytest.mark.parametrize(
    "supplied",
    [
        "A" * (REQUEST_ID_MAX_LENGTH + 1),  # unbounded growth of every log line
        'evil" ,"level":"critical',  # framing characters aimed at log consumers
        "",  # empty is not a usable correlation id
        "spaces are not allowed",
    ],
)
def test_unacceptable_caller_request_id_is_replaced(supplied: str) -> None:
    response = make_client().get("/healthz", headers={REQUEST_ID_HEADER: supplied})
    echoed = response.headers[REQUEST_ID_HEADER]
    assert echoed != supplied
    assert REQUEST_ID_RE.match(echoed)
