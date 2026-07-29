from fastapi.testclient import TestClient
from iceberg_api.app import REQUEST_ID_HEADER, create_app


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
