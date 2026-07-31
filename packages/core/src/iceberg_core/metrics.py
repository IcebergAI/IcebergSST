"""Prometheus metrics shared by the API and engine roles.

Central definitions for the counters promised in docs/api.md. They register on
the default registry; the API serves them at ``GET /metrics`` and engines via a
standalone metrics HTTP server. Wiring happens as the features land (M1+).

Both roles import this module, so both register every series below — which is
what makes the ``iceberg_engine_`` prefix load-bearing. Only an engine can move
those; only the API can move the rest. A dashboard that reads a scrape without
knowing which is which sees an engine target sitting at zero and calls it dead
(#132).
"""

from prometheus_client import Counter, Gauge

# ─── The API's ────────────────────────────────────────────────────────────────

SCANS_STARTED = Counter(
    "iceberg_scans_started_total",
    "Scans started, by trigger.",
    ["trigger"],
)
SCAN_TASKS_COMPLETED = Counter(
    "iceberg_scan_tasks_completed_total",
    "Scan tasks finished, by kind and terminal status.",
    ["kind", "status"],
)
QUEUE_DEPTH = Gauge(
    "iceberg_queue_depth",
    "Approximate broker queue depth, by queue.",
    ["queue"],
)
LEASE_RECLAIMS = Counter(
    "iceberg_lease_reclaims_total",
    "Tasks reclaimed after lease expiry (dead or stalled engine).",
)
FINDINGS_INGESTED = Counter(
    "iceberg_findings_ingested_total",
    "Findings accepted by the results-ingest endpoint.",
)

# ─── An engine's ──────────────────────────────────────────────────────────────

ENGINE_TASKS_RUN = Counter(
    "iceberg_engine_tasks_run_total",
    "Scan tasks this engine ran, by kind and outcome.",
    ["kind", "outcome"],
)
ENGINE_FINDINGS_REPORTED = Counter(
    "iceberg_engine_findings_reported_total",
    "Findings submitted and accepted, after the engine's local pre-filter.",
)
ENGINE_CONNECTOR_FAILURES = Counter(
    "iceberg_engine_connector_failures_total",
    "Tasks the source failed rather than the engine, by source type.",
    ["source_type"],
)
ENGINE_API_RETRIES = Counter(
    "iceberg_engine_api_retries_total",
    "Control-plane requests tried again after a transport failure or a 5xx.",
)
ENGINE_HEARTBEAT_FAILURES = Counter(
    "iceberg_engine_heartbeat_failures_total",
    "Beats that did not reach the API; four in a row and a lease lapses.",
)
