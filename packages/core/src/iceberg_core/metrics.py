"""Prometheus metrics shared by the API and engine roles.

Central definitions for the counters promised in docs/api.md. They register on
the default registry; the API serves them at ``GET /metrics`` and engines via a
standalone metrics HTTP server. Wiring happens as the features land (M1+).
"""

from prometheus_client import Counter, Gauge

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
