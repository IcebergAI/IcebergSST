"""The heartbeat interval is sized against the API's lease (#51, ADR 0009).

One number in the API and one in the engine, and nothing connects them but this
test. If the API shortened its lease to a minute, engines beating every minute
would start losing tasks to reclaim under any transient failure at all — and the
symptom would be duplicated scan work, not an error anyone could trace back here.

Lives in the root suite because it is the only place both roles may be imported.
"""

from iceberg_api.scans.service import DEFAULT_LEASE_SECONDS
from iceberg_engine.heartbeat import DEFAULT_INTERVAL_SECONDS


def test_a_lease_survives_several_missed_heartbeats() -> None:
    """Four consecutive failures before anything lapses: the difference between a
    blip in the control plane and an engine losing work it is still doing."""
    beats_per_lease = DEFAULT_LEASE_SECONDS / DEFAULT_INTERVAL_SECONDS

    assert beats_per_lease >= 4, (
        f"a {DEFAULT_LEASE_SECONDS}s lease with a {DEFAULT_INTERVAL_SECONDS}s beat leaves "
        f"only {beats_per_lease:.1f} attempts; one slow round would cost the task"
    )


def test_the_beat_is_not_so_frequent_it_becomes_load() -> None:
    """Every engine beats on this interval, so it is also a floor on control-plane
    traffic from an idle fleet."""
    assert DEFAULT_INTERVAL_SECONDS >= 10
