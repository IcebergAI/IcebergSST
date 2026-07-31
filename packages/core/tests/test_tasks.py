"""The broker contract the API dispatches on and the engine registers (ADR 0009)."""

from iceberg_core.tasks import SCAN_TASK_ACTOR, SCAN_TASK_OPTIONS, SCAN_TASK_QUEUE

#: The API's lease, in seconds. Duplicated rather than imported: core cannot depend
#: on the API role, and the point of the assertion below is the ratio, not the value.
LEASE_SECONDS = 300


def test_the_queue_and_actor_names_are_stable() -> None:
    """Both roles address these by name and neither imports the other."""
    assert SCAN_TASK_QUEUE == "iceberg.scan_tasks"
    assert SCAN_TASK_ACTOR == "run_scan_task"


def test_broker_retries_are_off() -> None:
    """Lease expiry and API-side reclaim are the single re-delivery mechanism."""
    assert SCAN_TASK_OPTIONS["max_retries"] == 0


def test_the_broker_time_limit_is_set_and_far_past_any_lease() -> None:
    """Left unset, the actor inherits Dramatiq's ten-minute default and a scan that
    outlives it is killed by a `BaseException` no handler in the runner catches: the
    task ends without reporting, the lease expires, the task is reclaimed, and the
    redelivered copy dies at ten minutes again. The limit has to be past anything a
    scan could plausibly still be doing, so that the lease is what notices.
    """
    assert SCAN_TASK_OPTIONS["time_limit"] > 100 * LEASE_SECONDS * 1000
