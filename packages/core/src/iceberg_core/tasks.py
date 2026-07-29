"""The broker contract between the API and engines (ADR 0009).

The queue and actor names are shared vocabulary, not implementation: the API
enqueues messages the engine's actor consumes, and neither imports the other. They
live here for the same reason the enums do — an engine may know these names without
knowing anything about the database.

**A broker message carries a task id and nothing else.** No spec, no credential, no
pepper. It is a hint that work exists; the engine must lease the task before doing
anything, and the lease response is where the real payload comes from. That is what
keeps a compromised broker to "re-delivery noise" rather than a data leak.

Retries are disabled on purpose. Lease expiry followed by API-side reclaim is the
single re-delivery mechanism; broker-level retry would be a second, uncoordinated
one (ADR 0009 §2).
"""

from typing import Any, Final

#: Queue every scan task is dispatched on.
SCAN_TASK_QUEUE: Final = "iceberg.scan_tasks"

#: Dramatiq actor name the engine registers and the API addresses.
SCAN_TASK_ACTOR: Final = "run_scan_task"

#: Options attached to every dispatched message.
SCAN_TASK_OPTIONS: Final[dict[str, Any]] = {
    # See the module docstring: the API's lease is the only re-delivery authority.
    "max_retries": 0,
}
