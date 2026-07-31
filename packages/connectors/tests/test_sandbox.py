"""Extraction survives a hostile parser (#46, docs/security.md boundary 4).

The acceptance criterion is that a crashing or hanging parse affects only its own
content unit. That is not something a `try` can deliver — a segfault is not an
exception and a C loop never returns to notice a signal — so it is tested against
the mechanism that actually provides it: a child process that can be killed.

These tests spawn real processes and are therefore slower than the rest of the
suite. That is the cost of testing the property rather than a mock of it.
"""

import time
from collections.abc import Iterator

import pytest
from hostile import allocates, crashes, hangs, raises, succeeds
from iceberg_connectors.extraction import ExtractionLimits
from iceberg_connectors.sandbox import ExtractionSandbox, SandboxCrashed, SandboxTimeout

LIMITS = ExtractionLimits(timeout_seconds=1.0)


@pytest.fixture(name="sandbox")
def sandbox_fixture() -> Iterator[ExtractionSandbox]:
    with ExtractionSandbox() as sandbox:
        yield sandbox


def test_a_well_behaved_parser_returns_its_result(sandbox: ExtractionSandbox) -> None:
    assert sandbox.run(succeeds, b"hello", LIMITS, timeout=10) == "hello"


def test_a_hanging_parser_times_out_rather_than_wedging_the_worker(
    sandbox: ExtractionSandbox,
) -> None:
    """The failure a timer in-process cannot catch: the child never yields."""
    started = time.perf_counter()

    with pytest.raises(SandboxTimeout):
        sandbox.run(hangs, b"", LIMITS, timeout=0.5)

    # It gave up near the deadline rather than waiting on the parser to relent.
    assert time.perf_counter() - started < 10


def test_a_crashing_parser_does_not_take_the_worker_with_it(
    sandbox: ExtractionSandbox,
) -> None:
    """A segfault in a C decoder ends the child. The worker keeps its own process."""
    with pytest.raises(SandboxCrashed):
        sandbox.run(crashes, b"", LIMITS, timeout=10)


def test_an_ordinary_parser_error_propagates_unchanged(sandbox: ExtractionSandbox) -> None:
    """A politely-rejected malformed file is not a sandbox failure — the caller
    maps it to `failed_parse`, and conflating the two would hide real crashes."""
    with pytest.raises(ValueError, match="malformed document structure"):
        sandbox.run(raises, b"", LIMITS, timeout=10)


def test_the_sandbox_recovers_after_a_hang(sandbox: ExtractionSandbox) -> None:
    """The property that makes isolation per-*unit* rather than per-*task*: the
    next file is extracted normally."""
    with pytest.raises(SandboxTimeout):
        sandbox.run(hangs, b"", LIMITS, timeout=0.5)

    assert sandbox.run(succeeds, b"after the hang", LIMITS, timeout=10) == "after the hang"


def test_the_sandbox_recovers_after_a_crash(sandbox: ExtractionSandbox) -> None:
    with pytest.raises(SandboxCrashed):
        sandbox.run(crashes, b"", LIMITS, timeout=10)

    assert sandbox.run(succeeds, b"after the crash", LIMITS, timeout=10) == "after the crash"


def test_a_child_that_allocates_without_bound_fails_alone() -> None:
    """Size caps bound what goes *into* a parser; nothing bounds what pypdf
    allocates decoding a crafted Flate stream, and gigabytes inside a 30 s timeout is
    reachable. Unlimited, the pod's cgroup picks the OOM victim and may pick the
    worker — one hostile attachment becoming a restart, a reclaimed task, and the
    same file downloaded again (#133)."""
    with ExtractionSandbox(address_space_bytes=1024 * 1024 * 1024) as sandbox:
        with pytest.raises((MemoryError, OSError)):
            sandbox.run(allocates, b"", LIMITS, timeout=10)

        # ...and the child that refused is still the worker's to use.
        assert sandbox.run(succeeds, b"ok after it", LIMITS, timeout=10) == "ok after it"


def test_the_child_is_reused_across_extractions(sandbox: ExtractionSandbox) -> None:
    """Spawning a process per file would be the obvious way to get isolation and
    an unaffordable one; the pool is only replaced when a child is actually lost."""
    import os

    def child_pid() -> int:
        return sandbox.run(_pid, b"", LIMITS, timeout=10)

    assert child_pid() == child_pid()
    assert child_pid() != os.getpid()


def _pid(data: bytes, limits: ExtractionLimits) -> int:
    import os

    return os.getpid()
