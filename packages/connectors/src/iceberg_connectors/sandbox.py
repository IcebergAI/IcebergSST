"""Running untrusted parsers where they cannot take the worker with them (#46).

Extraction parsers are the engine's largest attack surface. Attachments are
attacker-editable by anyone who can upload to a Confluence space, and the code
that reads a PDF or an office document is thousands of lines of format handling —
some of it C — with a long history of hangs and crashes on malformed input
(docs/security.md, boundary 4).

Size caps and ratio limits handle the inputs you can recognise as hostile before
parsing. This module handles the ones you cannot: a parser that loops forever on a
crafted cross-reference table, or segfaults on a malformed stream. Neither can be
caught with ``try``, and neither can be bounded with a timer in the same process —
``signal.alarm`` only fires on the main thread, and a C extension in a tight loop
never returns to the interpreter to notice it.

So extraction runs in a **child process**. A hang is a timeout on the parent's
side and the child is killed; a crash takes the child only. Either way the cost is
one content unit, which is the isolation #46 asks for and the only way to get it
honestly.

The cost is a process spawn per extraction. The pool is reused across files to
amortise it, and replaced only when a child actually dies or hangs.
"""

import concurrent.futures as futures
from collections.abc import Callable
from typing import Any

import structlog

logger = structlog.get_logger()

#: Address space the extraction child may map. Size caps bound what goes *in* to a
#: parser; nothing bounds what pypdf allocates decoding a crafted Flate stream, and
#: gigabytes inside a 30 s timeout is comfortably reachable. Without this the pod's
#: cgroup picks the OOM victim, and it may pick the worker rather than the child —
#: turning one hostile attachment into a restart, a reclaimed task, and the same
#: file downloaded again. With it the child raises and one unit fails.
CHILD_ADDRESS_SPACE_BYTES = 2 * 1024 * 1024 * 1024


class SandboxTimeout(Exception):
    """The parser did not finish in time. Assume it never will."""


class SandboxCrashed(Exception):
    """The child process died — a segfault, an OOM kill, an abort in C."""


class ExtractionSandbox:
    """A one-child process pool that is replaced whenever the child is lost.

    Not thread-safe: one per worker thread. Engines process one task per thread,
    so that is the natural granularity, and sharing one across threads would mean
    a hostile file in one task killing the extraction of another.
    """

    def __init__(self, address_space_bytes: int = CHILD_ADDRESS_SPACE_BYTES) -> None:
        self._pool: futures.ProcessPoolExecutor | None = None
        self._address_space_bytes = address_space_bytes

    def run[ResultT](
        self,
        function: Callable[..., ResultT],
        *args: Any,
        timeout: float,
    ) -> ResultT:
        """Run ``function`` in the child, or raise :class:`SandboxTimeout`/:class:`SandboxCrashed`.

        ``function`` must be importable by name — a module-level function, not a
        closure or a lambda — because it is pickled to reach the child.
        """
        pool = self._ensure_pool()
        future = pool.submit(function, *args)
        try:
            return future.result(timeout=timeout)
        except futures.TimeoutError as exc:
            # The child is still spinning. Cancelling the future does not stop it,
            # so the pool is torn down and the process killed outright.
            logger.warning("extraction_timed_out", timeout_seconds=timeout)
            self._discard_pool()
            raise SandboxTimeout(f"extraction exceeded {timeout}s") from exc
        except futures.process.BrokenProcessPool as exc:
            # The child died mid-parse. Whatever it was doing, the worker survived,
            # which is the entire point of this module.
            logger.warning("extraction_crashed_the_child", error=str(exc))
            self._discard_pool()
            raise SandboxCrashed("extraction crashed the child process") from exc

    def close(self) -> None:
        self._discard_pool()

    def __enter__(self) -> ExtractionSandbox:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def _ensure_pool(self) -> futures.ProcessPoolExecutor:
        if self._pool is None:
            # max_workers=1: extraction is already parallel across engine replicas,
            # and one child per sandbox keeps "which file killed it" answerable.
            self._pool = futures.ProcessPoolExecutor(
                max_workers=1,
                initializer=_limit_address_space,
                initargs=(self._address_space_bytes,),
            )
        return self._pool

    def _discard_pool(self) -> None:
        pool, self._pool = self._pool, None
        if pool is None:
            return
        # `shutdown` waits for the very work we are abandoning, so the children are
        # killed first. `_processes` is private, and there is no public way to stop
        # a running task — this is the accepted cost of process isolation.
        for process in list(getattr(pool, "_processes", {}).values()):
            if process.is_alive():
                process.kill()
        pool.shutdown(wait=False, cancel_futures=True)


def _limit_address_space(ceiling: int) -> None:
    """Cap the child's address space, in the child.

    A pool initializer rather than a setting on the parent: the limit has to apply
    to the process that may be handed a bomb and to nothing else, and the parent
    holding the same limit would defeat the isolation it exists for. Platforms
    without ``resource`` (Windows) simply go without — the timeout and the crash
    isolation still hold there.
    """
    try:
        import resource
    except ImportError:  # pragma: no cover — POSIX only
        return

    _, hard = resource.getrlimit(resource.RLIMIT_AS)
    if hard != resource.RLIM_INFINITY:
        ceiling = min(ceiling, hard)
    try:
        resource.setrlimit(resource.RLIMIT_AS, (ceiling, hard))
    except OSError, ValueError:  # pragma: no cover — a sandbox that forbids it
        logger.warning("extraction_address_space_limit_refused", ceiling=ceiling)
