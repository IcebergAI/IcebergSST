"""Parsers that behave the way malicious input makes real parsers behave (#46).

A module rather than closures in the test file: the sandbox pickles a function by
name to reach the child, so these have to be importable there.

Nothing here is contrived for the sake of it. A PDF with a crafted cross-reference
loop hangs a reader; a malformed stream segfaults a C decoder; a crafted archive
allocates until the kernel intervenes. These are the same three outcomes, reached
by the shortest route.
"""

import os
import time

from iceberg_connectors.extraction import ExtractionLimits


def hangs(data: bytes, limits: ExtractionLimits) -> str:
    """Never returns — a parser stuck in a loop the interpreter never interrupts."""
    while True:
        time.sleep(0.05)


def crashes(data: bytes, limits: ExtractionLimits) -> str:
    """Dies without unwinding, as a segfault in a C extension would.

    `os._exit` skips cleanup and finalisers, which is precisely what makes it a
    faithful stand-in: nothing in the child gets a chance to report anything.
    """
    os._exit(1)


def raises(data: bytes, limits: ExtractionLimits) -> str:
    """Fails in the ordinary way — a malformed file a parser rejects politely."""
    raise ValueError("malformed document structure")


def succeeds(data: bytes, limits: ExtractionLimits) -> str:
    """A well-behaved parser, for asserting the sandbox recovers after a casualty."""
    return data.decode("utf-8", errors="replace")
