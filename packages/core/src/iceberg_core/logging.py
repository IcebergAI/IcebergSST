"""Structured logging for all IcebergSST roles.

Every log line is a single JSON object carrying the emitting role and any bound
correlation ids (``request_id`` in the API, ``task_id`` in engines). Values of
sensitive-looking keys are masked before rendering — credentials must never
reach log output, even by accident (see docs/security.md).
"""

import re
import sys
from collections.abc import Mapping
from typing import Any, TextIO

import structlog
from structlog.typing import EventDict, WrappedLogger

SENSITIVE_KEY_RE = re.compile(
    r"password|passwd|pwd|passphrase|secret|token|credential|authorization"
    r"|bearer|cookie|api_?key|private[_-]?key|access[_-]?key|salt|pepper",
    re.IGNORECASE,
)
MASK = "[REDACTED]"

# Containers nested deeper than this are dropped rather than rendered. The cap is
# what makes the walk total: it bounds cost on pathological payloads and stops a
# self-referential structure from recursing forever. Truncation replaces the
# subtree with a marker — never the raw value — so exceeding the cap can only
# lose detail, never leak a secret.
MAX_CONTAINER_DEPTH = 6
TRUNCATED = "[TRUNCATED]"


def redact_sensitive(logger: WrappedLogger, method_name: str, event_dict: EventDict) -> EventDict:
    """Mask the value of any event key that looks like it holds a secret.

    Masking follows the whole structure — dicts and lists/tuples at any depth,
    in any combination — because a credential buried in a list of dicts is still
    a credential. The walk copies as it goes: callers routinely pass live config
    or connection objects as event values, and a log call must never leave the
    caller's own data masked.
    """
    return {key: _redact_value(key, value, 0) for key, value in event_dict.items()}


def _redact_value(key: object, value: object, depth: int) -> Any:
    if SENSITIVE_KEY_RE.search(str(key)):
        return MASK
    return _redact_container(value, depth)


def _redact_container(value: object, depth: int) -> Any:
    if isinstance(value, Mapping):
        if depth >= MAX_CONTAINER_DEPTH:
            return TRUNCATED
        return {k: _redact_value(k, v, depth + 1) for k, v in value.items()}
    # str/bytes are sequences too; only genuine collections are worth walking.
    if isinstance(value, list | tuple):
        if depth >= MAX_CONTAINER_DEPTH:
            return TRUNCATED
        return [_redact_container(item, depth + 1) for item in value]
    return value


def configure_logging(*, role: str, stream: TextIO | None = None) -> None:
    """Configure structlog for a role (``api`` or ``engine``).

    Output is JSON on stdout by default; ``stream`` exists for tests. Bind
    per-request/per-task correlation ids with
    ``structlog.contextvars.bind_contextvars``.
    """

    def add_role(logger: WrappedLogger, method_name: str, event_dict: EventDict) -> EventDict:
        event_dict.setdefault("role", role)
        return event_dict

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            add_role,
            redact_sensitive,
            structlog.processors.JSONRenderer(),
        ],
        logger_factory=structlog.PrintLoggerFactory(stream or sys.stdout),
        cache_logger_on_first_use=False,
    )
