"""Structured logging for all IcebergSST roles.

Every log line is a single JSON object carrying the emitting role and any bound
correlation ids (``request_id`` in the API, ``task_id`` in engines). Values of
sensitive-looking keys are masked before rendering — credentials must never
reach log output, even by accident (see docs/security.md).
"""

import re
import sys
from typing import TextIO

import structlog
from structlog.typing import EventDict, WrappedLogger

SENSITIVE_KEY_RE = re.compile(
    r"password|passwd|secret|token|credential|authorization|api_?key|pepper",
    re.IGNORECASE,
)
MASK = "[REDACTED]"


def redact_sensitive(logger: WrappedLogger, method_name: str, event_dict: EventDict) -> EventDict:
    """Mask the value of any event key that looks like it holds a secret."""
    return _redact_mapping(event_dict)


def _redact_mapping(mapping: EventDict) -> EventDict:
    for key, value in mapping.items():
        if SENSITIVE_KEY_RE.search(key):
            mapping[key] = MASK
        elif isinstance(value, dict):
            mapping[key] = _redact_mapping(value)
        elif isinstance(value, list):
            mapping[key] = [_redact_mapping(v) if isinstance(v, dict) else v for v in value]
    return mapping


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
