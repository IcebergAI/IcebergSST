"""Matching analyst suppressions against findings (ADR 0008).

Suppressions are runtime data, not code: an analyst silences a known-benign match
without waiting for a rule-pack release. This module is only the *matching*; the
CRUD routes are #40.

Two properties are worth stating because they are easy to get wrong:

* **The API is the authoritative enforcement point.** Engines receive the
  applicable suppressions in their lease and pre-filter locally to save bandwidth,
  but ingest applies them again. A suppression created after an engine leased its
  task is still honoured, because the copy that decides is the one read at ingest
  (#44).
* **Suppressed findings are recorded, not discarded.** They are stored and marked,
  so "why is this not in my list?" has an answer and an expiring suppression brings
  the finding back rather than losing the history.
"""

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from fnmatch import fnmatch
from typing import Any

from iceberg_core.enums import SuppressionScope
from iceberg_core.models import Suppression
from sqlmodel import Session, col, or_, select


@dataclass(frozen=True, slots=True)
class SuppressionRule:
    """One suppression, flattened for matching and for the lease payload."""

    id: uuid.UUID
    scope: SuppressionScope
    pattern: str

    def as_payload(self) -> dict[str, str]:
        """The shape sent to an engine in its lease (ADR 0009)."""
        return {"id": str(self.id), "scope": self.scope.value, "pattern": self.pattern}


def applicable_suppressions(
    db: Session,
    source_id: uuid.UUID,
    *,
    now: datetime | None = None,
) -> list[SuppressionRule]:
    """Every live suppression for this source, plus the global ones.

    ``source_id IS NULL`` means global. An expired suppression is simply not
    returned — expiry is how an analyst says "silence this for a sprint" without
    having to remember to undo it.
    """
    at = now or datetime.now(UTC)
    rows = db.exec(
        select(Suppression).where(
            or_(col(Suppression.source_id) == source_id, col(Suppression.source_id).is_(None))
        )
    )
    return [
        SuppressionRule(id=row.id, scope=row.scope, pattern=row.pattern)
        for row in rows
        if row.expires_at is None or _as_utc(row.expires_at) > at
    ]


def matches(
    rule: SuppressionRule,
    *,
    fingerprint: str,
    rule_id: str,
    resource_locator: dict[str, Any],
) -> bool:
    """Does this suppression cover this finding?"""
    # Exhaustive over SuppressionScope on purpose: adding a scope without deciding
    # how it matches should fail the type check, not silently match nothing.
    match rule.scope:
        case SuppressionScope.FINGERPRINT:
            return rule.pattern == fingerprint
        case SuppressionScope.RULE:
            return rule.pattern == rule_id
        case SuppressionScope.PATH_GLOB:
            return any(fnmatch(path, rule.pattern) for path in _locator_paths(resource_locator))


def first_match(
    rules: list[SuppressionRule],
    *,
    fingerprint: str,
    rule_id: str,
    resource_locator: dict[str, Any],
) -> SuppressionRule | None:
    """The first suppression covering a finding, or None."""
    for rule in rules:
        if matches(
            rule, fingerprint=fingerprint, rule_id=rule_id, resource_locator=resource_locator
        ):
            return rule
    return None


def _locator_paths(resource_locator: dict[str, Any]) -> list[str]:
    """The parts of a locator a path glob can sensibly match.

    Connectors describe location differently — a Confluence page has a URL and a
    space key, a file share has a path — so a glob is matched against each stringy
    identifier rather than against one field that only some connectors populate.
    """
    keys = ("path", "url", "space", "space_key", "resource_id", "sub_resource", "title")
    return [
        str(resource_locator[key]) for key in keys if isinstance(resource_locator.get(key), str)
    ]


def _as_utc(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)
