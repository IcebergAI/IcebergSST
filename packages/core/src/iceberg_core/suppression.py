"""What a suppression covers — shared by the engine and the API (#44, ADR 0008).

Suppression is decided in two places. An engine pre-filters its detection output
using the suppressions delivered in its lease, to save bandwidth on matches nobody
will look at; the API applies them again at ingest, which is the authoritative
decision (ADR 0009 §2). Those two must never disagree — a match the engine drops
and the API would have kept is a finding that silently never existed.

The way to guarantee that is not to test two implementations against each other
but to have one. This module is it: pure matching over a flattened suppression,
importable by both roles because it depends on nothing but
:mod:`iceberg_core.enums`. Deliberately no database imports — the engine's module
graph is asserted to be free of them (ADR 0002), and this is on its import path.

The database-backed half — which suppressions are live for a source, applying and
lifting them against stored findings — lives in ``iceberg_api.suppressions``.
"""

import uuid
from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import Any

from iceberg_core.enums import SuppressionScope

#: The parts of a locator a path glob can sensibly match. Connectors describe
#: location differently — a Confluence page has a URL and a space key, a file share
#: has a path — so a glob is matched against each stringy identifier rather than
#: against one field only some connectors populate.
LOCATOR_PATH_KEYS = ("path", "url", "space", "space_key", "resource_id", "sub_resource", "title")


class SuppressionPayloadError(ValueError):
    """A lease carried a suppression this engine cannot interpret."""


@dataclass(frozen=True, slots=True)
class SuppressionRule:
    """One suppression, flattened for matching and for the lease payload."""

    id: uuid.UUID
    scope: SuppressionScope
    pattern: str

    def as_payload(self) -> dict[str, str]:
        """The shape sent to an engine in its lease (ADR 0009)."""
        return {"id": str(self.id), "scope": self.scope.value, "pattern": self.pattern}

    @classmethod
    def from_payload(cls, payload: dict[str, str]) -> SuppressionRule:
        """Rebuild a rule an engine received in its lease.

        Raises rather than skipping an unparseable entry: an engine that quietly
        ignored a scope it did not recognise would pre-filter differently from the
        API, which is the one divergence this module exists to prevent.
        """
        pattern = payload.get("pattern")
        if not isinstance(pattern, str):
            # Outside the try, or the generic handler below would swallow this
            # deliberately specific diagnosis (it subclasses ValueError).
            raise SuppressionPayloadError(f"suppression pattern must be a string: {payload}")
        try:
            return cls(
                id=uuid.UUID(payload["id"]),
                scope=SuppressionScope(payload["scope"]),
                pattern=pattern,
            )
        except (KeyError, ValueError, TypeError, AttributeError) as exc:
            # A JSON payload can carry wrong value *types* (a number for `id`, null
            # for `pattern`), which raise TypeError/AttributeError rather than
            # ValueError; all of them mean "this engine cannot use this entry", and
            # failing here beats crashing mid-scan inside fnmatch (ADR 0009).
            raise SuppressionPayloadError(f"unusable suppression payload: {payload}") from exc


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
            # fnmatchcase, not fnmatch: fnmatch folds case per the host OS
            # (os.path.normcase), which would make the engine on one platform
            # pre-filter differently from the API on another — the very
            # engine/API divergence this shared module exists to prevent.
            return any(fnmatchcase(path, rule.pattern) for path in locator_paths(resource_locator))


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


def locator_paths(resource_locator: dict[str, Any]) -> list[str]:
    """The parts of a locator a path glob can sensibly match."""
    return [
        str(resource_locator[key])
        for key in LOCATOR_PATH_KEYS
        if isinstance(resource_locator.get(key), str)
    ]
