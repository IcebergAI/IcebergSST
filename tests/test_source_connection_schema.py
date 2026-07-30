"""Every connection key the Confluence connector reads is storable via the API.

The API validates a source's ``connection`` blob with ``extra="forbid"``
(`iceberg_api.sources.schemas.ConfluenceConnection`), while the connector reads
keys out of that same blob inside an engine, delivered verbatim in the task
lease. The two never import each other, so nothing structural stops them
drifting — and a key the connector understands but the schema forbids is
configuration nobody can store. That is how ``email``, the Cloud auth-flavor
selector (docs/connectors.md § Auth), was once unconfigurable while every doc
and pipeline test used it.

This lives in the root suite because it must import both roles at once:
`apps/api/tests` cannot depend on the connectors package any more than the
reverse (the same reasoning as ``test_suppression_consistency.py``).
"""

import ast
import inspect
from types import ModuleType

import iceberg_connectors.confluence.connector as confluence_connector
from iceberg_api.sources import probe
from iceberg_api.sources.schemas import ConfluenceConnection

#: Keys the connector tolerates as fallbacks in hand-authored blobs, mapped to
#: the canonical field the API stores instead. The schema deliberately offers
#: one spelling; the connector stays lenient about the other.
TOLERATED_ALIASES = {"username": "email"}


def _keys_read_from_connection(module: ModuleType) -> set[str]:
    """Every string K in a ``connection.get(K, …)`` call in the module's source.

    Matches both the connector's ``connection`` parameter and the probe's
    ``source.connection`` attribute. Purely syntactic on purpose — the point is
    to catch a key added in code review, not to execute anything.
    """
    tree = ast.parse(inspect.getsource(module))
    keys: set[str] = set()
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and node.args):
            continue
        target = node.func
        if not (isinstance(target, ast.Attribute) and target.attr == "get"):
            continue
        holder = target.value
        reads_connection = (isinstance(holder, ast.Name) and holder.id == "connection") or (
            isinstance(holder, ast.Attribute) and holder.attr == "connection"
        )
        first = node.args[0]
        if reads_connection and isinstance(first, ast.Constant) and isinstance(first.value, str):
            keys.add(first.value)
    return keys


def test_every_key_the_connector_reads_is_a_schema_field() -> None:
    read = _keys_read_from_connection(confluence_connector)
    # The scan found the real reads: if a refactor renames the parameter, this
    # fails loudly rather than the invariant silently checking nothing.
    assert {"base_url", "email"} <= read

    fields = set(ConfluenceConnection.model_fields)
    unknown = {key for key in read if key not in fields and key not in TOLERATED_ALIASES}
    assert not unknown, (
        f"the Confluence connector reads connection key(s) {sorted(unknown)} that "
        f"ConfluenceConnection forbids — no admin can store them (extra='forbid'), "
        f"so no engine will ever receive them; add the field(s) to the schema"
    )
    # Every alias must resolve to a field that actually exists.
    assert set(TOLERATED_ALIASES.values()) <= fields


def test_the_probe_reads_only_storable_keys() -> None:
    """The probe authenticates from the same blob a scan does; a key it reads
    that the schema forbids would make `POST /sources/{id}/test` and a real scan
    disagree about the source's configuration."""
    read = _keys_read_from_connection(probe)
    assert read  # the probe reads base_url at minimum
    assert read <= set(ConfluenceConnection.model_fields)
