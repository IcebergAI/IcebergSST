"""Database access for the api role only.

Nothing in this subpackage may be imported by ``apps/engine`` — engines hold no
database credentials and never open a connection (ADR 0002). The guard for that
invariant lands with issue #52; this subpackage exists as a single, addressable
import target so the guard is a one-line rule rather than a refactor.

It is deliberately **not** re-exported from ``iceberg_core/__init__.py``: importing
``iceberg_core`` must never drag in a database driver. The driver itself ships in
the ``iceberg-core[db]`` extra, which only the api installs, so an engine that
tried would fail at import with ModuleNotFoundError.
"""
