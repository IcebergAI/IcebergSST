"""Migrations must apply, reverse, and match the models.

The value of these tests is drift: a model field added without a migration, or a
migration that renames a column the code still reads, fails here rather than on a
production ``alembic upgrade``. SQLite stands in for Postgres — enough to prove
the ops execute and the resulting shape matches the metadata.
"""

from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from iceberg_api.cli import alembic_config
from iceberg_core.enums import ScanStatus, ScanTrigger, SourceType
from iceberg_core.models import Scan, Source, metadata
from sqlalchemy import Engine, create_engine, inspect
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select


@pytest.fixture(name="migrated_engine")
def migrated_engine_fixture(tmp_path: Path) -> Iterator[tuple[Engine, Config]]:
    """A file-backed SQLite database with migrations applied to head."""
    url = f"sqlite:///{tmp_path / 'migrations.db'}"
    # Deliberately the same loader the operator CLI and the Helm Job use: these
    # tests are only evidence about production migrations if they run the same
    # config, from the same place.
    config = alembic_config()
    config.attributes["sqlalchemy.url"] = url
    # The suite configures its own logging; let Alembic keep its hands off it.
    config.attributes["skip_logging_config"] = True

    command.upgrade(config, "head")
    engine = create_engine(url)
    try:
        yield engine, config
    finally:
        engine.dispose()


def test_upgrade_creates_every_table_in_the_metadata(
    migrated_engine: tuple[Engine, Config],
) -> None:
    engine, _ = migrated_engine

    applied = set(inspect(engine).get_table_names()) - {"alembic_version"}

    assert applied == set(metadata.tables)


def test_columns_match_the_models(migrated_engine: tuple[Engine, Config]) -> None:
    engine, _ = migrated_engine
    inspector = inspect(engine)

    for name, table in metadata.tables.items():
        migrated = {column["name"] for column in inspector.get_columns(name)}
        assert migrated == {column.name for column in table.columns}, f"{name} columns drifted"


def test_indexes_and_constraints_carry_their_conventional_names(
    migrated_engine: tuple[Engine, Config],
) -> None:
    engine, _ = migrated_engine
    inspector = inspect(engine)

    finding_indexes = {index["name"] for index in inspector.get_indexes("finding")}
    scan_indexes = {index["name"] for index in inspector.get_indexes("scan")}

    assert "ix_finding_fingerprint" in finding_indexes
    assert "ix_finding_source_id_state" in finding_indexes
    assert {"pk_finding"} == {inspector.get_pk_constraint("finding")["name"]}
    # The "one active scan per source" guard from ADR 0009.
    assert "uq_scan_active_per_source" in scan_indexes


def test_the_paginated_and_cascaded_columns_are_indexed(
    migrated_engine: tuple[Engine, Config],
) -> None:
    """Two costs that only appear once a deployment has data.

    Every list endpoint orders on ``(created_at, id)``, so without that pair the
    findings queue sorts the whole table per page; and ``notification_delivery``
    cascades from finding and scan, which Postgres enforces with a per-row lookup
    on each of the thousand rows a retention round can delete.
    """
    engine, _ = migrated_engine
    inspector = inspect(engine)

    def index_names(table: str) -> set[str]:
        return {str(index["name"]) for index in inspector.get_indexes(table)}

    assert "ix_finding_created_at_id" in index_names("finding")
    assert "ix_scan_created_at_id" in index_names("scan")
    assert {
        "ix_notification_delivery_finding_id",
        "ix_notification_delivery_scan_id",
    } <= index_names("notification_delivery")


def test_one_active_scan_per_source_is_enforced_by_the_database(
    migrated_engine: tuple[Engine, Config],
) -> None:
    """The partial unique index, exercised rather than merely inspected.

    Two concurrent scans of one source would let two reconciliations race and
    resolve each other's findings (ADR 0006/0009), so the guard belongs in the
    database rather than in application code that a second replica can bypass.
    """
    engine, _ = migrated_engine
    source = Source(name="confluence-prod", type=SourceType.CONFLUENCE)
    source_id = source.id  # client-generated, so it outlives the session

    with Session(engine) as session:
        session.add(source)
        session.add(Scan(source_id=source_id, trigger=ScanTrigger.MANUAL))
        session.commit()

    with Session(engine) as session, pytest.raises(IntegrityError):
        session.add(Scan(source_id=source_id, trigger=ScanTrigger.SCHEDULED))
        session.commit()

    # A finished scan is outside the index's WHERE clause, so the next scan is fine.
    with Session(engine) as session:
        first = session.exec(select(Scan)).one()
        first.status = ScanStatus.COMPLETED
        session.add(Scan(source_id=source_id, trigger=ScanTrigger.SCHEDULED))
        session.commit()

        assert len(session.exec(select(Scan)).all()) == 2


def test_downgrade_removes_everything(migrated_engine: tuple[Engine, Config]) -> None:
    engine, config = migrated_engine

    command.downgrade(config, "base")

    remaining = set(inspect(engine).get_table_names()) - {"alembic_version"}
    assert remaining == set()
