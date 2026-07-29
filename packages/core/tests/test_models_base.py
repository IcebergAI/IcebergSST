"""The base model conventions every table inherits."""

from datetime import UTC

from iceberg_core.enums import ScanStatus
from iceberg_core.models import IcebergModel, TimestampedModel
from iceberg_core.models.base import (
    NAMING_CONVENTION,
    enum_type,
    json_type,
    metadata,
    utc_now,
)
from sqlalchemy.dialects import postgresql, sqlite


def test_naming_convention_is_installed_on_the_shared_metadata() -> None:
    assert metadata.naming_convention == NAMING_CONVENTION


def test_utc_now_is_timezone_aware_utc() -> None:
    now = utc_now()

    assert now.tzinfo is not None
    assert now.utcoffset() == UTC.utcoffset(None)


def test_json_columns_are_jsonb_on_postgres_and_json_elsewhere() -> None:
    column_type = json_type()
    # SQLAlchemy's dialect factories are unannotated.
    pg_dialect = postgresql.dialect()  # type: ignore[no-untyped-call]
    sqlite_dialect = sqlite.dialect()

    assert isinstance(column_type.dialect_impl(pg_dialect), postgresql.JSONB)
    assert not isinstance(column_type.dialect_impl(sqlite_dialect), postgresql.JSONB)


def test_enums_are_stored_as_checked_strings_not_native_enums() -> None:
    column_type = enum_type(ScanStatus, name="scan_status")

    assert column_type.native_enum is False
    assert set(column_type.enums) == {member.value for member in ScanStatus}


def test_ids_are_unique_per_instance() -> None:
    class _Scratch(IcebergModel):
        pass

    assert _Scratch().id != _Scratch().id


def test_timestamps_default_to_aware_utc() -> None:
    class _Scratch(TimestampedModel):
        pass

    row = _Scratch()

    assert row.created_at.tzinfo is not None
    assert row.updated_at.tzinfo is not None
