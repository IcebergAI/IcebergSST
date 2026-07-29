"""Development fixtures: idempotent, disabled, and sealed."""

import pytest
from iceberg_api.seed import DEMO_SOURCE_NAME, SeedRefused, main, seed
from iceberg_core.config import ApiSettings
from iceberg_core.models import Schedule, Source
from iceberg_core.secrets import EnvKeyBackend
from sqlmodel import Session, select

PLACEHOLDER_CREDENTIAL = "replace-with-a-real-api-token"


def test_seeding_creates_a_disabled_source_with_a_sealed_credential(
    session: Session, secret_store: EnvKeyBackend
) -> None:
    """Disabled on purpose: a scanner must not be pointed anywhere by a fixture."""
    source = seed(session, secret_store)
    session.commit()

    assert source.name == DEMO_SOURCE_NAME
    assert source.enabled is False
    assert source.credential_ref is not None
    assert PLACEHOLDER_CREDENTIAL not in source.credential_ref
    assert secret_store.open(source.credential_ref).get_secret_value() == PLACEHOLDER_CREDENTIAL
    assert session.exec(select(Schedule)).one().source_id == source.id


def test_seeding_twice_is_a_no_op(session: Session, secret_store: EnvKeyBackend) -> None:
    first = seed(session, secret_store)
    session.commit()

    again = seed(session, secret_store)
    session.commit()

    assert again.id == first.id
    assert len(session.exec(select(Source)).all()) == 1
    assert len(session.exec(select(Schedule)).all()) == 1


def test_seeding_is_refused_in_production() -> None:
    settings = ApiSettings(database_url="sqlite://", environment="prod")

    with pytest.raises(SeedRefused):
        main(settings)
