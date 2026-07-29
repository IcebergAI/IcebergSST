"""Settings behaviour, and the role split that keeps engines DB-credential-free."""

import pytest
from iceberg_core.config import (
    ApiSettings,
    EngineSettings,
    get_api_settings,
    get_engine_settings,
    reset_settings_cache,
)
from pydantic import SecretStr, ValidationError

# Anything that smells like a route to the database. An engine settings class
# must not grow a field matching one of these (ADR 0002).
FORBIDDEN_ENGINE_FIELD_FRAGMENTS = ("database", "postgres", "master_key", "pepper", "db_")


@pytest.fixture(autouse=True)
def _clear_settings_cache() -> None:
    reset_settings_cache()


def test_api_settings_read_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ICEBERG_DATABASE_URL", "postgresql+psycopg://api:pw@db:5432/iceberg")
    monkeypatch.setenv("ICEBERG_ENVIRONMENT", "prod")
    monkeypatch.setenv("ICEBERG_MASTER_KEY", "not-a-real-key")

    settings = get_api_settings()

    assert settings.database_url == "postgresql+psycopg://api:pw@db:5432/iceberg"
    assert settings.environment == "prod"
    assert settings.secret_store_backend == "env_key"  # noqa: S105  # a backend name, not a secret
    assert settings.master_key is not None
    assert settings.master_key.get_secret_value() == "not-a-real-key"


def test_api_settings_require_a_database_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ICEBERG_DATABASE_URL", raising=False)

    with pytest.raises(ValidationError):
        ApiSettings()  # type: ignore[call-arg]


def test_api_settings_reject_a_urlless_dsn() -> None:
    with pytest.raises(ValidationError):
        ApiSettings(database_url="iceberg")


def test_secrets_do_not_appear_in_repr() -> None:
    settings = ApiSettings(database_url="sqlite://", master_key=SecretStr("s3kr1t"))

    assert "s3kr1t" not in repr(settings)


def test_engine_settings_read_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ICEBERG_REDIS_URL", "redis://redis:6379/1")
    monkeypatch.setenv("ICEBERG_API_BASE_URL", "https://iceberg.internal")
    monkeypatch.setenv("ICEBERG_ENGINE_TOKEN", "engine-token")

    settings = get_engine_settings()

    assert settings.redis_url == "redis://redis:6379/1"
    assert settings.api_base_url == "https://iceberg.internal"
    assert settings.engine_token is not None


def test_engine_settings_have_no_route_to_the_database() -> None:
    """The invariant, expressed as a test: no DB field can appear on engines."""
    offenders = [
        name
        for name in EngineSettings.model_fields
        if any(fragment in name for fragment in FORBIDDEN_ENGINE_FIELD_FRAGMENTS)
    ]

    assert offenders == []


def test_engine_settings_ignore_database_variables_in_the_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A shared .env must not smuggle DB config into an engine process."""
    monkeypatch.setenv("ICEBERG_DATABASE_URL", "postgresql+psycopg://api:pw@db:5432/iceberg")

    settings = EngineSettings()

    assert not hasattr(settings, "database_url")
    assert "database_url" not in settings.model_dump()
