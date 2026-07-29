"""Issue #23 acceptance: settings load from env, split so the engine has no DB URL."""

import pytest
from iceberg_core.config import ApiSettings, CommonSettings, EngineSettings, get_api_settings
from pydantic import SecretStr


def test_settings_load_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ICEBERG_METRICS_PORT", "9999")
    monkeypatch.setenv("ICEBERG_LOG_LEVEL", "DEBUG")
    settings = CommonSettings()
    assert settings.metrics_port == 9999
    assert settings.log_level == "DEBUG"


def test_iceberg_prefix_is_required(monkeypatch: pytest.MonkeyPatch) -> None:
    """A bare METRICS_PORT must not be picked up — the prefix is the contract."""
    monkeypatch.setenv("METRICS_PORT", "1234")
    assert CommonSettings().metrics_port == 9191


def test_engine_settings_have_no_database_url() -> None:
    """ADR 0002 / #52: an engine cannot be handed a DB URL by accident.

    The field does not exist, so a stray ICEBERG_DATABASE_URL in the engine's
    environment has nowhere to land.
    """
    assert "database_url" not in EngineSettings.model_fields
    assert "secret_key" not in EngineSettings.model_fields
    assert "fingerprint_pepper" not in EngineSettings.model_fields


def test_stray_database_url_is_ignored_by_engine_settings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ICEBERG_DATABASE_URL", "postgresql+asyncpg://leak:leak@db/leak")
    settings = EngineSettings()
    assert not hasattr(settings, "database_url")
    assert "leak" not in settings.model_dump_json()


def test_api_settings_own_the_database_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ICEBERG_DATABASE_URL", "postgresql+asyncpg://u:p@host/db")
    assert ApiSettings().database_url == "postgresql+asyncpg://u:p@host/db"


def test_secret_material_is_not_stringified(monkeypatch: pytest.MonkeyPatch) -> None:
    """SecretStr keeps the key out of tracebacks and repr()."""
    monkeypatch.setenv("ICEBERG_SECRET_KEY", "fake-master-key-value")
    settings = ApiSettings()
    assert isinstance(settings.secret_key, SecretStr)
    assert "fake-master-key-value" not in repr(settings)
    assert settings.secret_key.get_secret_value() == "fake-master-key-value"


def test_engine_settings_carry_the_api_endpoint() -> None:
    """Engines reach the API and Redis, nothing else (ADR 0002)."""
    assert EngineSettings().api_base_url.startswith("http")


def test_get_api_settings_is_cached() -> None:
    get_api_settings.cache_clear()
    assert get_api_settings() is get_api_settings()
    get_api_settings.cache_clear()
