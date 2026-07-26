"""Typed settings for the IcebergSST roles (issue #23).

Settings are **split by role on purpose**. ``EngineSettings`` does not declare a
database URL at all, so an engine cannot be handed one by accident — a mistyped
compose file or a stray env var has nowhere to land (ADR 0002, issue #52). Only
``ApiSettings`` knows how to reach Postgres.

All values are read through pydantic-settings with the ``ICEBERG_`` prefix, never
by direct ``os.environ`` access. Note that pydantic-settings loads ``.env`` into
the settings object only — it never populates ``os.environ`` — so code that
bypasses these classes will not see configured values.
"""

from functools import lru_cache

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

ENV_PREFIX = "ICEBERG_"

_BASE_CONFIG = SettingsConfigDict(
    env_prefix=ENV_PREFIX,
    env_file=".env",
    env_file_encoding="utf-8",
    extra="ignore",
)


class CommonSettings(BaseSettings):
    """Settings both roles share. Deliberately contains no database fields."""

    model_config = _BASE_CONFIG

    log_level: str = "INFO"
    metrics_port: int = 9191
    redis_url: str | None = None


class ApiSettings(CommonSettings):
    """API-role settings. The only place a database URL is declared."""

    model_config = _BASE_CONFIG

    database_url: str = Field(
        default="postgresql+asyncpg://iceberg:iceberg@localhost:5432/iceberg",
        description="Async SQLAlchemy DSN. Must use the asyncpg driver.",
    )
    db_echo: bool = False
    db_pool_size: int = 5
    db_max_overflow: int = 10

    # Master key for the EnvKeyBackend secret store (ADR 0007). Held by the API
    # only: engines receive decrypted, task-scoped material in the lease response
    # (ADR 0009) and never unwrap ciphertext themselves.
    secret_key: SecretStr | None = None
    fingerprint_pepper: SecretStr | None = None


class EngineSettings(CommonSettings):
    """Engine-role settings.

    No ``database_url``, no ``secret_key``, no ``fingerprint_pepper``: engines get
    the source credential and the pepper from the task lease response, per
    ADR 0009. If you find yourself wanting to add one of those here, the design
    has gone wrong.
    """

    model_config = _BASE_CONFIG

    api_base_url: str = "http://localhost:8000"
    engine_token: SecretStr | None = None


@lru_cache(maxsize=1)
def get_api_settings() -> ApiSettings:
    """Process-wide API settings (cached; call ``.cache_clear()`` in tests)."""
    return ApiSettings()


@lru_cache(maxsize=1)
def get_engine_settings() -> EngineSettings:
    """Process-wide engine settings (cached; call ``.cache_clear()`` in tests)."""
    return EngineSettings()
