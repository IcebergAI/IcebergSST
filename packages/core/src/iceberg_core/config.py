"""Typed settings for the IcebergSST roles.

Configuration is read from the environment (prefix ``ICEBERG_``) exactly once,
at the edges of the process, and passed around as objects. Nothing deeper in the
codebase reads ``os.environ`` — that is what makes the role split auditable.

The split is the point: :class:`ApiSettings` carries the database URL and the
secret-store master key; :class:`EngineSettings` carries neither and has no
field that could hold them (ADR 0002). An engine that wanted DB credentials
would have to grow a new settings field, which is a reviewable change rather
than an accident of deployment.
"""

from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

Environment = Literal["dev", "test", "prod"]
SecretStoreBackend = Literal["env_key", "vault"]

DEFAULT_METRICS_PORT = 9191


class CoreSettings(BaseSettings):
    """Settings shared by every role.

    ``extra="ignore"`` is deliberate: a container is routinely handed the whole
    ``.env`` file, so each role must tolerate variables belonging to the other.
    """

    model_config = SettingsConfigDict(
        env_prefix="ICEBERG_",
        extra="ignore",
        frozen=True,
    )

    environment: Environment = "dev"
    log_level: str = "INFO"


class ApiSettings(CoreSettings):
    """API-role settings: the only role that holds database credentials."""

    database_url: str
    redis_url: str = "redis://localhost:6379/0"

    # Secret store (ADR 0007). The master key never leaves this role: engines
    # receive the fingerprint pepper per task in the lease response (ADR 0009).
    secret_store_backend: SecretStoreBackend = "env_key"  # noqa: S105  # a backend name
    master_key: SecretStr | None = None
    fingerprint_pepper_ref: str | None = None

    db_echo: bool = False

    @field_validator("database_url", "redis_url")
    @classmethod
    def _require_url_scheme(cls, value: str) -> str:
        if "://" not in value:
            raise ValueError("expected a URL of the form scheme://…")
        return value


class EngineSettings(CoreSettings):
    """Engine-role settings: Redis in, API out, and nothing else.

    There is intentionally no database field here, and no master key — see
    ``tests/test_config.py``, which fails if one appears.
    """

    redis_url: str = "redis://localhost:6379/0"
    api_base_url: str = "http://localhost:8000"
    engine_token: SecretStr | None = None
    metrics_port: int = Field(default=DEFAULT_METRICS_PORT, ge=1, le=65535)


@lru_cache(maxsize=1)
def get_api_settings() -> ApiSettings:
    """Process-wide API settings, read from the environment on first use."""
    return ApiSettings()  # type: ignore[call-arg]  # values come from the environment


@lru_cache(maxsize=1)
def get_engine_settings() -> EngineSettings:
    """Process-wide engine settings, read from the environment on first use."""
    return EngineSettings()


def reset_settings_cache() -> None:
    """Drop cached settings. For tests that manipulate the environment."""
    get_api_settings.cache_clear()
    get_engine_settings.cache_clear()
