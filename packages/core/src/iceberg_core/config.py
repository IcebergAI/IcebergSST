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

import uuid
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
        # Compose hands every variable to every container, often as an empty string
        # (`${ICEBERG_ENGINE_ID:-}`). Treat empty as unset so a blank optional falls
        # back to its default instead of failing validation — an empty
        # ICEBERG_ENGINE_ID would otherwise crash the engine at startup rather than
        # dropping it into the documented no-heartbeat mode.
        env_ignore_empty=True,
    )

    environment: Environment = "dev"
    log_level: str = "INFO"


class SecretStoreSettings(CoreSettings):
    """Secret-store configuration (ADR 0007).

    Split out from :class:`ApiSettings` so the key-management CLI can run without
    a database URL — but still API-role-only: the master key never leaves this
    role, and engines receive the fingerprint pepper per task in the lease
    response (ADR 0009).
    """

    secret_store_backend: SecretStoreBackend = "env_key"  # noqa: S105  # a backend name
    master_key: SecretStr | None = None
    fingerprint_pepper_ref: str | None = None


class ApiSettings(SecretStoreSettings):
    """API-role settings: the only role that holds database credentials."""

    database_url: str
    redis_url: str = "redis://localhost:6379/0"
    db_echo: bool = False

    # ─── Authentication (ADR 0005) ────────────────────────────────────────────
    # Optional so the migration CLI, the seed command, and the test suite can
    # build settings without an identity provider. Routes that need OIDC call
    # oidc_config(), which fails loudly rather than half-configuring a login.
    oidc_issuer: str | None = None
    oidc_client_id: str | None = None
    oidc_client_secret: SecretStr | None = None
    oidc_redirect_url: str = "http://localhost:8000/api/v1/auth/callback"
    oidc_scopes: str = "openid profile email"

    #: Signs the session and login-state cookies (HS256). Rotating it logs
    #: everyone out, which is the intended blast radius.
    session_secret: SecretStr | None = None
    session_ttl_minutes: int = Field(default=480, ge=1)

    #: False only for local HTTP development; a session cookie sent in clear is
    #: a session anyone on the path can steal.
    cookie_secure: bool = True

    # ─── Background maintenance (#33, #35) ────────────────────────────────────
    #: The scheduler tick and lease reclaim run in-process on this cadence. Every
    #: replica runs them; a Postgres advisory lock decides which one acts.
    background_interval_seconds: int = Field(default=60, ge=5)

    # ─── Detection (#70) ──────────────────────────────────────────────────────
    #: Matches scoring below this are noise and are dropped. Configured here and
    #: delivered to engines in their lease rather than set in engine config: one
    #: value, one place to change it, and no way for a stale engine to run its own.
    #: Kept in step with `iceberg_detect.DEFAULT_CONFIDENCE_THRESHOLD` by a test —
    #: core cannot import detect, which depends on core.
    confidence_threshold: float = Field(default=0.5, ge=0.0, le=1.0)

    #: OIDC-only auth needs a seed administrator (docs/security.md § Bootstrap).
    #: Matched at user creation, so a later demotion is not undone by re-login.
    bootstrap_admin_subject: str | None = None
    bootstrap_admin_email: str | None = None

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
    #: This engine's own id, printed beside the token at enrolment. An engine
    #: names itself in its heartbeat path and the API checks the two agree, so a
    #: token without its id can lease and report but never renew a lease (#51).
    engine_id: uuid.UUID | None = None
    metrics_port: int = Field(default=DEFAULT_METRICS_PORT, ge=1, le=65535)

    #: Concurrent scan tasks per engine process. Each holds a lease and an HTTP
    #: connection to the API, so this is the knob that trades scan throughput
    #: against load on the control plane; scale replicas as well (`make scale`).
    worker_threads: int = Field(default=4, ge=1, le=64)


@lru_cache(maxsize=1)
def get_api_settings() -> ApiSettings:
    """Process-wide API settings, read from the environment on first use."""
    return ApiSettings()  # type: ignore[call-arg]  # values come from the environment


@lru_cache(maxsize=1)
def get_secret_store_settings() -> SecretStoreSettings:
    """Process-wide secret-store settings (used by the API and the key CLI)."""
    return SecretStoreSettings()


@lru_cache(maxsize=1)
def get_engine_settings() -> EngineSettings:
    """Process-wide engine settings, read from the environment on first use."""
    return EngineSettings()


def reset_settings_cache() -> None:
    """Drop cached settings. For tests that manipulate the environment."""
    get_api_settings.cache_clear()
    get_secret_store_settings.cache_clear()
    get_engine_settings.cache_clear()
