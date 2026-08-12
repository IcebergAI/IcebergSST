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

    #: The pepper being rotated *out*. Set only during a rotation window (#64).
    #:
    #: Every finding identity is an HMAC keyed by the pepper, and the plaintext
    #: secret that produced it was never stored — so a new pepper cannot be
    #: applied to existing rows by recomputation. Instead, while both are set,
    #: engines report each finding under both peppers and ingest re-keys a match
    #: found under the old one, carrying its triage state across. Unset it once a
    #: full scan cycle has completed.
    #:
    #: docs/runbooks/key-rotation.md is the procedure; do not set this casually.
    previous_fingerprint_pepper_ref: str | None = None


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

    #: Silence after which the maintenance round marks an engine ``offline``. An
    #: engine cannot report that it died, so the only evidence is a heartbeat that
    #: stopped; this is how long to wait before believing it. Comfortably longer
    #: than the lease window, so a busy engine mid-fetch is never called dead.
    engine_offline_after_seconds: int = Field(default=900, ge=60)

    # ─── Detection (#70) ──────────────────────────────────────────────────────
    #: Matches scoring below this are noise and are dropped. Configured here and
    #: delivered to engines in their lease rather than set in engine config: one
    #: value, one place to change it, and no way for a stale engine to run its own.
    #: Kept in step with `iceberg_detect.DEFAULT_CONFIDENCE_THRESHOLD` by a test —
    #: core cannot import detect, which depends on core.
    confidence_threshold: float = Field(default=0.5, ge=0.0, le=1.0)

    #: Deployment-wide kill switch for the only feature that deliberately sends
    #: a detected credential to its provider (ADR 0010). Database policies are a
    #: second, independent opt-in; neither can enable validation alone.
    secret_validation_enabled: bool = False

    #: OIDC-only auth needs a seed administrator (docs/security.md § Bootstrap).
    #: Matched at user creation, so a later demotion is not undone by re-login.
    bootstrap_admin_subject: str | None = None
    bootstrap_admin_email: str | None = None

    # ─── Notification dispatch (#60) ──────────────────────────────────────────
    # Channel *configuration* lives in the database, because an analyst edits it.
    # These are deployment facts — which relay to use, how hard to try — so they
    # are configuration, and they are api-role only: engines never dispatch.
    #: Unset disables email delivery. Email channels then fail their deliveries
    #: with a clear error rather than appearing to work.
    smtp_host: str | None = None
    smtp_port: int = Field(default=587, ge=1, le=65535)
    smtp_username: str | None = None
    smtp_password: SecretStr | None = None
    #: STARTTLS on a submission port. Turn off only for a relay on localhost.
    smtp_starttls: bool = True
    smtp_from: str = "icebergsst@localhost"
    #: A dispatch must never be the reason an API worker is tied up.
    smtp_timeout_seconds: float = Field(default=10.0, gt=0, le=120)

    #: Per-attempt ceiling for a webhook POST. Deliberately short: the receiver is
    #: operator-supplied and may be a black hole.
    webhook_timeout_seconds: float = Field(default=10.0, gt=0, le=120)

    #: Attempts before a delivery is marked `failed`. The row is kept either way —
    #: giving up is recorded, not silent.
    notification_max_attempts: int = Field(default=5, ge=1, le=20)
    #: First retry delay; doubles each attempt, so the default 60s reaches roughly
    #: 16 minutes by the fifth. Long enough to ride out a receiver's restart.
    notification_retry_backoff_seconds: int = Field(default=60, ge=1)
    #: Deliveries attempted per maintenance round. Bounds how long one round can
    #: take when a channel is timing out.
    notification_batch_size: int = Field(default=50, ge=1, le=1000)
    # ─── Rate limiting (#63) ──────────────────────────────────────────────────
    # Ceilings on the endpoints an unauthenticated caller can reach. Not the last
    # line of defence — authentication is — so these are set to stop floods, not
    # to meter usage (docs/security.md § Rate limiting).
    rate_limit_enabled: bool = True
    #: Shared counters across replicas. Off falls back to per-process counters,
    #: which are exact for a single replica and per-replica for several.
    rate_limit_use_redis: bool = True

    #: `/auth/login` and `/auth/callback`, per client address. Generous enough for
    #: a person retrying a failed login, small enough that nobody drives the
    #: identity provider through us.
    auth_rate_limit: int = Field(default=20, ge=1)
    auth_rate_limit_window_seconds: int = Field(default=60, ge=1)

    #: Per authenticated engine, not per address: a fleet behind one NAT must not
    #: share a budget. Sized for `worker_threads` engines heartbeating and leasing
    #: without ever approaching it.
    engine_rate_limit: int = Field(default=600, ge=1)
    engine_rate_limit_window_seconds: int = Field(default=60, ge=1)

    #: Rejected engine-token presentations, per client address — the bucket that
    #: makes credential stuffing visible and bounded.
    engine_auth_rate_limit: int = Field(default=30, ge=1)

    #: How many reverse proxies sit in front. Zero means the peer address is the
    #: truth and `X-Forwarded-For` is ignored, which is the safe default: a caller
    #: can put anything in that header, and trusting it would let an attacker take
    #: a fresh identity per request.
    trusted_proxy_hops: int = Field(default=0, ge=0, le=10)

    # ─── Data retention (#73) ─────────────────────────────────────────────────
    # Findings and their append-only event trail grow forever otherwise. Every
    # window is *off by default*: this database is evidence, and deleting some of
    # it has to be a decision an operator made, not something that started
    # happening because they upgraded (docs/retention.md).
    #
    # 0 means "keep forever" for all three.
    #
    #: Auto-resolved findings older than this are deleted. Only ``auto`` — a
    #: finding an analyst resolved, accepted the risk on, or marked a false
    #: positive is a decision, and decisions are not noise to be cleaned up.
    retention_resolved_findings_days: int = Field(default=0, ge=0)
    #: FindingEvent rows older than this are deleted, except the ones belonging to
    #: findings that are still open.
    retention_finding_events_days: int = Field(default=0, ge=0)
    #: AuditEvent rows older than this are deleted. Usually the window a
    #: compliance regime names; think before shortening it.
    retention_audit_events_days: int = Field(default=0, ge=0)
    #: Rows deleted per table per round, so one purge cannot lock a table for
    #: minutes on a database that has never been purged before.
    retention_batch_size: int = Field(default=1000, ge=1, le=100_000)

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
def get_core_settings() -> CoreSettings:
    """The settings every role shares, and the only ones with no required field.

    Exists for code that needs `environment` but must not require a database URL
    to answer — the browser security headers, which key HSTS and
    ``upgrade-insecure-requests`` off it and are built once per process before
    anything has established that this process is the API role.
    """
    return CoreSettings()


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
    get_core_settings.cache_clear()
    get_api_settings.cache_clear()
    get_secret_store_settings.cache_clear()
    get_engine_settings.cache_clear()
