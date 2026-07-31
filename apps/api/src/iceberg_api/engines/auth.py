"""Engine authentication (#35 — ADR 0002).

Engines authenticate with a per-engine bearer token. The database stores only its
SHA-256 hash: the API can verify a token it is shown but cannot reproduce one, so a
database compromise does not hand an attacker a fleet of engine credentials.

A plain hash, not a password KDF, on purpose. These are 256-bit random tokens, not
chosen secrets — there is no dictionary to attack, and a slow KDF on every lease and
heartbeat would be a real cost for no gain.

The separation from human auth is deliberate and total: this dependency ignores
session cookies, and the human dependencies ignore this header. An engine token
cannot read findings and a browser session cannot post results (docs/api.md).
"""

import hashlib
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated

import structlog
from fastapi import Depends, HTTPException, Request, status
from iceberg_core.config import ApiSettings
from iceberg_core.enums import EngineStatus
from iceberg_core.models import Engine
from sqlmodel import Session, col, select

from iceberg_api import ratelimit
from iceberg_api.auth.dependencies import SessionDep, SettingsDep
from iceberg_api.ratelimit import RateLimitStoreDep

TOKEN_BYTES = 32
BEARER_PREFIX = "Bearer "

logger = structlog.get_logger()


@dataclass(frozen=True, slots=True)
class MintedToken:
    """A new engine credential. The plaintext exists only in this object."""

    engine: Engine
    #: Shown once, at registration. It is not recoverable afterwards.
    token: str


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def mint_token(engine: Engine) -> MintedToken:
    """Generate a token for ``engine`` and store its hash."""
    token = secrets.token_urlsafe(TOKEN_BYTES)
    engine.token_hash = hash_token(token)
    return MintedToken(engine=engine, token=token)


def presented_token(request: Request) -> str | None:
    header = request.headers.get("authorization", "")
    if header.startswith(BEARER_PREFIX):
        return header.removeprefix(BEARER_PREFIX).strip() or None
    return None


def current_engine(
    request: Request,
    db: SessionDep,
    settings: SettingsDep,
    store: RateLimitStoreDep,
) -> Engine:
    """Authenticate the calling engine, or reject with 401.

    An ``offline`` or ``draining`` engine is still allowed to authenticate: it may
    need to finish reporting work it already leased. Refusing here would strand
    results the API asked for.

    Two rate limits apply, and which one applies is the interesting part (#63).
    **Rejections** are charged to the client address: that is the bucket that
    bounds credential stuffing and makes it visible. **Accepted** requests are
    charged to the engine, not the address, because a fleet behind one NAT must
    not share a budget — `--scale engine=N` has to keep working.
    """
    token = presented_token(request)
    if not token:
        _charge_rejection(request, store, settings)
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "engine token required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    engine = db.exec(select(Engine).where(col(Engine.token_hash) == hash_token(token))).first()
    if engine is None:
        # Same message as a missing token: which of the two failed is not the
        # caller's business.
        logger.info("engine_token_rejected")
        _charge_rejection(request, store, settings)
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "engine token required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    ratelimit.enforce(
        request,
        store,
        settings,
        bucket="engine",
        identity=str(engine.id),
        limit=settings.engine_rate_limit,
        window_seconds=settings.engine_rate_limit_window_seconds,
    )
    return engine


def _charge_rejection(
    request: Request,
    store: ratelimit.RateLimitStore,
    settings: ApiSettings,
) -> None:
    """Count a failed authentication against the caller's address.

    Charging only failures is deliberate: a healthy fleet never touches this
    bucket, so the limit can be small enough to matter without any risk of
    throttling legitimate engines.
    """
    ratelimit.enforce(
        request,
        store,
        settings,
        bucket="engine-auth",
        identity=ratelimit.client_address(request, trusted_proxy_hops=settings.trusted_proxy_hops),
        limit=settings.engine_auth_rate_limit,
        window_seconds=settings.engine_rate_limit_window_seconds,
    )


CurrentEngine = Annotated[Engine, Depends(current_engine)]


def record_heartbeat(
    db: Session,
    engine: Engine,
    *,
    version: str | None = None,
    rulepack: dict[str, object] | None = None,
    now: datetime | None = None,
) -> Engine:
    """Stamp a heartbeat, and treat the engine as active again if it had gone quiet."""
    engine.last_heartbeat_at = now or datetime.now(UTC)
    if version:
        engine.version = version
    if rulepack is not None:
        # Replaced, not merged: an engine that restarted onto a smaller pack must
        # not appear to still be running the rules it dropped (#70).
        engine.rulepack = rulepack
    if engine.status is EngineStatus.OFFLINE:
        engine.status = EngineStatus.ACTIVE
    db.add(engine)
    db.commit()
    db.refresh(engine)
    return engine
