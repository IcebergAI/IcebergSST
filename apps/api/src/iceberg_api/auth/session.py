"""Session and login-state cookies.

A session is a signed, expiring token in an ``HttpOnly`` cookie carrying three
things: which user it belongs to, when it was issued, and that session's CSRF
token. It carries **no** authorization state — no role, no permissions. Every
request re-loads the user from the database, so demoting or disabling someone
takes effect on their next request instead of whenever their cookie happens to
expire (#69).

The login-state cookie is the same mechanism with a short lifetime, holding the
OAuth ``state``, the OIDC ``nonce``, and the PKCE verifier between the redirect
out to the identity provider and the callback back. Keeping it in a signed cookie
rather than server-side state means the flow works across API replicas without a
shared store.

Both are signed with ``ICEBERG_SESSION_SECRET`` (HS256). Rotating that secret
invalidates every session, which is the intended blast radius.
"""

import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
from fastapi import Response
from iceberg_core.config import ApiSettings

SESSION_COOKIE = "iceberg_session"  # a cookie name
LOGIN_COOKIE = "iceberg_login"  # a cookie name
ALGORITHM = "HS256"

#: How long the OIDC round trip may take before the state cookie expires. Long
#: enough for a password prompt and MFA, short enough to bound replay.
LOGIN_STATE_TTL = timedelta(minutes=10)

#: RFC 7518 §3.2: an HS256 key shorter than the hash output weakens the MAC.
#: PyJWT warns; a security tool should refuse to start instead.
MIN_SESSION_SECRET_BYTES = 32

_SESSION_AUDIENCE = "iceberg:session"
_LOGIN_AUDIENCE = "iceberg:login"
_FLASH_AUDIENCE = "iceberg:flash"

#: How long a message survives being carried across a redirect. Long enough for
#: the browser to follow one, short enough that a URL pasted into a chat later
#: shows nothing rather than a stale complaint.
FLASH_TTL = timedelta(minutes=2)


class SessionError(Exception):
    """A cookie was missing, malformed, expired, or not signed by us."""


class AuthConfigError(Exception):
    """Authentication is not configured (no session secret, no OIDC)."""


@dataclass(frozen=True, slots=True)
class SessionData:
    """The contents of a valid session cookie."""

    user_id: uuid.UUID
    csrf_token: str
    issued_at: datetime


@dataclass(frozen=True, slots=True)
class LoginState:
    """In-flight OIDC login state, carried across the provider round trip."""

    state: str
    nonce: str
    code_verifier: str
    #: Where to send the browser after a successful login. Path-only —
    #: see :func:`safe_return_path`.
    return_path: str = "/"


def signing_key(settings: ApiSettings) -> str:
    """Return the cookie signing secret, or explain what is wrong with it."""
    hint = "generate one with `python -m iceberg_core.secrets generate-master-key`"
    if settings.session_secret is None:
        raise AuthConfigError(f"ICEBERG_SESSION_SECRET is not set; {hint}")

    secret = settings.session_secret.get_secret_value()
    if len(secret.encode()) < MIN_SESSION_SECRET_BYTES:
        raise AuthConfigError(
            f"ICEBERG_SESSION_SECRET must be at least {MIN_SESSION_SECRET_BYTES} bytes "
            f"(RFC 7518 §3.2 for HS256); {hint}"
        )
    return secret


def new_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def issue_session(
    user_id: uuid.UUID, settings: ApiSettings, *, csrf_token: str | None = None
) -> str:
    """Mint a session token for ``user_id``."""
    issued_at = datetime.now(UTC)
    payload = {
        "sub": str(user_id),
        "csrf": csrf_token or new_csrf_token(),
        "iat": issued_at,
        "exp": issued_at + timedelta(minutes=settings.session_ttl_minutes),
        "aud": _SESSION_AUDIENCE,
    }
    return jwt.encode(payload, signing_key(settings), algorithm=ALGORITHM)


def read_session(token: str, settings: ApiSettings) -> SessionData:
    """Verify a session token and return its contents."""
    claims = _decode(token, settings, audience=_SESSION_AUDIENCE)
    try:
        return SessionData(
            user_id=uuid.UUID(claims["sub"]),
            csrf_token=claims["csrf"],
            issued_at=datetime.fromtimestamp(claims["iat"], tz=UTC),
        )
    except (KeyError, ValueError) as exc:
        raise SessionError("session cookie is malformed") from exc


def issue_login_state(state: LoginState, settings: ApiSettings) -> str:
    """Mint the short-lived cookie that carries an in-flight login."""
    issued_at = datetime.now(UTC)
    payload = {
        "state": state.state,
        "nonce": state.nonce,
        "verifier": state.code_verifier,
        "next": state.return_path,
        "iat": issued_at,
        "exp": issued_at + LOGIN_STATE_TTL,
        "aud": _LOGIN_AUDIENCE,
    }
    return jwt.encode(payload, signing_key(settings), algorithm=ALGORITHM)


def read_login_state(token: str, settings: ApiSettings) -> LoginState:
    """Verify a login-state token and return its contents."""
    claims = _decode(token, settings, audience=_LOGIN_AUDIENCE)
    try:
        return LoginState(
            state=claims["state"],
            nonce=claims["nonce"],
            code_verifier=claims["verifier"],
            return_path=claims.get("next", "/"),
        )
    except KeyError as exc:
        raise SessionError("login cookie is malformed") from exc


def safe_return_path(candidate: str | None) -> str:
    """Reduce a caller-supplied redirect target to a local path.

    ``?next=`` is attacker-controlled: anything that could send the browser to
    another origin after login is an open redirect, so only a single-slash
    absolute path survives. ``//evil.example`` is protocol-relative and is
    rejected, as is a backslash variant such as ``/\\evil.example`` — a browser's
    URL parser treats the backslash as a slash, so it is protocol-relative too —
    and anything carrying a control character.
    """
    if (
        not candidate
        or not candidate.startswith("/")
        or candidate.startswith(("//", "/\\"))
        or "\\" in candidate
        or any(char < " " or char == "\x7f" for char in candidate)
    ):
        return "/"
    return candidate


def set_session_cookie(response: Response, token: str, settings: ApiSettings) -> None:
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=settings.session_ttl_minutes * 60,
        httponly=True,
        secure=settings.cookie_secure,
        # Lax, not Strict: the OIDC callback is a top-level cross-site
        # navigation, and Strict would drop the cookie on arrival.
        samesite="lax",
        path="/",
    )


def clear_session_cookie(response: Response, settings: ApiSettings) -> None:
    response.delete_cookie(
        SESSION_COOKIE,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
        path="/",
    )


def set_login_cookie(response: Response, token: str, settings: ApiSettings) -> None:
    response.set_cookie(
        LOGIN_COOKIE,
        token,
        max_age=int(LOGIN_STATE_TTL.total_seconds()),
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
        path="/",
    )


def clear_login_cookie(response: Response, settings: ApiSettings) -> None:
    response.delete_cookie(
        LOGIN_COOKIE,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
        path="/",
    )


def issue_flash(message: str, settings: ApiSettings, *, ttl: timedelta = FLASH_TTL) -> str:
    """Sign a message so it can ride a redirect without becoming forgeable (#197).

    These messages are the API's own prose about why a save failed, and they are
    rendered inside the console's own chrome. Carried as plain query text they
    were the console rendering **attacker-chosen words in a trusted frame** — a
    crafted `/login?error=…` could tell somebody their account was disabled and
    give them a number to call. Autoescaping stops it being script; nothing
    stopped it being convincing.

    Signed rather than replaced by an enum of codes because the API's sentence is
    the useful part ("base_url: is not a valid URL"), and rather than a
    server-side flash because this deployment keeps no per-user state between
    requests — the same reason the login state rides in a cookie.
    """
    issued_at = datetime.now(UTC)
    payload = {
        "msg": message,
        "iat": issued_at,
        "exp": issued_at + ttl,
        "aud": _FLASH_AUDIENCE,
    }
    return jwt.encode(payload, signing_key(settings), algorithm=ALGORITHM)


def read_flash(token: str | None, settings: ApiSettings) -> str | None:
    """The message this deployment signed, or None for anything else.

    Every failure is None: unsigned, expired, signed for another audience, or
    simply absent. A page that cannot tell them apart shows no banner, which is
    the correct outcome for all four.
    """
    if not token:
        return None
    try:
        claims = _decode(token, settings, audience=_FLASH_AUDIENCE)
    except SessionError, AuthConfigError:
        return None
    message = claims.get("msg")
    return message if isinstance(message, str) else None


def _decode(token: str, settings: ApiSettings, *, audience: str) -> dict[str, Any]:
    """Verify signature, expiry, and audience.

    The audience is what stops a login-state cookie from being replayed as a
    session: both are signed with the same key, so the claim is the only thing
    keeping them apart.
    """
    try:
        decoded: dict[str, Any] = jwt.decode(
            token,
            signing_key(settings),
            algorithms=[ALGORITHM],
            audience=audience,
            options={"require": ["exp", "iat", "aud"]},
        )
    except jwt.PyJWTError as exc:
        raise SessionError("cookie is not valid") from exc
    return decoded
