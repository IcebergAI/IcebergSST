"""Session and login-state cookie behaviour."""

import uuid
from datetime import UTC, datetime, timedelta

import jwt
import pytest
from fastapi import Response
from iceberg_api.auth.session import (
    LOGIN_COOKIE,
    SESSION_COOKIE,
    AuthConfigError,
    LoginState,
    SessionError,
    clear_session_cookie,
    issue_login_state,
    issue_session,
    read_login_state,
    read_session,
    safe_return_path,
    set_session_cookie,
)
from iceberg_core.config import ApiSettings
from pydantic import SecretStr

USER_ID = uuid.UUID("11111111-2222-3333-4444-555555555555")
# HS256 needs 32+ bytes (RFC 7518 §3.2), which signing_key() enforces.
TEST_SECRET = "session-signing-secret-for-tests-0123456789"
OTHER_SECRET = "a-completely-different-secret-0123456789012"


@pytest.fixture(name="settings")
def settings_fixture() -> ApiSettings:
    return ApiSettings(
        database_url="sqlite://",
        session_secret=SecretStr(TEST_SECRET),
        cookie_secure=True,
    )


def test_session_round_trips(settings: ApiSettings) -> None:
    token = issue_session(USER_ID, settings, csrf_token="csrf-value")

    data = read_session(token, settings)

    assert data.user_id == USER_ID
    assert data.csrf_token == "csrf-value"
    assert data.issued_at <= datetime.now(UTC)


def test_a_session_signed_with_another_secret_is_rejected(settings: ApiSettings) -> None:
    stranger = settings.model_copy(update={"session_secret": SecretStr(OTHER_SECRET)})
    token = issue_session(USER_ID, stranger)

    with pytest.raises(SessionError):
        read_session(token, settings)


def test_a_tampered_session_is_rejected(settings: ApiSettings) -> None:
    token = issue_session(USER_ID, settings)
    header, payload, signature = token.split(".")

    with pytest.raises(SessionError):
        read_session(f"{header}.{payload}x.{signature}", settings)


def test_an_expired_session_is_rejected(settings: ApiSettings) -> None:
    """Constructed directly, since the TTL is minutes at its smallest."""
    issued = datetime.now(UTC) - timedelta(hours=2)
    token = jwt.encode(
        {
            "sub": str(USER_ID),
            "csrf": "x",
            "iat": issued,
            "exp": issued + timedelta(minutes=1),
            "aud": "iceberg:session",
        },
        TEST_SECRET,
        algorithm="HS256",
    )

    with pytest.raises(SessionError):
        read_session(token, settings)


def test_a_login_cookie_cannot_be_replayed_as_a_session(settings: ApiSettings) -> None:
    """Both are signed with the same key; the audience claim keeps them apart."""
    login_token = issue_login_state(LoginState(state="s", nonce="n", code_verifier="v"), settings)

    with pytest.raises(SessionError):
        read_session(login_token, settings)


def test_a_session_cannot_be_replayed_as_login_state(settings: ApiSettings) -> None:
    with pytest.raises(SessionError):
        read_login_state(issue_session(USER_ID, settings), settings)


def test_login_state_round_trips(settings: ApiSettings) -> None:
    state = LoginState(state="st", nonce="no", code_verifier="ver", return_path="/findings")

    assert read_login_state(issue_login_state(state, settings), settings) == state


def test_without_a_session_secret_the_failure_names_the_variable() -> None:
    unset = ApiSettings(database_url="sqlite://")

    with pytest.raises(AuthConfigError, match="ICEBERG_SESSION_SECRET is not set"):
        issue_session(USER_ID, unset)


def test_a_short_session_secret_is_refused_rather_than_warned_about(
    settings: ApiSettings,
) -> None:
    """PyJWT only warns about a weak HMAC key; refusing is the better default."""
    weak = settings.model_copy(update={"session_secret": SecretStr("too-short")})

    with pytest.raises(AuthConfigError, match="at least 32 bytes"):
        issue_session(USER_ID, weak)


@pytest.mark.parametrize(
    ("candidate", "expected"),
    [
        ("/findings", "/findings"),
        ("/findings?state=open", "/findings?state=open"),
        (None, "/"),
        ("", "/"),
        ("//evil.example/phish", "/"),
        ("https://evil.example", "/"),
        ("javascript:alert(1)", "/"),
        ("../../etc/passwd", "/"),
    ],
)
def test_return_paths_cannot_leave_this_origin(candidate: str | None, expected: str) -> None:
    """`?next=` is attacker-controlled; an open redirect after login is a phish."""
    assert safe_return_path(candidate) == expected


def test_session_cookie_flags_are_hostile_to_theft(settings: ApiSettings) -> None:
    response = Response()

    set_session_cookie(response, "token-value", settings)
    header = response.headers["set-cookie"]

    assert header.startswith(f"{SESSION_COOKIE}=token-value")
    assert "HttpOnly" in header
    assert "Secure" in header
    # Lax rather than Strict: the OIDC callback is a cross-site top-level
    # navigation and Strict would drop the cookie on the way in.
    assert "SameSite=lax" in header
    assert "Path=/" in header


def test_insecure_cookies_are_opt_in_only(settings: ApiSettings) -> None:
    development = settings.model_copy(update={"cookie_secure": False})
    response = Response()

    set_session_cookie(response, "token-value", development)

    assert "Secure" not in response.headers["set-cookie"]


def test_clearing_a_session_expires_the_cookie(settings: ApiSettings) -> None:
    response = Response()

    clear_session_cookie(response, settings)
    header = response.headers["set-cookie"]

    assert header.startswith(f"{SESSION_COOKIE}=")
    assert "Max-Age=0" in header or "expires=Thu, 01 Jan 1970" in header.lower()


def test_login_and_session_cookies_have_distinct_names() -> None:
    assert SESSION_COOKIE != LOGIN_COOKIE
