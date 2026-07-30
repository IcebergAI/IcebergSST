"""The login flow end to end, through the app (#28, #30)."""

from urllib.parse import parse_qs, urlparse

import httpx2
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from iceberg_api.auth.dependencies import get_settings
from iceberg_api.auth.routes import get_oidc_client
from iceberg_api.auth.session import LOGIN_COOKIE, SESSION_COOKIE, read_login_state
from iceberg_core.config import ApiSettings
from iceberg_core.enums import UserRole
from iceberg_core.models import User
from oidc_provider import BOOTSTRAP_SUBJECT, FakeProvider
from sqlmodel import Session, select

LOGIN = "/api/v1/auth/login"
CALLBACK = "/api/v1/auth/callback"
LOGOUT = "/api/v1/auth/logout"
ME = "/api/v1/auth/me"


def _start_login(client: TestClient, *, next_path: str | None = None) -> tuple[str, str]:
    """Drive ``/auth/login`` and return the (state, nonce) the server chose."""
    params = {"next": next_path} if next_path else None
    response = client.get(LOGIN, params=params, follow_redirects=False)

    assert response.status_code == 307
    return (
        parse_qs(urlparse(response.headers["location"]).query)["state"][0],
        parse_qs(urlparse(response.headers["location"]).query)["nonce"][0],
    )


def _complete_login(
    client: TestClient,
    provider: FakeProvider,
    *,
    subject: str,
    email: str = "alice@example.test",
    email_verified: bool | None = True,
    next_path: str | None = None,
) -> httpx2.Response:
    state, nonce = _start_login(client, next_path=next_path)
    provider.id_token = provider.mint_id_token(
        subject=subject, nonce=nonce, email=email, email_verified=email_verified
    )
    return client.get(
        CALLBACK, params={"code": "auth-code", "state": state}, follow_redirects=False
    )


def test_login_redirects_to_the_provider_and_remembers_the_attempt(
    client: TestClient, api_settings: ApiSettings
) -> None:
    response = client.get(LOGIN, follow_redirects=False)

    location = urlparse(response.headers["location"])
    assert response.status_code == 307
    assert location.netloc == "idp.example.test"
    assert location.path == "/authorize"

    cookie = client.cookies.get(LOGIN_COOKIE)
    assert cookie is not None
    # The state and nonce in the URL must be the ones we can prove later.
    state = read_login_state(cookie, api_settings)
    query = parse_qs(location.query)
    assert query["state"] == [state.state]
    assert query["nonce"] == [state.nonce]
    assert query["code_challenge_method"] == ["S256"]


def test_first_login_provisions_a_user_and_starts_a_session(
    client: TestClient, provider: FakeProvider, session: Session
) -> None:
    response = _complete_login(client, provider, subject="oidc|alice")

    assert response.status_code == 303
    assert response.headers["location"] == "/"
    assert client.cookies.get(SESSION_COOKIE) is not None

    user = session.exec(select(User).where(User.oidc_subject == "oidc|alice")).one()
    assert user.email == "alice@example.test"
    assert user.display_name == "Alice Analyst"
    # Least privilege: an account exists because the IdP knows them, not because
    # anyone decided what they may do.
    assert user.role is UserRole.VIEWER
    assert user.last_login_at is not None


def test_the_bootstrap_subject_becomes_admin_on_first_login(
    client: TestClient, provider: FakeProvider, session: Session
) -> None:
    """OIDC-only auth needs a seed admin (docs/security.md § Bootstrap)."""
    _complete_login(client, provider, subject=BOOTSTRAP_SUBJECT)

    user = session.exec(select(User).where(User.oidc_subject == BOOTSTRAP_SUBJECT)).one()
    assert user.role is UserRole.ADMIN


def test_the_bootstrap_email_grants_admin_only_when_the_provider_vouches_for_it(
    app: FastAPI,
    client: TestClient,
    provider: FakeProvider,
    session: Session,
    api_settings: ApiSettings,
) -> None:
    """OIDC's `email` claim is untrustworthy without `email_verified`: at an IdP
    with self-service emails, anyone could claim the bootstrap address."""
    by_email = api_settings.model_copy(
        update={"bootstrap_admin_subject": None, "bootstrap_admin_email": "root@example.test"}
    )
    app.dependency_overrides[get_settings] = lambda: by_email

    _complete_login(
        client, provider, subject="oidc|imposter", email="root@example.test", email_verified=False
    )
    imposter = session.exec(select(User).where(User.oidc_subject == "oidc|imposter")).one()
    assert imposter.role is UserRole.VIEWER

    client.cookies.clear()
    _complete_login(
        client, provider, subject="oidc|root", email="Root@example.test", email_verified=True
    )
    admin = session.exec(select(User).where(User.oidc_subject == "oidc|root")).one()
    assert admin.role is UserRole.ADMIN


def test_an_unverified_email_is_not_stored_as_the_users_identity(
    client: TestClient, provider: FakeProvider, session: Session
) -> None:
    """An unverified address is user-settable at many IdPs; storing it and showing
    it in the admin list primes a social-engineered promotion. Only a verified email
    is trusted onto the profile."""
    _complete_login(
        client, provider, subject="oidc|mallory", email="ciso@company.test", email_verified=False
    )
    user = session.exec(select(User).where(User.oidc_subject == "oidc|mallory")).one()
    assert user.email == ""  # the unverified claim was not trusted

    client.cookies.clear()
    _complete_login(
        client, provider, subject="oidc|mallory", email="mallory@company.test", email_verified=True
    )
    session.refresh(user)
    assert user.email == "mallory@company.test"  # a verified claim does refresh it


def test_a_demoted_bootstrap_admin_is_not_re_promoted_by_logging_in_again(
    client: TestClient, provider: FakeProvider, session: Session
) -> None:
    _complete_login(client, provider, subject=BOOTSTRAP_SUBJECT)
    user = session.exec(select(User).where(User.oidc_subject == BOOTSTRAP_SUBJECT)).one()
    user.role = UserRole.VIEWER
    session.commit()

    _complete_login(client, provider, subject=BOOTSTRAP_SUBJECT)

    session.refresh(user)
    assert user.role is UserRole.VIEWER


def test_a_second_login_refreshes_the_profile_without_duplicating_the_user(
    client: TestClient, provider: FakeProvider, session: Session
) -> None:
    _complete_login(client, provider, subject="oidc|alice", email="alice@example.test")
    _complete_login(client, provider, subject="oidc|alice", email="alice.new@example.test")

    users = session.exec(select(User).where(User.oidc_subject == "oidc|alice")).all()
    assert len(users) == 1
    assert users[0].email == "alice.new@example.test"


def test_a_returning_users_role_is_never_taken_from_the_token(
    client: TestClient, provider: FakeProvider, session: Session
) -> None:
    """Roles are assigned in IcebergSST, not asserted by the IdP (ADR 0005)."""
    _complete_login(client, provider, subject="oidc|alice")
    user = session.exec(select(User).where(User.oidc_subject == "oidc|alice")).one()
    user.role = UserRole.ADMIN
    session.commit()

    _complete_login(client, provider, subject="oidc|alice")

    session.refresh(user)
    assert user.role is UserRole.ADMIN


def test_a_callback_with_a_mismatched_state_is_refused(
    client: TestClient, provider: FakeProvider, session: Session
) -> None:
    """This is the check that makes a forced login fail."""
    _, nonce = _start_login(client)
    provider.id_token = provider.mint_id_token(nonce=nonce)

    response = client.get(
        CALLBACK, params={"code": "auth-code", "state": "not-the-state"}, follow_redirects=False
    )

    assert response.status_code == 400
    assert client.cookies.get(SESSION_COOKIE) is None
    assert session.exec(select(User)).all() == []


def test_a_callback_without_the_login_cookie_is_refused(client: TestClient) -> None:
    response = client.get(
        CALLBACK, params={"code": "auth-code", "state": "whatever"}, follow_redirects=False
    )

    assert response.status_code == 400
    assert client.cookies.get(SESSION_COOKIE) is None


def test_a_token_minted_for_another_login_attempt_is_refused(
    client: TestClient, provider: FakeProvider
) -> None:
    state, _ = _start_login(client)
    provider.id_token = provider.mint_id_token(nonce="some-other-login")

    response = client.get(
        CALLBACK, params={"code": "auth-code", "state": state}, follow_redirects=False
    )

    assert response.status_code == 400
    assert client.cookies.get(SESSION_COOKIE) is None


def test_a_provider_error_does_not_start_a_session(client: TestClient) -> None:
    _start_login(client)

    response = client.get(
        CALLBACK, params={"error": "access_denied", "state": "x"}, follow_redirects=False
    )

    assert response.status_code == 400
    assert client.cookies.get(SESSION_COOKIE) is None


def test_a_disabled_user_cannot_log_in(
    client: TestClient, provider: FakeProvider, session: Session
) -> None:
    """Authentication succeeded at the provider; authorization stops here."""
    _complete_login(client, provider, subject="oidc|alice")
    user = session.exec(select(User).where(User.oidc_subject == "oidc|alice")).one()
    user.disabled = True
    session.commit()
    client.cookies.clear()

    response = _complete_login(client, provider, subject="oidc|alice")

    assert response.status_code == 403
    assert client.cookies.get(SESSION_COOKIE) is None


def test_the_return_path_is_honoured_but_only_within_this_origin(
    client: TestClient, provider: FakeProvider
) -> None:
    local = _complete_login(client, provider, subject="oidc|alice", next_path="/findings")
    assert local.headers["location"] == "/findings"

    client.cookies.clear()
    remote = _complete_login(
        client, provider, subject="oidc|alice", next_path="https://evil.example"
    )
    assert remote.headers["location"] == "/"


def test_me_returns_the_identity_and_a_csrf_token(
    client: TestClient, provider: FakeProvider
) -> None:
    _complete_login(client, provider, subject="oidc|alice")

    body = client.get(ME).json()

    assert body["user"]["oidc_subject"] == "oidc|alice"
    assert body["user"]["role"] == "viewer"
    assert body["csrf_token"]


def test_me_never_exposes_another_users_session(client: TestClient) -> None:
    assert client.get(ME).status_code == 401


def test_logout_clears_the_session_and_requires_a_csrf_token(
    client: TestClient, provider: FakeProvider
) -> None:
    _complete_login(client, provider, subject="oidc|alice")
    csrf_token = client.get(ME).json()["csrf_token"]

    unprotected = client.post(LOGOUT)
    assert unprotected.status_code == 403
    assert client.get(ME).status_code == 200  # still logged in

    protected = client.post(LOGOUT, headers={"X-CSRF-Token": csrf_token})
    assert protected.status_code == 204
    assert client.get(ME).status_code == 401


def test_a_forged_csrf_token_does_not_pass(client: TestClient, provider: FakeProvider) -> None:
    _complete_login(client, provider, subject="oidc|alice")

    response = client.post(LOGOUT, headers={"X-CSRF-Token": "not-the-token"})

    assert response.status_code == 403


def test_a_non_ascii_csrf_token_fails_closed_rather_than_raising() -> None:
    """Starlette decodes a header's raw bytes as latin-1, so a hostile client can
    present a non-ASCII token. compare_digest raises TypeError on a non-ASCII str;
    verify must fail the check closed (a CsrfError → 403), not let a 500 escape."""
    from iceberg_api.auth.csrf import CsrfError, verify

    with pytest.raises(CsrfError):
        verify("the-real-token", "café-ÿ-tokén")


def test_a_csrf_token_from_a_form_post_is_accepted(
    client: TestClient, provider: FakeProvider
) -> None:
    """HTMX posts forms, so the token has to be readable from the body too."""
    _complete_login(client, provider, subject="oidc|alice")
    csrf_token = client.get(ME).json()["csrf_token"]

    response = client.post(LOGOUT, data={"csrf_token": csrf_token})

    assert response.status_code == 204


@pytest.mark.parametrize("route", [ME, LOGOUT])
def test_a_session_signed_with_another_secret_is_not_a_session(
    client: TestClient, route: str
) -> None:
    client.cookies.set(SESSION_COOKIE, "not.a.token")

    response = client.get(route) if route == ME else client.post(route)

    assert response.status_code in {401, 403}


def test_login_without_oidc_configured_reports_a_service_error(
    client: TestClient, app: FastAPI, api_settings: ApiSettings
) -> None:
    """A misconfigured deployment should say so, not 500."""
    unconfigured = api_settings.model_copy(update={"oidc_issuer": None})
    app.dependency_overrides.pop(get_oidc_client)
    app.dependency_overrides[get_settings] = lambda: unconfigured

    response = client.get(LOGIN, follow_redirects=False)

    assert response.status_code == 503
    assert "ICEBERG_OIDC_ISSUER" in response.json()["detail"]
