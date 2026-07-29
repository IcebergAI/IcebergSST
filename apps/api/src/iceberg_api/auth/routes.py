"""Login, callback, logout, and `/auth/me` (#28, #30)."""

import secrets

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import RedirectResponse
from iceberg_core.config import ApiSettings

from iceberg_api.auth.dependencies import (
    CsrfProtected,
    CurrentUser,
    SessionDataDep,
    SessionDep,
    SettingsDep,
)
from iceberg_api.auth.oidc import (
    OidcClient,
    OidcConfig,
    OidcError,
    new_pkce_verifier,
    pkce_challenge,
)
from iceberg_api.auth.provisioning import AccountDisabled, provision_user
from iceberg_api.auth.session import (
    LOGIN_COOKIE,
    AuthConfigError,
    LoginState,
    SessionError,
    clear_login_cookie,
    clear_session_cookie,
    issue_login_state,
    issue_session,
    new_csrf_token,
    read_login_state,
    safe_return_path,
    set_login_cookie,
    set_session_cookie,
)
from iceberg_api.schemas import MeRead, UserRead

router = APIRouter(prefix="/auth", tags=["auth"])
logger = structlog.get_logger()


def oidc_config(settings: ApiSettings) -> OidcConfig:
    """Assemble the provider configuration, or say exactly what is missing."""
    issuer, client_id = settings.oidc_issuer, settings.oidc_client_id
    client_secret = settings.oidc_client_secret
    missing = [
        name
        for name, value in (
            ("ICEBERG_OIDC_ISSUER", issuer),
            ("ICEBERG_OIDC_CLIENT_ID", client_id),
            ("ICEBERG_OIDC_CLIENT_SECRET", client_secret),
        )
        if not value
    ]
    if missing or issuer is None or client_id is None or client_secret is None:
        raise AuthConfigError(f"OIDC is not configured; set {', '.join(missing)}")

    return OidcConfig(
        issuer=issuer,
        client_id=client_id,
        client_secret=client_secret.get_secret_value(),
        redirect_url=settings.oidc_redirect_url,
        scopes=settings.oidc_scopes,
    )


def get_oidc_client(settings: SettingsDep) -> OidcClient:
    """The provider client as a dependency, so tests can inject a fake provider."""
    try:
        return OidcClient(oidc_config(settings))
    except AuthConfigError as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc)) from exc


OidcClientDep = Depends(get_oidc_client)


@router.get("/login", status_code=status.HTTP_307_TEMPORARY_REDIRECT)
async def login(
    settings: SettingsDep,
    client: OidcClient = OidcClientDep,
    next_path: str | None = Query(default=None, alias="next"),
) -> RedirectResponse:
    """Start the authorization-code flow.

    The state, nonce, and PKCE verifier go into a short-lived signed cookie: the
    callback needs all three, and holding them client-side keeps the flow working
    across API replicas without shared server state.
    """
    login_state = LoginState(
        state=secrets.token_urlsafe(32),
        nonce=secrets.token_urlsafe(32),
        code_verifier=new_pkce_verifier(),
        return_path=safe_return_path(next_path),
    )
    try:
        target = await client.authorization_url(
            state=login_state.state,
            nonce=login_state.nonce,
            code_challenge=pkce_challenge(login_state.code_verifier),
        )
    except OidcError as exc:
        logger.warning("oidc_discovery_failed", error=str(exc))
        raise HTTPException(
            status.HTTP_502_BAD_GATEWAY, "identity provider is unavailable"
        ) from exc

    response = RedirectResponse(target, status_code=status.HTTP_307_TEMPORARY_REDIRECT)
    set_login_cookie(response, issue_login_state(login_state, settings), settings)
    return response


@router.get("/callback")
async def callback(
    request: Request,
    settings: SettingsDep,
    db: SessionDep,
    client: OidcClient = OidcClientDep,
    code: str | None = Query(default=None),
    state: str | None = Query(default=None),
    error: str | None = Query(default=None),
) -> RedirectResponse:
    """Finish the flow: verify, provision, and start a session."""
    if error:
        # The provider declined (consent refused, account locked). Its error code
        # is caller-influenced, so it is logged, not reflected.
        logger.info("oidc_provider_returned_error", error=error)
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "login failed")
    if not code or not state:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "login failed")

    cookie = request.cookies.get(LOGIN_COOKIE)
    if not cookie:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "login session expired; start again")

    try:
        login_state = read_login_state(cookie, settings)
    except (SessionError, AuthConfigError) as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "login failed") from exc

    # Constant-time compare: this is the check that makes a forced login fail.
    if not secrets.compare_digest(login_state.state, state):
        logger.warning("oidc_state_mismatch")
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "login failed")

    try:
        id_token = await client.exchange_code(code, login_state.code_verifier)
        claims = await client.verify_id_token(id_token, nonce=login_state.nonce)
    except OidcError as exc:
        logger.warning("oidc_exchange_failed", error=str(exc))
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "login failed") from exc

    try:
        user = provision_user(db, claims, settings)
    except AccountDisabled as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "account is disabled") from exc
    db.commit()

    logger.info("login_succeeded", user_id=str(user.id), role=user.role.value)
    response = RedirectResponse(login_state.return_path, status_code=status.HTTP_303_SEE_OTHER)
    session_token = issue_session(user.id, settings, csrf_token=new_csrf_token())
    set_session_cookie(response, session_token, settings)
    clear_login_cookie(response, settings)
    return response


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT, dependencies=[CsrfProtected])
async def logout(settings: SettingsDep, user: CurrentUser) -> Response:
    """End the session.

    A POST, and CSRF-protected: a GET logout can be triggered by any page that
    embeds a link to it, which is a nuisance attack that costs nothing to prevent.
    """
    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    clear_session_cookie(response, settings)
    logger.info("logout", user_id=str(user.id))
    return response


@router.get("/me")
async def me(user: CurrentUser, session_data: SessionDataDep) -> MeRead:
    """Current identity, role, and this session's CSRF token."""
    return MeRead(user=UserRead.model_validate(user), csrf_token=session_data.csrf_token)
