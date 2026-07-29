"""Fixtures for the API tests: a wired app, a scripted identity provider, sessions.

The provider is a real one as far as the code under test is concerned: discovery
and the token endpoint are answered by an in-process transport, and ID tokens are
RSA-signed with a key whose public half is served as a JWKS. So every login test
exercises the actual signature, issuer, audience, and nonce checks rather than a
stub that returns claims.
"""

import uuid
from collections.abc import Callable, Iterator

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI
from fastapi.testclient import TestClient
from iceberg_api.app import API_PREFIX, create_app
from iceberg_api.auth.dependencies import get_db_session, get_secret_store, get_settings
from iceberg_api.auth.oidc import OidcClient, OidcConfig
from iceberg_api.auth.routes import get_oidc_client
from iceberg_api.auth.session import SESSION_COOKIE, issue_session
from iceberg_api.dispatch import get_dispatcher
from iceberg_api.engines.auth import mint_token
from iceberg_core.config import ApiSettings
from iceberg_core.enums import UserRole
from iceberg_core.models import Engine as CoreEngine
from iceberg_core.models import User
from iceberg_core.secrets import EnvKeyBackend
from oidc_provider import BOOTSTRAP_SUBJECT, CLIENT_ID, ISSUER, FakeProvider
from pydantic import SecretStr
from sqlalchemy import Engine
from sqlmodel import Session


@pytest.fixture(name="anyio_backend", scope="session")
def anyio_backend_fixture() -> str:
    """anyio's pytest plugin needs a backend; asyncio is what uvicorn runs."""
    return "asyncio"


@pytest.fixture(name="signing_key", scope="session")
def signing_key_fixture() -> rsa.RSAPrivateKey:
    # Generated once per session: 2048-bit keygen is the slowest thing in these tests.
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(name="provider")
def provider_fixture(signing_key: rsa.RSAPrivateKey) -> FakeProvider:
    return FakeProvider(private_key=signing_key)


@pytest.fixture(name="api_settings")
def api_settings_fixture() -> ApiSettings:
    return ApiSettings(
        database_url="sqlite://",
        environment="test",
        oidc_issuer=ISSUER,
        oidc_client_id=CLIENT_ID,
        oidc_client_secret=SecretStr("client-secret"),
        oidc_redirect_url="http://testserver/api/v1/auth/callback",
        session_secret=SecretStr("session-signing-secret-for-tests-0123456789"),
        # The test client speaks plain HTTP; Secure cookies would never come back.
        cookie_secure=False,
        bootstrap_admin_subject=BOOTSTRAP_SUBJECT,
    )


@pytest.fixture(name="app")
def app_fixture(
    api_settings: ApiSettings,
    provider: FakeProvider,
    db_engine: Engine,
    session: Session,
    secret_store: EnvKeyBackend,
    dispatcher: "RecordingDispatcher",
) -> FastAPI:
    """The real app, with settings, the database, and the provider overridden."""
    # background=False: the tests drive the scheduler and reclaim directly.
    app = create_app(api_settings, background=False)

    def _settings() -> ApiSettings:
        return api_settings

    def _db() -> Iterator[Session]:
        # One session for the whole test, so a route's writes are visible to
        # assertions made through the fixture afterwards.
        yield session

    def _oidc() -> OidcClient:
        return OidcClient(
            OidcConfig(
                issuer=ISSUER,
                client_id=CLIENT_ID,
                client_secret="client-secret",  # scripted provider
                redirect_url=api_settings.oidc_redirect_url,
            ),
            transport=provider.transport(),
        )

    app.dependency_overrides[get_settings] = _settings
    # The real env-key backend with an ephemeral master key: credential sealing in
    # a route runs the same code path production does.
    app.dependency_overrides[get_secret_store] = lambda: secret_store
    app.dependency_overrides[get_db_session] = _db
    app.dependency_overrides[get_oidc_client] = _oidc
    app.dependency_overrides[get_dispatcher] = lambda: dispatcher
    return app


class RecordingDispatcher:
    """Records dispatched task ids instead of talking to Redis.

    Tests assert on *what was enqueued* — that a launch dispatches its discovery
    task, that reclaim re-dispatches — which is the API's whole side of the broker
    contract (ADR 0009).
    """

    def __init__(self) -> None:
        self.enqueued: list[uuid.UUID] = []

    def enqueue(self, task_id: uuid.UUID) -> None:
        self.enqueued.append(task_id)


@pytest.fixture(name="dispatcher")
def dispatcher_fixture() -> RecordingDispatcher:
    return RecordingDispatcher()


@pytest.fixture(name="client")
def client_fixture(app: FastAPI) -> Iterator[TestClient]:
    with TestClient(app, base_url="http://testserver") as test_client:
        yield test_client


@pytest.fixture(name="make_user")
def make_user_fixture(session: Session) -> Callable[..., User]:
    """Create a persisted user with a given role."""

    def factory(
        role: UserRole = UserRole.VIEWER,
        *,
        subject: str | None = None,
        disabled: bool = False,
    ) -> User:
        suffix = uuid.uuid4().hex[:8]
        user = User(
            oidc_subject=subject or f"oidc|{role.value}-{suffix}",
            email=f"{role.value}-{suffix}@example.test",
            display_name=f"{role.value.title()} {suffix}",
            role=role,
            disabled=disabled,
        )
        session.add(user)
        session.commit()
        return user

    return factory


@pytest.fixture(name="login_as")
def login_as_fixture(
    client: TestClient, api_settings: ApiSettings
) -> Callable[[User], dict[str, str]]:
    """Attach a session cookie for ``user`` and return its CSRF header.

    Mints the session directly rather than driving the OIDC flow: tests about
    authorization should not re-test authentication.
    """

    def login(user: User) -> dict[str, str]:
        csrf_token = f"csrf-{uuid.uuid4().hex}"
        token = issue_session(user.id, api_settings, csrf_token=csrf_token)
        client.cookies.set(SESSION_COOKIE, token)
        return {"X-CSRF-Token": csrf_token}

    return login


@pytest.fixture(name="api")
def api_prefix_fixture() -> str:
    return API_PREFIX


@pytest.fixture(name="engine_credential")
def engine_credential_fixture(session: Session) -> tuple[CoreEngine, dict[str, str]]:
    """A registered engine and the Authorization header that authenticates it."""
    engine = CoreEngine(name=f"engine-{uuid.uuid4().hex[:6]}", token_hash="", version="0.1.0")
    minted = mint_token(engine)
    session.add(minted.engine)
    session.commit()
    return minted.engine, {"Authorization": f"Bearer {minted.token}"}
