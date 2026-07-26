"""Shared test fixtures (issue #23).

The first conftest in the repo. It lives at the workspace root because the
Postgres container is expensive and must be shared across every member's tests —
a per-member conftest would start one container per package.

Container discipline: the Postgres fixture is **session-scoped and started
lazily**, so suites that touch no database (the majority) never pay for Docker at
all, and those that do share a single instance. Interrupting a run mid-container
orphans both a Postgres and a testcontainers ryuk reaper, so let runs finish.
"""

import base64
from collections.abc import AsyncIterator, Iterator
from typing import TYPE_CHECKING

import pytest
from iceberg_core.config import ApiSettings
from iceberg_core.secrets.store import KEY_BYTES, EnvKeyBackend

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncEngine
    from sqlmodel.ext.asyncio.session import AsyncSession

# Deterministic, obviously-fake key material. Low-entropy and clearly labelled so
# the repo's own gitleaks scan (issue #19) does not flag it as a real credential.
TEST_MASTER_KEY_B64 = base64.b64encode(b"iceberg-test-key" * 2).decode()
TEST_PEPPER_B64 = base64.b64encode(b"iceberg-test-pepper").decode()


@pytest.fixture(scope="session")
def postgres_dsn() -> Iterator[str]:
    """Async DSN for a session-scoped Postgres container.

    Skips rather than fails when Docker is unavailable: contributors without a
    working Docker socket can still run the pure-Python suite.
    """
    docker = pytest.importorskip("docker", reason="testcontainers needs the docker SDK")
    from testcontainers.community.postgres import PostgresContainer

    try:
        docker.from_env().ping()
    except Exception as exc:  # pragma: no cover - environment dependent
        pytest.skip(f"Docker unavailable, skipping Postgres-backed tests: {exc}")

    with PostgresContainer("postgres:17-alpine", driver="asyncpg") as container:
        yield container.get_connection_url()


@pytest.fixture(scope="session")
def api_settings(postgres_dsn: str) -> ApiSettings:
    """API settings pointed at the throwaway container."""
    return ApiSettings(
        database_url=postgres_dsn,
        secret_key=TEST_MASTER_KEY_B64,
        fingerprint_pepper=TEST_PEPPER_B64,
    )


@pytest.fixture(scope="session")
async def db_engine(api_settings: ApiSettings) -> AsyncIterator["AsyncEngine"]:
    """One engine for the whole session, disposed once at the end.

    Session-scoped on purpose: an engine per test leaves asyncpg connections
    bound to a closed event loop, and the ResourceWarning that follows is fatal
    under ``filterwarnings = ["error"]``.

    Imported lazily so that collecting this module never pulls a database driver
    into a test process that does not need one.
    """
    from iceberg_core.db.session import create_engine

    engine = create_engine(api_settings)
    yield engine
    await engine.dispose()


@pytest.fixture
async def db_session(db_engine: "AsyncEngine") -> AsyncIterator["AsyncSession"]:
    """A live :class:`AsyncSession` against the container, rolled back afterwards."""
    from iceberg_core.db.session import create_session_factory

    async with create_session_factory(db_engine)() as session:
        yield session
        await session.rollback()


@pytest.fixture
def secret_store() -> EnvKeyBackend:
    """EnvKeyBackend wired with the fake test key material."""
    assert len(base64.b64decode(TEST_MASTER_KEY_B64)) == KEY_BYTES
    return EnvKeyBackend.from_values(
        master_key_b64=TEST_MASTER_KEY_B64,
        pepper_b64=TEST_PEPPER_B64,
    )
