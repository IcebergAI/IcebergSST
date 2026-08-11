"""Development fixtures: ``make seed``.

Enough data to click around a fresh stack — one disabled Confluence source with a
sealed placeholder credential, and a nightly schedule for it. The source is
**disabled** on purpose: seeding must never point a scanner at a real system with
a fake credential.

Two guards make this safe to leave in the image:

* it refuses to run when ``ICEBERG_ENVIRONMENT=prod``;
* it is idempotent, keyed on the source name, so running it twice is a no-op
  rather than a pile of duplicate fixtures.
"""

import structlog
from iceberg_core.config import ApiSettings, get_api_settings
from iceberg_core.db import session_scope
from iceberg_core.enums import SourceType
from iceberg_core.models import Schedule, Source
from iceberg_core.secrets import SecretStore, build_secret_store
from sqlmodel import Session, select

DEMO_SOURCE_NAME = "demo-confluence"
DEMO_CRON = "0 3 * * *"

logger = structlog.get_logger()


class SeedRefused(RuntimeError):
    """Raised when seeding is attempted somewhere it should not be."""


def seed(session: Session, store: SecretStore) -> Source:
    """Create (or return) the demo source and its schedule."""
    existing = session.exec(select(Source).where(Source.name == DEMO_SOURCE_NAME)).first()
    if existing is not None:
        logger.info("seed_already_present", source=DEMO_SOURCE_NAME)
        return existing

    source = Source(
        name=DEMO_SOURCE_NAME,
        type=SourceType.CONFLUENCE,
        connection={"base_url": "https://example.atlassian.net", "spaces": ["DEMO"]},
        # Sealed through the same interface the API uses, so the fixture exercises
        # the real path rather than writing a plaintext placeholder.
        credential_ref=store.seal("replace-with-a-real-api-token"),
        enabled=False,
    )
    session.add(source)
    session.flush()
    session.add(Schedule(source_id=source.id, cron=DEMO_CRON, enabled=False))
    logger.info("seed_created_source", source=DEMO_SOURCE_NAME, cron=DEMO_CRON)
    return source


def main(settings: ApiSettings | None = None) -> int:
    """Entrypoint: refuse in production, otherwise seed in one transaction."""
    resolved = settings or get_api_settings()
    if resolved.environment == "prod":
        raise SeedRefused("refusing to seed development fixtures in a prod environment")

    store = build_secret_store(resolved)
    with session_scope() as session:
        seed(session, store)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
