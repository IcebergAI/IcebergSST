"""The launcher the scheduler was written to expect (#33 → #34).

#33 landed the tick with an injected launcher because scans did not exist yet. This
is the real one, kept in its own module so neither the scheduler nor the scan service
has to import the other.

A source that already has an active scan is skipped rather than retried: the cadence
said "scan now" and a scan is already running, so the honest outcome is to note it
and let the next beat find the source idle.
"""

import uuid

import structlog
from iceberg_core.enums import ScanTrigger
from iceberg_core.models import Source
from sqlmodel import Session

from iceberg_api.dispatch import Dispatcher
from iceberg_api.scans import service
from iceberg_api.scheduler import ScanLauncher

logger = structlog.get_logger()


def build_launcher(dispatcher: Dispatcher) -> ScanLauncher:
    """A launcher that starts a scheduled scan for one source."""

    def launch(db: Session, source_id: uuid.UUID) -> uuid.UUID | None:
        source = db.get(Source, source_id)
        if source is None:
            logger.warning("scheduled_source_missing", source_id=str(source_id))
            return None
        if not source.enabled:
            logger.info("scheduled_source_disabled", source_id=str(source_id))
            return None

        try:
            scan = service.launch_scan(
                db, source, trigger=ScanTrigger.SCHEDULED, dispatcher=dispatcher
            )
        except service.ScanConflict:
            logger.info("scheduled_scan_skipped_active", source_id=str(source_id))
            return None
        return scan.id

    return launch
