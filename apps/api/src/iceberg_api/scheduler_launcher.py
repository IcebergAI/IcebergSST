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
from iceberg_core.enums import ScanMode, ScanTrigger
from iceberg_core.models import Source
from iceberg_core.secrets import SecretStore, SecretStoreError
from sqlmodel import Session

from iceberg_api.dispatch import Dispatcher
from iceberg_api.scans import cursors, service
from iceberg_api.scheduler import ScanLauncher

logger = structlog.get_logger()


def build_launcher(dispatcher: Dispatcher, store: SecretStore | None = None) -> ScanLauncher:
    """A launcher that starts a scheduled scan for one source.

    ``store`` is only consulted to notice a pepper rotation, which invalidates
    every watermark: fingerprints move, so nothing an incremental scan reported
    would match what is stored (#143). Without one the launcher assumes a rotation
    may be in flight and asks for a full scan, which is the safe direction.
    """

    def launch(
        db: Session, source_id: uuid.UUID, mode: ScanMode = ScanMode.FULL
    ) -> uuid.UUID | None:
        source = db.get(Source, source_id)
        if source is None:
            logger.warning("scheduled_source_missing", source_id=str(source_id))
            return None
        if not source.enabled:
            logger.info("scheduled_source_disabled", source_id=str(source_id))
            return None

        try:
            scan = service.launch_scan(
                db,
                source,
                trigger=ScanTrigger.SCHEDULED,
                dispatcher=dispatcher,
                mode=mode,
                # Both feed cursor validation: new rules must see content the old
                # ones passed over, and every fingerprint moves during a rotation.
                # Unknown counts as changed, so an unreadable fleet or store
                # promotes to a full scan rather than trusting a watermark (#143).
                rulepack_version=cursors.fleet_rulepack_version(db),
                pepper_rotating=_rotating(store),
            )
        except service.ScanConflict:
            logger.info("scheduled_scan_skipped_active", source_id=str(source_id))
            return None
        return scan.id

    return launch


def _rotating(store: SecretStore | None) -> bool:
    """Whether a fingerprint pepper rotation is in flight.

    Fails towards *rotating*: an unreadable store is not evidence that it is not,
    and the cost of being wrong that way is one full scan rather than an
    incremental scan whose fingerprints match nothing (ADR 0006/0007).
    """
    if store is None:
        return True
    try:
        return store.get_previous_pepper() is not None
    except SecretStoreError:
        return True
