"""The engine-facing API (#35, #36 — ADR 0002, 0009).

Four routes, one caller type. Engine tokens work here and nowhere else; session
cookies work everywhere else and not here. That is the boundary ADR 0002 describes,
and it is enforced by which dependency each route declares rather than by
convention.

Registration is the exception: it is admin-authenticated, because minting an engine
credential is an operator action. An engine cannot enrol itself — otherwise anyone
who could reach the API could join the fleet and start leasing tasks, credentials
included.
"""

import base64
import uuid
from datetime import UTC, datetime

import structlog
from fastapi import APIRouter, HTTPException, status
from iceberg_core.enums import ScanStatus, ScanTaskKind, ScanTaskStatus
from iceberg_core.models import Engine, Scan, ScanTask, Source
from iceberg_core.secrets import SecretStoreError
from sqlmodel import col, select

from iceberg_api import suppressions
from iceberg_api.auth.dependencies import CsrfProtected, SecretStoreDep, SessionDep
from iceberg_api.auth.rbac import AdminUser
from iceberg_api.dispatch import DispatcherDep
from iceberg_api.engines import ingest
from iceberg_api.engines.auth import CurrentEngine, mint_token, record_heartbeat
from iceberg_api.engines.schemas import (
    EngineCredential,
    EngineRead,
    EngineRegister,
    HeartbeatRequest,
    HeartbeatResponse,
    LeaseResponse,
    ResultsAccepted,
    ResultsSubmission,
)
from iceberg_api.scans import service
from iceberg_api.scans.reconcile import reconcile_scan

router = APIRouter(tags=["engines"])
logger = structlog.get_logger()

#: The only outcomes an engine may report. Cancellation is the API's decision, and
#: queued/leased are not outcomes.
REPORTABLE_STATUSES = (ScanTaskStatus.COMPLETED, ScanTaskStatus.FAILED)


@router.post(
    "/engines/register",
    status_code=status.HTTP_201_CREATED,
    dependencies=[CsrfProtected],
)
async def register_engine(
    body: EngineRegister,
    admin: AdminUser,
    db: SessionDep,
) -> EngineCredential:
    """Enrol an engine and mint its token. Admin-only; the token is shown once.

    Re-registering an existing name **rotates** its token rather than failing: that
    is how an operator replaces a credential they think has leaked, and the old
    token stops working the moment this returns.
    """
    engine = db.exec(select(Engine).where(col(Engine.name) == body.name)).first()
    rotating = engine is not None
    if engine is None:
        engine = Engine(name=body.name, token_hash="", version=body.version)
    elif body.version:
        engine.version = body.version

    minted = mint_token(engine)
    db.add(minted.engine)
    db.commit()
    db.refresh(minted.engine)

    logger.info(
        "engine_registered",
        engine_id=str(minted.engine.id),
        name=minted.engine.name,
        rotated=rotating,
        actor_id=str(admin.id),
    )
    return EngineCredential(engine_id=minted.engine.id, name=minted.engine.name, token=minted.token)


@router.get("/engines")
async def list_engines(admin: AdminUser, db: SessionDep) -> list[EngineRead]:
    """The fleet, for the engine-health view (#58). Never any token material."""
    engines = db.exec(select(Engine).order_by(col(Engine.name)))
    return [EngineRead.model_validate(engine) for engine in engines]


@router.post("/engines/{engine_id}/heartbeat")
async def heartbeat(
    engine_id: uuid.UUID,
    body: HeartbeatRequest,
    engine: CurrentEngine,
    db: SessionDep,
) -> HeartbeatResponse:
    """Extend the leases this engine holds, and report any cancellations.

    An engine may only heartbeat as itself: the path id has to match the token, or a
    compromised engine could keep another engine's leases alive.
    """
    if engine_id != engine.id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "token does not match this engine")

    now = datetime.now(UTC)
    record_heartbeat(db, engine, version=body.version, now=now)

    cancelled: list[uuid.UUID] = []
    for task_id in body.task_ids:
        task = db.get(ScanTask, task_id)
        if task is None or task.engine_id != engine.id:
            continue
        if task.status is ScanTaskStatus.CANCELLED:
            # The only way to tell a worker to stop (ADR 0009).
            cancelled.append(task.id)
            continue
        if task.status in service.LEASED_STATUSES:
            service.renew_lease(db, task, now=now)

    return HeartbeatResponse(engine_id=engine.id, acknowledged_at=now, cancelled_task_ids=cancelled)


@router.post("/scan-tasks/{task_id}/lease")
async def lease_task(
    task_id: uuid.UUID,
    engine: CurrentEngine,
    db: SessionDep,
    store: SecretStoreDep,
) -> LeaseResponse:
    """Claim a task and receive everything needed to run it.

    A 409 means the lease was refused — already claimed, already finished, or
    cancelled — and the engine's correct response to all of those is to drop the
    broker message and move on (ADR 0009 §2).
    """
    grant = service.claim_task(db, task_id, engine.id)
    if grant is None:
        raise HTTPException(status.HTTP_409_CONFLICT, "task is not available to lease")

    task = grant.task
    scan = db.get(Scan, task.scan_id)
    source = db.get(Source, scan.source_id) if scan else None
    if scan is None or source is None:  # pragma: no cover — FKs make this unreachable
        raise HTTPException(status.HTTP_409_CONFLICT, "task is not available to lease")

    credential: str | None = None
    if source.credential_ref is not None:
        try:
            credential = store.open(source.credential_ref).get_secret_value()
        except SecretStoreError as exc:
            # Fail the task rather than send an engine off without a credential: a
            # scan that cannot authenticate should say so, not report zero findings.
            service.complete_task(
                db, task, status=ScanTaskStatus.FAILED, error="source credential unreadable"
            )
            db.commit()
            logger.warning("lease_credential_unreadable", source_id=str(source.id))
            raise HTTPException(
                status.HTTP_500_INTERNAL_SERVER_ERROR,
                "source credential could not be decrypted",
            ) from exc

    return LeaseResponse(
        task_id=task.id,
        scan_id=scan.id,
        source_id=source.id,
        source_type=source.type.value,
        kind=task.kind,
        attempt=task.attempts,
        lease_expires_at=grant.expires_at,
        spec=task.spec,
        connection=source.connection,
        credential=credential,
        fingerprint_pepper=_pepper(store),
        suppressions=[
            rule.as_payload() for rule in suppressions.applicable_suppressions(db, source.id)
        ],
    )


@router.post("/scan-tasks/{task_id}/results")
async def submit_results(
    task_id: uuid.UUID,
    body: ResultsSubmission,
    engine: CurrentEngine,
    db: SessionDep,
    dispatcher: DispatcherDep,
) -> ResultsAccepted:
    """The only ingress for results (#36).

    Requires a live lease held by *this* engine. Replays carrying the same
    idempotency key are answered without re-ingesting; a different key against a
    finished task is a conflict, because that is an engine reporting work the API has
    already accounted for.
    """
    task = db.get(ScanTask, task_id)
    if task is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "task not found")
    if task.engine_id != engine.id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "task is not leased by this engine")
    if body.status not in REPORTABLE_STATUSES:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "an engine may report completed or failed only",
        )

    if task.result_key is not None:
        if task.result_key == body.idempotency_key:
            logger.info("results_replayed", task_id=str(task.id), key=body.idempotency_key)
            return ResultsAccepted(task_id=task.id, replay=True)
        raise HTTPException(status.HTTP_409_CONFLICT, "task results were already submitted")

    if task.status not in service.LEASED_STATUSES:
        # Cancelled, reclaimed, or already terminal: whatever this engine computed is
        # no longer wanted, and accepting it would resurrect work the API moved on from.
        raise HTTPException(status.HTTP_409_CONFLICT, "task is not leased")

    scan = db.get(Scan, task.scan_id)
    if scan is None:  # pragma: no cover — FK guarantees it
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scan not found")

    now = datetime.now(UTC)
    outcome = ingest.IngestOutcome()
    created = 0

    if body.status is ScanTaskStatus.COMPLETED:
        if task.kind is ScanTaskKind.DISCOVERY:
            created = len(body.task_specs)
        elif body.findings:
            outcome = ingest.ingest_findings(db, scan, body.findings, now=now)

    ingest.merge_scan_counts(scan, outcome, body.counts)
    if body.rulepack_version:
        scan.rulepack_version = body.rulepack_version
    task.result_key = body.idempotency_key
    service.complete_task(db, task, status=body.status, error=body.error, now=now)
    db.add(scan)
    db.commit()

    # Fan-out and finalisation both commit; they run after the results themselves are
    # durable so a crash between them loses nothing but a re-dispatch.
    if created:
        service.fan_out_fetch_tasks(db, scan, body.task_specs, dispatcher=dispatcher)

    final_status = service.finalize_scan_if_done(db, scan.id, now=now)
    if final_status is ScanStatus.COMPLETED:
        db.refresh(scan)
        reconcile_scan(db, scan, now=now)

    return ResultsAccepted(
        task_id=task.id,
        findings_ingested=outcome.ingested,
        findings_suppressed=outcome.suppressed,
        findings_reopened=outcome.reopened,
        fetch_tasks_created=created,
        scan_status=final_status.value if final_status else None,
    )


def _pepper(store: SecretStoreDep) -> str | None:
    """The fingerprint pepper, base64, or None if the deployment has none yet.

    Not fatal: detection still runs, and a scan without a pepper is a
    misconfiguration an operator should see in the logs rather than a crashed engine.
    """
    try:
        return base64.b64encode(store.get_pepper()).decode()
    except SecretStoreError as exc:
        logger.warning("fingerprint_pepper_unavailable", error=str(exc))
        return None
