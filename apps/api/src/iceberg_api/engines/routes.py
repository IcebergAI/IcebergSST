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
from iceberg_core.enums import CoverageReason, ScanTaskKind, ScanTaskStatus
from iceberg_core.models import (
    AUDIT_ENGINE_REGISTERED,
    AUDIT_ENGINE_TOKEN_ROTATED,
    AUDIT_TARGET_ENGINE,
    Engine,
    Scan,
    ScanTask,
    Source,
)
from iceberg_core.secrets import SecretStoreError
from sqlalchemy.exc import IntegrityError
from sqlmodel import col, select

from iceberg_api import audit, suppressions
from iceberg_api.auth.dependencies import (
    CsrfProtected,
    SecretStoreDep,
    SessionDep,
    SettingsDep,
)
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
    ProgressAccepted,
    ProgressSubmission,
    ResultsAccepted,
    ResultsSubmission,
    RulepackReport,
    TaskCoverageReport,
)
from iceberg_api.scans import cursors, service
from iceberg_api.scans.coverage import failure_report, merge_task_report, stored_task_report
from iceberg_api.validation import service as validation_service

router = APIRouter(tags=["engines"])
logger = structlog.get_logger()

#: The only outcomes an engine may report. Cancellation is the API's decision, and
#: queued/leased are not outcomes.
REPORTABLE_STATUSES = (ScanTaskStatus.COMPLETED, ScanTaskStatus.FAILED)


def _effective_outcome(
    body: ResultsSubmission,
    *,
    counts: dict[str, int],
    coverage: TaskCoverageReport | None,
) -> tuple[ScanTaskStatus, str | None]:
    """Fail closed when a connector could not read requested content.

    Engines report both a task status and connector tallies.  Older engines could
    truthfully report ``units_failed`` while still labelling the task completed;
    trusting that label lets source-wide reconciliation treat unread content as
    evidence that its old findings disappeared.  The API is the only writer of
    record, so it enforces the invariant at ingest as well as relying on current
    runners to send the correct status.

    ``counts`` and ``coverage`` are the task's **merged** totals, not the final
    submission's delta (#143). A task that flushed batches reports each one
    separately, so a unit that failed in the first batch is absent from the last
    body — judging that body alone would let a task whose failures all landed
    early report itself complete, and reconciliation would then auto-resolve
    against content nobody read.
    """
    failed_units = counts.get("units_failed", 0)
    truncated_units = counts.get("units_truncated", 0)
    if coverage is not None:
        failed_objects = coverage.counts.failed
        scope_gaps = coverage.scope.gaps
        if body.status is ScanTaskStatus.COMPLETED and (failed_objects or scope_gaps):
            return (
                ScanTaskStatus.FAILED,
                "coverage report contains uninspected requested content",
            )
    if body.status is ScanTaskStatus.COMPLETED and failed_units > 0 and not truncated_units:
        noun = "unit" if failed_units == 1 else "units"
        return (
            ScanTaskStatus.FAILED,
            f"{failed_units} requested content {noun} could not be read",
        )
    if body.status is ScanTaskStatus.COMPLETED and truncated_units > 0 and not failed_units:
        noun = "unit" if truncated_units == 1 else "units"
        verb = "was" if truncated_units == 1 else "were"
        return (
            ScanTaskStatus.FAILED,
            f"{truncated_units} requested content {noun} {verb} truncated",
        )
    if body.status is ScanTaskStatus.COMPLETED and (failed_units > 0 or truncated_units > 0):
        return (
            ScanTaskStatus.FAILED,
            f"{failed_units} requested content units could not be read and "
            f"{truncated_units} were truncated",
        )
    return body.status, body.error


def _checkpoint_still_valid(task: ScanTask, scan: Scan) -> bool:
    """Whether a stored resume point was taken under this scan's configuration.

    Compared rather than trusted: a task can be reclaimed long after its first
    attempt, and both the source and the running rule pack may have moved since.
    An unreadable context is treated as invalid — restarting a spec costs a re-read
    and nothing else, while resuming on a guess costs coverage.
    """
    context = task.checkpoint_context
    expected_configuration = (
        scan.source_configuration_version.isoformat() if scan.source_configuration_version else None
    )
    return (
        context.get("source_configuration_version") == expected_configuration
        and context.get("rulepack_version") == scan.rulepack_version
    )


def _rulepack_record(report: RulepackReport) -> dict[str, object]:
    """The stored shape of a reported rule pack. Metadata only — never a regex."""
    return report.model_dump(mode="json")


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
    if body.rulepack is not None:
        engine.rulepack = _rulepack_record(body.rulepack)

    minted = mint_token(engine)
    db.add(minted.engine)
    # Recorded in the same transaction as the mutation: enrolling an engine (or
    # rotating its token) mints a credential that later receives decrypted source
    # credentials and the fingerprint pepper at lease time — the most consequential
    # admin action in the system, and it belongs in the durable trail, not only a
    # log line. The token itself is never recorded (audit.py contract).
    audit.record(
        db,
        actor_id=admin.id,
        action=AUDIT_ENGINE_TOKEN_ROTATED if rotating else AUDIT_ENGINE_REGISTERED,
        target_type=AUDIT_TARGET_ENGINE,
        target_id=minted.engine.id,
        detail={"name": minted.engine.name},
    )
    try:
        db.commit()
    except IntegrityError as exc:
        # Two concurrent registrations of the same new name: one row exists, one
        # token was shown. The loser must retry so its operator gets a real token
        # — answering with the winner's engine would hand back a credential this
        # caller never saw.
        db.rollback()
        raise HTTPException(
            status.HTTP_409_CONFLICT, "engine was registered concurrently; retry to rotate"
        ) from exc
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
    # Reported every beat, so a rolling deploy shows up in `GET /rules` as it
    # happens rather than only when someone re-registers the engine (#70).
    record_heartbeat(
        db,
        engine,
        version=body.version,
        rulepack=_rulepack_record(body.rulepack) if body.rulepack else None,
        now=now,
    )

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
    settings: SettingsDep,
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

    # Fail closed on a missing pepper rather than lease without one: fingerprints
    # computed unpeppered (or with a different pepper) match nothing stored, so
    # every finding would ingest as new and reconciliation would auto-resolve the
    # real ones — a transient secret-store failure must not cost the triage state
    # (ADR 0006/0007).
    try:
        pepper = base64.b64encode(store.get_pepper()).decode()
    except SecretStoreError as exc:
        service.complete_task(
            db,
            task,
            status=ScanTaskStatus.FAILED,
            error="fingerprint pepper unavailable",
            coverage=failure_report(task.kind, CoverageReason.CONNECTOR_ERROR),
        )
        db.commit()
        service.finalize_and_reconcile(db, task.scan_id)
        logger.warning("lease_pepper_unavailable", source_id=str(source.id))
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "fingerprint pepper could not be read",
        ) from exc

    # The outgoing pepper, during a rotation window only (#64). Unlike the pepper
    # above this does *not* fail closed: a deployment that is not rotating has no
    # previous pepper, and one that is would rather scan without re-keying this
    # round — findings ingest as new, which is recoverable — than not scan at all.
    previous_pepper: str | None = None
    try:
        previous = store.get_previous_pepper()
        previous_pepper = base64.b64encode(previous).decode() if previous else None
    except SecretStoreError:
        logger.warning("lease_previous_pepper_unavailable", source_id=str(source.id))

    credential: str | None = None
    if source.credential_ref is not None:
        try:
            credential = store.open(source.credential_ref).get_secret_value()
        except SecretStoreError as exc:
            # Fail the task rather than send an engine off without a credential: a
            # scan that cannot authenticate should say so, not report zero findings.
            service.complete_task(
                db,
                task,
                status=ScanTaskStatus.FAILED,
                error="source credential unreadable",
                coverage=failure_report(task.kind, CoverageReason.PERMISSION_DENIED),
            )
            db.commit()
            # The task just went terminal outside the results path, so the scan
            # must be settled here — nothing else would ever finish it, and an
            # unfinished scan blocks its source forever.
            service.finalize_and_reconcile(db, task.scan_id)
            logger.warning("lease_credential_unreadable", source_id=str(source.id))
            raise HTTPException(
                status.HTTP_500_INTERNAL_SERVER_ERROR,
                "source credential could not be decrypted",
            ) from exc

    # A resume point is only meaningful under the configuration it was taken from
    # (#143). Handing back one taken under different scope filters or a different
    # rule pack would resume into content this scan does not cover, or skip content
    # the new rules have never seen — either way a scan that reports more coverage
    # than it has. Restarting the spec is the cheap, correct answer.
    checkpoint = task.checkpoint
    if checkpoint and not _checkpoint_still_valid(task, scan):
        service.discard_checkpoint(db, task)
        db.commit()
        checkpoint = {}
        logger.info("scan_task_checkpoint_discarded", task_id=str(task.id))

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
        checkpoint=checkpoint,
        checkpoint_sequence=task.checkpoint_sequence,
        cursors=cursors.positions_for_scan(db, scan),
        mode=scan.mode,
        credential=credential,
        fingerprint_pepper=pepper,
        previous_fingerprint_pepper=previous_pepper,
        suppressions=[
            rule.as_payload() for rule in suppressions.applicable_suppressions(db, source.id)
        ],
        confidence_threshold=settings.confidence_threshold,
        validation_policies=validation_service.enabled_lease_snapshot(
            db, deployment_enabled=settings.secret_validation_enabled
        ),
    )


@router.post("/scan-tasks/{task_id}/progress")
async def submit_progress(
    task_id: uuid.UUID,
    body: ProgressSubmission,
    engine: CurrentEngine,
    db: SessionDep,
    settings: SettingsDep,
    store: SecretStoreDep,
) -> ProgressAccepted:
    """Durably record one batch of a still-running task (#143).

    The counterpart to ``/results`` for work that has not finished. Findings and
    the connector's resume point are written in a single transaction, because a
    checkpoint that commits ahead of its findings tells the next attempt to start
    beyond content nobody stored — which loses secrets silently, and is the one
    failure this whole mechanism exists to prevent.

    Deliberately **not** terminal: no ``complete_task``, no ``finalize_and_reconcile``.
    A batch says "this much is safe", never "this task is done".
    """
    task = db.get(ScanTask, task_id)
    if task is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "task not found")
    if task.engine_id != engine.id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "task is not leased by this engine")
    if task.kind is not ScanTaskKind.FETCH:
        # Discovery produces specs, not findings, and its output is meaningless
        # until complete — there is nothing a partial discovery could safely store.
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "only fetch tasks batch results")

    try:
        validation_service.require_authorized_results(
            db,
            body.findings,
            deployment_enabled=settings.secret_validation_enabled,
        )
    except validation_service.UnauthorizedValidation as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc

    now = datetime.now(UTC)
    scan = db.exec(select(Scan).where(col(Scan.id) == task.scan_id).with_for_update()).one_or_none()
    if scan is None:  # pragma: no cover — FK guarantees it
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scan not found")

    context = {
        "source_configuration_version": (
            scan.source_configuration_version.isoformat()
            if scan.source_configuration_version
            else None
        ),
        "rulepack_version": body.rulepack_version,
    }
    if not service.advance_checkpoint(
        db,
        task,
        sequence=body.sequence,
        checkpoint=body.checkpoint,
        context=context,
    ):
        # Duplicate, out of order, or from an engine whose lease has gone. All
        # three are the same answer: nothing was ingested, and the stored counter
        # tells the engine where the task actually stands.
        db.rollback()
        db.refresh(task)
        if task.engine_id != engine.id or task.result_key is not None:
            raise HTTPException(status.HTTP_409_CONFLICT, "task is no longer accepting batches")
        logger.info(
            "scan_task_batch_refused",
            task_id=str(task.id),
            offered=body.sequence,
            stored=task.checkpoint_sequence,
        )
        return ProgressAccepted(task_id=task.id, sequence=task.checkpoint_sequence, replay=True)

    outcome = ingest.IngestOutcome()
    if body.findings:
        # Fail-open on the correlation key exactly as `/results` does (ADR 0011):
        # a transient secret-store failure must not drop findings.
        correlation_key: bytes | None = None
        try:
            correlation_key = store.get_correlation_key()
        except SecretStoreError:
            logger.warning("correlation_key_unavailable", scan_id=str(scan.id))

        outcome = ingest.ingest_findings(
            db,
            scan,
            body.findings,
            now=now,
            threshold=settings.confidence_threshold,
            correlation_key=correlation_key,
        )

    if body.coverage is not None:
        merged = merge_task_report(stored_task_report(task), body.coverage)
        task.coverage = merged.model_dump(mode="json")
        db.add(task)

    ingest.merge_scan_counts(scan, outcome, body.counts)
    if body.rulepack_version:
        scan.rulepack_version = body.rulepack_version
    db.add(scan)
    db.commit()

    return ProgressAccepted(
        task_id=task.id,
        sequence=body.sequence,
        findings_ingested=outcome.ingested,
        findings_suppressed=outcome.suppressed,
        findings_reopened=outcome.reopened,
        findings_below_threshold=outcome.below_threshold,
    )


@router.post("/scan-tasks/{task_id}/results")
async def submit_results(
    task_id: uuid.UUID,
    body: ResultsSubmission,
    engine: CurrentEngine,
    db: SessionDep,
    dispatcher: DispatcherDep,
    settings: SettingsDep,
    store: SecretStoreDep,
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
    if body.coverage is not None and body.coverage.phase is not task.kind:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "coverage phase does not match the leased task kind",
        )
    if (
        task.kind is ScanTaskKind.DISCOVERY
        and body.coverage is not None
        and body.coverage.scope.discovered != len(body.task_specs)
    ):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "discovery coverage must reconcile to the reported task specs",
        )
    if task.kind is ScanTaskKind.DISCOVERY and body.findings:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "discovery tasks may report task specs but not findings",
        )
    if body.checkpoint_sequence != task.checkpoint_sequence:
        # The engine believes it flushed a different number of batches than the API
        # recorded. Merging the remainder onto the wrong base would over- or
        # under-count coverage, and an over-count reads as content that was never
        # there. Refuse and let the task be reclaimed.
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "reported batch sequence does not match the recorded one",
        )
    if task.kind is ScanTaskKind.FETCH and body.task_specs:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "fetch tasks may report findings but not task specs",
        )

    try:
        validation_service.require_authorized_results(
            db,
            body.findings,
            deployment_enabled=settings.secret_validation_enabled,
        )
    except validation_service.UnauthorizedValidation as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc

    now = datetime.now(UTC)

    # Claiming result_key is a conditional UPDATE: of two concurrent submissions,
    # exactly one records results. The loser re-reads and answers as a replay or a
    # conflict — never a second ingest, never double-counted tallies.
    if not service.claim_result(db, task, body.idempotency_key):
        db.rollback()
        db.refresh(task)
        if task.result_key == body.idempotency_key:
            return _replay(db, task, now=now)
        if task.result_key is not None:
            raise HTTPException(status.HTTP_409_CONFLICT, "task results were already submitted")
        # Cancelled, reclaimed, or already terminal: whatever this engine computed is
        # no longer wanted, and accepting it would resurrect work the API moved on from.
        raise HTTPException(status.HTTP_409_CONFLICT, "task is not leased")

    # Lock the scan row for the rest of the transaction: two tasks of one scan can
    # be submitted concurrently, and `merge_scan_counts` is a read-modify-write of
    # the whole counts blob. Without the lock, the second commit clobbers the
    # first's tallies (findings, units_scanned, …). FOR UPDATE serialises the two
    # so each merges onto the other's committed result.
    scan = db.exec(select(Scan).where(col(Scan.id) == task.scan_id).with_for_update()).one_or_none()
    if scan is None:  # pragma: no cover — FK guarantees it
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scan not found")

    outcome = ingest.IngestOutcome()
    fetch_tasks: list[ScanTask] = []

    # A task that flushed batches has already reported part of its coverage; this
    # body carries only the remainder. Judge the *task*, not the last body of it —
    # a unit that failed in batch one is absent from here, and calling the task
    # complete on that basis would let reconciliation auto-resolve against content
    # nobody read.
    #
    # Coverage carries this, not `counts`: a truncated or unreadable unit is
    # recorded as a failed *object* in the same batch's report, so the merged
    # report sees every batch's failures even though per-batch tallies are not
    # retained. `counts` stays the body's own, and is only consulted for an engine
    # old enough to send no coverage — which is also too old to send batches.
    #
    # `checkpoint_sequence == 0` means no batches at all, where this is
    # byte-identical to the previous behaviour.
    merged_coverage = body.coverage
    if body.checkpoint_sequence > 0:
        merged_coverage = (
            merge_task_report(stored_task_report(task), body.coverage)
            if body.coverage is not None
            else stored_task_report(task)
        )

    task_status, task_error = _effective_outcome(body, counts=body.counts, coverage=merged_coverage)

    if task.kind is ScanTaskKind.DISCOVERY:
        if body.task_specs:
            # Created in the same transaction that completes the discovery task: a
            # crash cannot record the discovery as done yet lose what it discovered.
            # Specs yielded before a late discovery failure are still safe to scan:
            # the failed discovery keeps the overall scan partial, so their findings
            # are ingested but the incomplete source can never reconcile.
            fetch_tasks = service.create_fetch_tasks(db, scan, body.task_specs)
    elif body.findings:
        # Ingested whatever the task's outcome. A connector that dies halfway
        # through a space still saw real secrets before it died, and
        # `complete_task(status=failed)` is terminal — reclaim only touches leased
        # work — so discarding them means they surface only if an operator re-runs
        # the whole scan. The scan's own status still records that it was partial,
        # and reconciliation still refuses to auto-resolve on it (ADR 0009 §4).
        # Fail-open, unlike the pepper: a missing correlation key stores NULL ids
        # that the maintenance backfill repairs from the stored hash, so losing
        # the key transiently must not fail the task or drop findings (ADR 0011).
        correlation_key: bytes | None = None
        try:
            correlation_key = store.get_correlation_key()
        except SecretStoreError:
            logger.warning("correlation_key_unavailable", scan_id=str(scan.id))

        outcome = ingest.ingest_findings(
            db,
            scan,
            body.findings,
            now=now,
            threshold=settings.confidence_threshold,
            correlation_key=correlation_key,
        )

    ingest.merge_scan_counts(scan, outcome, body.counts)
    if body.rulepack_version:
        scan.rulepack_version = body.rulepack_version
    if body.cursor is not None:
        # Held, not applied. A proposal is worth something only if the whole scan
        # completes with complete coverage, which is not knowable until the last
        # task reports — `finalize_and_reconcile` commits them together (#143).
        task.cursor_proposal = body.cursor.model_dump(mode="json")
    service.complete_task(
        db,
        task,
        status=task_status,
        error=task_error,
        coverage=merged_coverage.model_dump(mode="json") if merged_coverage else None,
        now=now,
    )
    db.add(scan)
    db.commit()

    if fetch_tasks:
        logger.info("scan_fanned_out", scan_id=str(scan.id), fetch_tasks=len(fetch_tasks))
    for fetch in fetch_tasks:
        try:
            dispatcher.enqueue(fetch.id)
        except Exception:  # durably queued; redispatch_stale_tasks retries
            logger.exception("scan_task_dispatch_failed", task_id=str(fetch.id))

    final_status = service.finalize_and_reconcile(db, scan.id, now=now)

    return ResultsAccepted(
        task_id=task.id,
        findings_ingested=outcome.ingested,
        findings_suppressed=outcome.suppressed,
        findings_reopened=outcome.reopened,
        findings_below_threshold=outcome.below_threshold,
        fetch_tasks_created=len(fetch_tasks),
        scan_status=final_status.value if final_status else None,
    )


def _replay(db: SessionDep, task: ScanTask, *, now: datetime) -> ResultsAccepted:
    """Acknowledge a duplicate submission without re-ingesting anything.

    A replay often means the first attempt's response was lost — possibly along
    with the follow-up finalisation, which ran in its own transaction. Re-checking
    it here repairs that: it is conditional, so if the scan already settled this
    is a cheap no-op.
    """
    logger.info("results_replayed", task_id=str(task.id), key=task.result_key)
    final_status = service.finalize_and_reconcile(db, task.scan_id, now=now)
    return ResultsAccepted(
        task_id=task.id,
        replay=True,
        scan_status=final_status.value if final_status else None,
    )
