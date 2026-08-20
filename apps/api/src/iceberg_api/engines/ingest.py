"""Persisting what an engine reports (#36, #37 — ADR 0004, 0006, 0008).

The "new" and "matching" halves of reconciliation happen here, at the moment a
finding arrives:

* **unseen fingerprint** → a new finding, ``open``
* **known fingerprint** → keep its triage state, bump ``last_seen_scan``, refresh
  the display fields
* **known and auto-resolved** → re-open it: the secret came back
* **suppressed** → stored and marked, never discarded (ADR 0008)
* **below the confidence threshold** → dropped, and counted

The threshold is applied here as well as in the engine (#70). Engines are handed
the value in their lease, so the two normally agree; applying it again is what
stops an engine running a stale image — or a rebuilt one with a lower default —
from filling the queue with matches this deployment has decided are noise.

A deliberate asymmetry: an analyst's decision (`false_positive`, `accepted_risk`) is
never overwritten by a scan, but an *automatic* resolution is, because that was only
ever an inference from absence.
"""

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

import structlog
from iceberg_core.correlation import correlation_id
from iceberg_core.enums import FindingEventKind, FindingState, ValidationStatus
from iceberg_core.metrics import FINDINGS_INGESTED
from iceberg_core.models import Finding, FindingEvent, Scan
from sqlmodel import Session, col, select

from iceberg_api import suppressions
from iceberg_api.engines.schemas import FindingPayload
from iceberg_api.findings import ownership

logger = structlog.get_logger()


@dataclass(slots=True)
class IngestOutcome:
    """Tallies for the response, the scan's counts, and the logs."""

    ingested: int = 0
    suppressed: int = 0
    reopened: int = 0
    #: Reported by the engine, dropped here for scoring too low.
    below_threshold: int = 0
    #: Matched under the outgoing pepper and re-keyed to the new identity during
    #: a rotation window (#64). Zero outside one. Watching this fall to zero
    #: across a full scan cycle is how an operator knows the rotation is done.
    rekeyed: int = 0
    fingerprints: list[str] = field(default_factory=list)


def ingest_findings(
    db: Session,
    scan: Scan,
    payloads: list[FindingPayload],
    *,
    now: datetime | None = None,
    threshold: float = 0.0,
    correlation_key: bytes | None = None,
) -> IngestOutcome:
    """Store a task's findings. Does not commit; the route owns the transaction.

    ``correlation_key`` derives each finding's ``correlation_id`` (ADR 0011).
    None stores NULL and carries on — unlike a missing pepper this is repairable
    later, because the input is the stored hash.
    """
    at = now or datetime.now(UTC)
    rules = suppressions.applicable_suppressions(db, scan.source_id, now=at)
    # Read once for the whole batch, so every finding in one submission is routed
    # by the same rule set rather than by whatever a concurrent edit left behind
    # halfway through (#146).
    policy = ownership.load(db, scan.source_id)
    outcome = IngestOutcome()

    # An unscored finding is kept: `None` means the engine did not judge it,
    # which is not the same as judging it noise, and dropping it would lose a
    # finding over a missing field.
    scored = [
        payload
        for payload in payloads
        if payload.confidence is None or payload.confidence >= threshold
    ]
    outcome.below_threshold = len(payloads) - len(scored)
    # One query for the batch instead of one or two per payload (#197). This is
    # the hottest path in the API — a 500-finding batch issued up to a thousand
    # point selects inside the ingest transaction, each holding the scan lock a
    # little longer.
    known = _load_findings(db, scan.source_id, scored)

    for payload in scored:
        suppression = suppressions.first_match(
            rules,
            fingerprint=payload.fingerprint,
            rule_id=payload.rule_id,
            resource_locator=payload.resource_locator,
        )
        existing = known.get(payload.fingerprint)

        rekeyed = False
        if existing is None and payload.previous_fingerprint:
            # A pepper rotation is in progress (#64). The engine reported this
            # finding's identity under both peppers; a hit on the old one is the
            # *same* finding, so it is re-keyed in place — which is what carries
            # the analyst's state, notes, assignee and event trail across a
            # rotation that no recomputation could perform.
            existing = known.get(payload.previous_fingerprint)
            if existing is not None and not _same_secret(existing, payload):
                # The old identity matched but the stored hash of the secret does
                # not, so this is a different secret wearing a colliding
                # fingerprint — or an engine that paired the two identities under
                # mismatched peppers. Re-keying would move an analyst's decision
                # onto a secret it was never about, which is the one thing a
                # rotation must not do; treat it as a finding nobody has seen.
                logger.warning(
                    "finding_rekey_refused_hash_mismatch",
                    finding_id=str(existing.id),
                    scan_id=str(scan.id),
                )
                existing = None
            if existing is not None:
                existing.fingerprint = payload.fingerprint
                existing.secret_hash = payload.secret_hash
                # The correlation id is a function of the hash, so it must move
                # with it — a row left keyed under the old pepper's hash would
                # sit in a cluster of one until the next reindex.
                existing.correlation_id = (
                    correlation_id(payload.secret_hash, key=correlation_key)
                    if correlation_key is not None
                    else None
                )
                rekeyed = True
                outcome.rekeyed += 1
                # The row now answers to the new identity and no longer to the
                # old, which is what a re-read would have found. Keeping the map
                # in step is what makes it a cache of the table rather than a
                # snapshot of it.
                known.pop(payload.previous_fingerprint, None)
                known[payload.fingerprint] = existing

        if existing is None:
            # Registered under its fingerprint so a second payload for the same
            # one — the same secret reported twice in a batch — refreshes it
            # rather than inserting a duplicate the unique constraint refuses.
            # The per-payload select used to get this from autoflush.
            known[payload.fingerprint] = _create(
                db,
                scan,
                payload,
                suppression=suppression,
                at=at,
                correlation_key=correlation_key,
                policy=policy,
            )
        elif _refresh(
            db,
            existing,
            scan,
            payload,
            suppression=suppression,
            at=at,
            correlation_key=correlation_key,
            policy=policy,
        ):
            outcome.reopened += 1
        if rekeyed:
            logger.info(
                "finding_rekeyed",
                finding_id=str(existing.id) if existing else None,
                scan_id=str(scan.id),
            )

        outcome.ingested += 1
        outcome.fingerprints.append(payload.fingerprint)
        if suppression is not None:
            outcome.suppressed += 1

    FINDINGS_INGESTED.inc(outcome.ingested)
    logger.info(
        "findings_ingested",
        scan_id=str(scan.id),
        ingested=outcome.ingested,
        suppressed=outcome.suppressed,
        reopened=outcome.reopened,
        below_threshold=outcome.below_threshold,
        rekeyed=outcome.rekeyed,
    )
    return outcome


def _same_secret(existing: Finding, payload: FindingPayload) -> bool:
    """Whether the re-key candidate really is the secret already stored.

    ``previous_secret_hash`` is the same value the stored row holds, recomputed
    under the outgoing pepper, so comparing them is the one check available that
    the two identities describe one secret. An engine too old to send it is
    trusted on the fingerprint alone — that is the behaviour the field was added
    to strengthen, not a precondition for re-keying at all.
    """
    return payload.previous_secret_hash is None or (
        payload.previous_secret_hash == existing.secret_hash
    )


#: How many fingerprints go into one `IN (...)`. A batch is capped at 500
#: findings and each may carry a second identity during a rotation window, so
#: this is one or two round trips — while staying well under the bind-parameter
#: ceiling of every database this runs on.
_LOOKUP_CHUNK = 500


def _load_findings(
    db: Session,
    source_id: uuid.UUID,
    payloads: list[FindingPayload],
) -> dict[str, Finding]:
    """Every stored finding this batch could be about, keyed by fingerprint.

    Both identities are looked up together: the one each payload carries now, and
    the one it carried under the outgoing pepper during a rotation window (#64).
    Fetching them in one pass is the whole point — asking per payload made ingest
    an N+1 on the API's busiest transaction.

    The result is used as a live map, not a snapshot: the loop registers what it
    creates and re-keys what it moves, so a second payload for the same
    fingerprint sees what the per-payload select used to see through autoflush.
    """
    wanted = {payload.fingerprint for payload in payloads}
    wanted.update(
        payload.previous_fingerprint for payload in payloads if payload.previous_fingerprint
    )
    ordered = sorted(wanted)
    found: dict[str, Finding] = {}
    for start in range(0, len(ordered), _LOOKUP_CHUNK):
        chunk = ordered[start : start + _LOOKUP_CHUNK]
        for finding in db.exec(
            select(Finding)
            .where(col(Finding.source_id) == source_id)
            .where(col(Finding.fingerprint).in_(chunk))
        ):
            found[finding.fingerprint] = finding
    return found


def _create(
    db: Session,
    scan: Scan,
    payload: FindingPayload,
    *,
    suppression: suppressions.SuppressionRule | None,
    at: datetime,
    correlation_key: bytes | None,
    policy: ownership.Policy,
) -> Finding:
    finding = Finding(
        source_id=scan.source_id,
        fingerprint=payload.fingerprint,
        rule_id=payload.rule_id,
        rulepack_version=payload.rulepack_version,
        resource_locator=payload.resource_locator,
        redacted_snippet=payload.redacted_snippet,
        secret_hash=payload.secret_hash,
        correlation_id=(
            correlation_id(payload.secret_hash, key=correlation_key)
            if correlation_key is not None
            else None
        ),
        entropy=payload.entropy,
        confidence=payload.confidence,
        severity=payload.severity,
        state=FindingState.OPEN,
        first_seen_scan_id=scan.id,
        last_seen_scan_id=scan.id,
    )
    db.add(finding)
    db.flush()
    _record_validation(db, finding, payload, from_status=None, scan_id=scan.id, at=at)
    # Ownership before suppression: a finding that arrives already silenced still
    # gets an owner and a clock, so the day its suppression lapses it is somebody's
    # work immediately rather than sitting unowned until the scan after that (#146).
    ownership.route(db, finding, policy, scan_id=scan.id)
    ownership.start_clock(db, finding, policy, at=at)
    if suppression is not None:
        suppressions.suppress(db, finding, suppression, at=at)
    return finding


def _refresh(
    db: Session,
    finding: Finding,
    scan: Scan,
    payload: FindingPayload,
    *,
    suppression: suppressions.SuppressionRule | None,
    at: datetime,
    correlation_key: bytes | None,
    policy: ownership.Policy,
) -> bool:
    """Update a known finding for this sighting. Returns True if it re-opened."""
    finding.last_seen_scan_id = scan.id

    # A row from before the correlation key existed gets its id on next sighting;
    # a non-null id is left alone (identity fields are never refreshed).
    if finding.correlation_id is None and correlation_key is not None:
        finding.correlation_id = correlation_id(finding.secret_hash, key=correlation_key)

    # Display metadata is refreshed — line numbers move, snippets change around the
    # secret — while identity (fingerprint, secret_hash) is by definition unchanged.
    finding.resource_locator = payload.resource_locator
    finding.redacted_snippet = payload.redacted_snippet
    finding.rulepack_version = payload.rulepack_version
    finding.entropy = payload.entropy
    finding.confidence = payload.confidence
    finding.severity = payload.severity
    prior_validation = finding.validation_status
    prior_validation_identity = (
        finding.validation_provider,
        finding.validation_validator_id,
        finding.validation_contract_version,
        finding.validation_status,
        finding.validation_reason,
    )
    if payload.validation is not None:
        current_validation_identity = (
            payload.validation.provider,
            payload.validation.validator_id,
            payload.validation.contract_version,
            payload.validation.status,
            payload.validation.reason,
        )
        if current_validation_identity != prior_validation_identity:
            _record_validation(
                db, finding, payload, from_status=prior_validation, scan_id=scan.id, at=at
            )

    reopened = False
    if finding.state is FindingState.RESOLVED:
        # It was resolved — the secret had been removed — and now it is back. A
        # sighting refutes "resolved" whether the resolution was automatic (an
        # inference from absence) or manual (an analyst believing it was fixed):
        # ADR 0006, "a resolved secret that reappears re-opens automatically". The
        # analyst *judgement* states — false_positive, accepted_risk — are not
        # RESOLVED, so they are left untouched, exactly as the ADR intends.
        finding.state = FindingState.OPEN
        finding.resolution = None
        db.add(
            FindingEvent(
                finding_id=finding.id,
                actor_id=None,
                # Idempotent per scan by index: a batched task that re-reports the
                # same finding cannot append a second reopen.
                scan_id=scan.id,
                kind=FindingEventKind.REOPENED,
                from_value=FindingState.RESOLVED.value,
                to_value=FindingState.OPEN.value,
                comment=f"seen again by scan {scan.id}",
            )
        )
        reopened = True

    # An unowned finding is routed on every sighting, so a rule added today drains
    # yesterday's unowned queue at the next scan. An owned one is left alone —
    # ownership is established once, never continuously re-decided (#146).
    ownership.route(db, finding, policy, scan_id=scan.id)
    # A reopen restarts the clock: the secret came back, and the team gets the full
    # response target from the sighting that refuted the resolution rather than a
    # deadline that expired while the finding was correctly resolved.
    ownership.start_clock(db, finding, policy, at=at, restart=reopened)

    # A suppression that appeared since the last scan applies now; one that expired
    # stops applying, and the finding returns to the active view.
    if suppression is not None:
        suppressions.suppress(db, finding, suppression, at=at)
    else:
        suppressions.release(db, finding, reason=f"no suppression matched in scan {scan.id}")

    db.add(finding)
    return reopened


def _record_validation(
    db: Session,
    finding: Finding,
    payload: FindingPayload,
    *,
    from_status: ValidationStatus | None,
    scan_id: uuid.UUID,
    at: datetime,
) -> None:
    """Persist structured metadata and its content-free status transition."""
    result = payload.validation
    if result is None:
        return
    finding.validation_provider = result.provider
    finding.validation_validator_id = result.validator_id
    finding.validation_contract_version = result.contract_version
    finding.validation_status = result.status
    finding.validation_reason = result.reason
    finding.validated_at = at
    db.add(finding)
    db.add(
        FindingEvent(
            finding_id=finding.id,
            actor_id=None,
            # Provenance only. Validation is *not* in the idempotency index: a scan
            # whose tasks see a credential change status mid-run may truthfully
            # record two, and constraining that would fail the submission.
            scan_id=scan_id,
            kind=FindingEventKind.VALIDATION,
            from_value=getattr(from_status, "value", None),
            to_value=result.status.value,
            # All components are bounded identifiers or a schema-constrained
            # machine reason. Provider response bodies never enter the payload.
            comment=(
                f"{result.provider}:{result.validator_id}:{result.contract_version}:{result.reason}"
            ),
        )
    )


def merge_scan_counts(scan: Scan, outcome: IngestOutcome, engine_counts: dict[str, int]) -> None:
    """Accumulate one task's tallies onto the scan.

    Additive because tasks report independently and in any order: a scan's counts are
    the sum of what its tasks saw, not whatever the last one to finish happened to
    report.
    """
    totals: dict[str, int] = {
        key: int(value) for key, value in scan.counts.items() if isinstance(value, int | float)
    }
    for key, value in engine_counts.items():
        totals[key] = totals.get(key, 0) + int(value)
    totals["findings"] = totals.get("findings", 0) + outcome.ingested
    totals["suppressed"] = totals.get("suppressed", 0) + outcome.suppressed
    totals["reopened"] = totals.get("reopened", 0) + outcome.reopened
    totals["below_threshold"] = totals.get("below_threshold", 0) + outcome.below_threshold
    totals["rekeyed"] = totals.get("rekeyed", 0) + outcome.rekeyed
    scan.counts = {**scan.counts, **totals}
