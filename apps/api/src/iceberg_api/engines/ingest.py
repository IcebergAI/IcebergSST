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

from dataclasses import dataclass, field
from datetime import UTC, datetime

import structlog
from iceberg_core.correlation import correlation_id
from iceberg_core.enums import FindingEventKind, FindingState
from iceberg_core.metrics import FINDINGS_INGESTED
from iceberg_core.models import Finding, FindingEvent, Scan
from sqlmodel import Session, col, select

from iceberg_api import suppressions
from iceberg_api.engines.schemas import FindingPayload

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

    ``correlation_key`` derives each finding's ``correlation_id`` (ADR 0010).
    None stores NULL and carries on — unlike a missing pepper this is repairable
    later, because the input is the stored hash.
    """
    at = now or datetime.now(UTC)
    rules = suppressions.applicable_suppressions(db, scan.source_id, now=at)
    outcome = IngestOutcome()

    for payload in payloads:
        # An unscored finding is kept: `None` means the engine did not judge it,
        # which is not the same as judging it noise, and dropping it would lose a
        # finding over a missing field.
        if payload.confidence is not None and payload.confidence < threshold:
            outcome.below_threshold += 1
            continue

        suppression = suppressions.first_match(
            rules,
            fingerprint=payload.fingerprint,
            rule_id=payload.rule_id,
            resource_locator=payload.resource_locator,
        )
        existing = db.exec(
            select(Finding)
            .where(col(Finding.source_id) == scan.source_id)
            .where(col(Finding.fingerprint) == payload.fingerprint)
        ).first()

        rekeyed = False
        if existing is None and payload.previous_fingerprint:
            # A pepper rotation is in progress (#64). The engine reported this
            # finding's identity under both peppers; a hit on the old one is the
            # *same* finding, so it is re-keyed in place — which is what carries
            # the analyst's state, notes, assignee and event trail across a
            # rotation that no recomputation could perform.
            existing = db.exec(
                select(Finding)
                .where(col(Finding.source_id) == scan.source_id)
                .where(col(Finding.fingerprint) == payload.previous_fingerprint)
            ).first()
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

        if existing is None:
            _create(
                db, scan, payload, suppression=suppression, at=at, correlation_key=correlation_key
            )
        elif _refresh(
            db,
            existing,
            scan,
            payload,
            suppression=suppression,
            at=at,
            correlation_key=correlation_key,
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


def _create(
    db: Session,
    scan: Scan,
    payload: FindingPayload,
    *,
    suppression: suppressions.SuppressionRule | None,
    at: datetime,
    correlation_key: bytes | None,
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
                kind=FindingEventKind.REOPENED,
                from_value=FindingState.RESOLVED.value,
                to_value=FindingState.OPEN.value,
                comment=f"seen again by scan {scan.id}",
            )
        )
        reopened = True

    # A suppression that appeared since the last scan applies now; one that expired
    # stops applying, and the finding returns to the active view.
    if suppression is not None:
        suppressions.suppress(db, finding, suppression, at=at)
    else:
        suppressions.release(db, finding, reason=f"no suppression matched in scan {scan.id}")

    db.add(finding)
    return reopened


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
