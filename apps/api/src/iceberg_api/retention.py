"""Data retention (#73).

Findings and their append-only event trail grow forever, and so does the
administrative audit log. This deletes what a deployment has decided it no longer
needs — and nothing else, which is most of the design.

**Every window is off by default.** This database is evidence: it records where
secrets were found and who did what about them. Deleting some of it has to be a
decision somebody made, not something that starts happening because they
upgraded. With no windows configured this module does nothing at all.

**What is never eligible**, whatever the window says:

* **Open findings.** An unresolved secret is not old news, it is a secret nobody
  has dealt with.
* **Findings an analyst decided about** — ``false_positive``, ``accepted_risk``,
  or a manual resolution. Those are judgements, and a judgement that expires
  silently means the same finding comes back next scan with nobody remembering
  it was already considered. Only ``auto`` resolutions — an inference from
  absence, made by a scan — are eligible.
* **Events belonging to a finding that still exists and is open.** Its trail is
  how an analyst understands the state they are looking at.
* **A suppressed finding's row**, because the suppression is the reason it is not
  in anyone's list; deleting it would resurrect it on the next scan as new.

**The purge is itself audited.** Deleting evidence is an administrative action,
so each round that removes anything writes an ``audit_event`` recording what was
deleted, how much, and the window that justified it — and that row is subject to
the audit window like any other, which is the honest behaviour rather than a
special case that hides purges from the retention it enforces.

Deletion is batched (``retention_batch_size``) so the first purge on a database
that has never had one cannot hold locks for minutes. A round that hits the batch
ceiling simply continues on the next beat.
"""

from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta

import structlog
from iceberg_core.config import ApiSettings
from iceberg_core.enums import FindingResolution, FindingState
from iceberg_core.models import (
    AUDIT_RETENTION_PURGED,
    AUDIT_TARGET_RETENTION,
    AuditEvent,
    Finding,
    FindingEvent,
    RemediationAction,
)
from sqlmodel import Session, col, delete, select, update

from iceberg_api import audit

logger = structlog.get_logger()

#: Resolutions a purge may remove. Deliberately only this one — see the module
#: docstring. A tuple rather than a set so the membership test reads in the query.
PURGEABLE_RESOLUTIONS = (FindingResolution.AUTO,)


@dataclass(frozen=True, slots=True)
class PurgeResult:
    """What one retention round deleted (or, for evidence links, scrubbed)."""

    findings: int = 0
    finding_events: int = 0
    audit_events: int = 0
    #: Remediation actions whose evidence-link URLs were reduced to labels
    #: (#142). The rows survive; only where-the-proof-lives is aged out.
    remediation_evidence_scrubbed: int = 0

    def total(self) -> int:
        return (
            self.findings
            + self.finding_events
            + self.audit_events
            + self.remediation_evidence_scrubbed
        )


def purge(
    db: Session,
    settings: ApiSettings,
    *,
    now: datetime | None = None,
) -> PurgeResult:
    """Delete what has aged out. Commits, and audits itself if it removed anything."""
    at = now or datetime.now(UTC)
    batch = settings.retention_batch_size

    findings = _purge_findings(db, settings.retention_resolved_findings_days, at=at, batch=batch)
    # After the findings, so events cascaded away with their finding are not
    # counted twice — and so the count reported here is events pruned *from
    # surviving findings*, which is the number an operator is asking about.
    events = _purge_finding_events(db, settings.retention_finding_events_days, at=at, batch=batch)
    audits = _purge_audit_events(db, settings.retention_audit_events_days, at=at, batch=batch)
    scrubbed = _scrub_remediation_evidence(
        db, settings.retention_remediation_evidence_days, at=at, batch=batch
    )

    result = PurgeResult(
        findings=findings,
        finding_events=events,
        audit_events=audits,
        remediation_evidence_scrubbed=scrubbed,
    )
    if result.total() == 0:
        db.commit()
        return result

    audit.record(
        db,
        # No actor: nobody triggered this, a policy did.
        actor_id=None,
        action=AUDIT_RETENTION_PURGED,
        target_type=AUDIT_TARGET_RETENTION,
        target_id=None,
        detail={
            **{key: str(value) for key, value in asdict(result).items()},
            # The window that justified it, so the row still explains itself when
            # somebody reads it a year later and the settings have changed.
            "resolved_findings_days": str(settings.retention_resolved_findings_days),
            "finding_events_days": str(settings.retention_finding_events_days),
            "audit_events_days": str(settings.retention_audit_events_days),
            "remediation_evidence_days": str(settings.retention_remediation_evidence_days),
        },
    )
    db.commit()
    logger.info("retention_purged", **asdict(result))
    return result


def _cutoff(days: int, at: datetime) -> datetime | None:
    """The instant before which rows are eligible, or None when disabled."""
    return None if days <= 0 else at - timedelta(days=days)


def _purge_findings(db: Session, days: int, *, at: datetime, batch: int) -> int:
    """Auto-resolved findings that have been resolved longer than the window.

    Eligibility is checked in the query rather than in Python: a finding that
    changes state between a read and a delete would otherwise be removed on the
    strength of a state it no longer has.
    """
    cutoff = _cutoff(days, at)
    if cutoff is None:
        return 0

    eligible_where = (
        col(Finding.state) == FindingState.RESOLVED,
        col(Finding.resolution).in_(PURGEABLE_RESOLUTIONS),
        # `updated_at` moves when the finding is resolved, so it is the age of the
        # *decision*, not of the first sighting. A finding found two years ago and
        # resolved yesterday is a day old here.
        col(Finding.updated_at) < cutoff,
        # A suppressed finding is hidden, not gone: deleting it would bring it back
        # as new on the next scan (ADR 0008).
        col(Finding.suppressed_at).is_(None),
    )
    eligible = list(db.exec(select(col(Finding.id)).where(*eligible_where).limit(batch)))
    if not eligible:
        return 0

    # The predicates are repeated on the delete, with the id list serving only as
    # the batch limiter. Under READ COMMITTED an ingest can re-open one of these
    # findings between the select and the delete, and a delete by id alone would
    # remove a live secret finding — and, by cascade, its whole event trail.
    #
    # FindingEvent cascades on finding_id, so the trail goes with the finding it
    # describes rather than being orphaned.
    result = db.exec(
        delete(Finding)
        .where(col(Finding.id).in_(eligible), *eligible_where)
        # The datetime predicate cannot be evaluated against in-session objects
        # (SQLite hands back naive datetimes), so sync by re-select.
        .execution_options(synchronize_session="fetch")
    )
    return int(result.rowcount)


def _purge_finding_events(db: Session, days: int, *, at: datetime, batch: int) -> int:
    """Old trail entries for findings that are no longer open.

    An open finding keeps its whole history however old: it is what an analyst
    reads to understand the state in front of them.
    """
    cutoff = _cutoff(days, at)
    if cutoff is None:
        return 0

    still_open = select(col(Finding.id)).where(col(Finding.state) == FindingState.OPEN)
    eligible_where = (
        col(FindingEvent.created_at) < cutoff,
        col(FindingEvent.finding_id).not_in(still_open),
    )
    eligible = list(db.exec(select(col(FindingEvent.id)).where(*eligible_where).limit(batch)))
    if not eligible:
        return 0

    # Repeated on the delete for the same reason as above: a finding re-opened
    # between the two statements keeps the trail an analyst needs to read it.
    result = db.exec(
        delete(FindingEvent)
        .where(col(FindingEvent.id).in_(eligible), *eligible_where)
        .execution_options(synchronize_session="fetch")
    )
    return int(result.rowcount)


def _purge_audit_events(db: Session, days: int, *, at: datetime, batch: int) -> int:
    """Administrative audit rows past their window."""
    cutoff = _cutoff(days, at)
    if cutoff is None:
        return 0

    eligible = list(
        db.exec(select(col(AuditEvent.id)).where(col(AuditEvent.created_at) < cutoff).limit(batch))
    )
    if not eligible:
        return 0

    db.exec(delete(AuditEvent).where(col(AuditEvent.id).in_(eligible)))
    return len(eligible)


def _scrub_remediation_evidence(db: Session, days: int, *, at: datetime, batch: int) -> int:
    """Reduce evidence links to labels on long-resolved findings (#142).

    A scrub, not a delete: the remediation record — that something was done, by
    whom, of what kind, verified or not — is the decision trail and is never
    deleted here. What ages out is *where the proof lives*: ticket and console
    URLs name internal systems, and their value decays once the finding has
    stayed resolved past the window. The note goes with them; it is free text
    written about the same internals.

    The window is measured from the finding's resolution (its ``updated_at``,
    the same clock `_purge_findings` reads), and the eligibility predicates are
    **repeated on the write** — a finding that re-opened between the select and
    the update keeps its URLs, because its evidence is live again.
    """
    cutoff = _cutoff(days, at)
    if cutoff is None:
        return 0

    # The finding this action belongs to must *still* be resolved and still be
    # older than the window at write time. Repeated on the UPDATE rather than
    # re-read from the selected object: the object was loaded by this statement,
    # so a Python-side re-check would only ever see the value it was loaded
    # with, and a concurrent reopen committed in the ingest session would not
    # refresh it. Same reasoning, and the same shape, as `_purge_findings`.
    eligible = (
        select(col(RemediationAction.id))
        .join(Finding, col(RemediationAction.finding_id) == col(Finding.id))
        .where(col(RemediationAction.scrubbed_at).is_(None))
        .where(col(Finding.state) == FindingState.RESOLVED)
        .where(col(Finding.updated_at) < cutoff)
    )
    candidates = list(db.exec(eligible.limit(batch)))
    if not candidates:
        return 0

    scrubbed = 0
    for action_id in candidates:
        # One statement per action: the scrubbed content is derived from the
        # row's own JSON, so it cannot be expressed as a single bulk UPDATE —
        # but each write still carries the predicates, and a row that stopped
        # qualifying since the select simply updates nothing.
        action = db.get(RemediationAction, action_id)
        if action is None:
            continue
        result = db.exec(
            update(RemediationAction)
            .where(col(RemediationAction.id) == action_id)
            .where(col(RemediationAction.scrubbed_at).is_(None))
            .where(
                col(RemediationAction.finding_id).in_(
                    select(col(Finding.id))
                    .where(col(Finding.state) == FindingState.RESOLVED)
                    .where(col(Finding.updated_at) < cutoff)
                )
            )
            .values(
                evidence_links=[
                    {"label": link.get("label", "evidence"), "scrubbed": True}
                    for link in action.evidence_links
                ],
                note=None,
                scrubbed_at=at,
            )
            .execution_options(synchronize_session="fetch")
        )
        scrubbed += int(result.rowcount)
    return scrubbed


__all__ = ["PURGEABLE_RESOLUTIONS", "PurgeResult", "purge"]
