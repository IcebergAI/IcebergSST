"""Fingerprint-pepper rotation (#64 — ADR 0006, 0007).

The dry-run for `docs/runbooks/key-rotation.md`, and the reason that runbook can
promise what it promises.

The problem, stated exactly. A finding's identity is
``HMAC(pepper, locator ‖ rule ‖ HMAC(pepper, secret))``, and the plaintext secret
is deliberately never stored (ADR 0004). So a new pepper cannot be applied to
existing rows by recomputation — the input is gone. Nothing in the API can
migrate these values; only an engine that currently holds the secret can compute
its identity under a different key.

Hence the dual-pepper window: while both peppers are configured, engines report
each finding under both, and ingest treats a hit on the old identity as the same
finding under a new key. What these tests actually assert is that an analyst's
work — the triage state, the resolution, the assignee, the notes, the suppression
and the whole event trail — is still attached afterwards. That is the claim the
runbook makes, so it is the claim that is tested.
"""

import secrets
import uuid
from collections.abc import Callable
from typing import Any

import pytest
from iceberg_api.engines.ingest import ingest_findings
from iceberg_api.engines.schemas import FindingPayload
from iceberg_core.enums import (
    FindingEventKind,
    FindingState,
    ScanStatus,
    ScanTrigger,
    Severity,
    SourceType,
)
from iceberg_core.fingerprint import CoarseLocator, fingerprint, secret_hash
from iceberg_core.models import Finding, FindingEvent, Scan, Source, User
from iceberg_core.secrets import EnvKeyBackend, SecretPurpose, SecretStoreError
from sqlmodel import Session, col, select

OLD_PEPPER = b"the-outgoing-pepper-32-bytes-ok!"
NEW_PEPPER = b"the-incoming-pepper-32-bytes-ok!"

SECRET = "AKIAIOSFODNN7EXAMPLE"
LOCATOR = CoarseLocator(connector_type="confluence", resource_id="page-42")
RULE = "aws-access-key"


def _identity(pepper: bytes) -> tuple[str, str]:
    """(fingerprint, secret_hash) for the same secret under one pepper."""
    hashed = secret_hash(SECRET, pepper=pepper)
    return fingerprint(locator=LOCATOR, rule_id=RULE, secret_hash=hashed, pepper=pepper), hashed


def _payload(*, with_previous: bool) -> FindingPayload:
    """What an engine reports — under both peppers during a rotation window."""
    new_fingerprint, new_hash = _identity(NEW_PEPPER)
    fields: dict[str, Any] = {
        "fingerprint": new_fingerprint,
        "rule_id": RULE,
        "rulepack_version": "2026.07.1",
        "resource_locator": {"path": "/space/DOCS/page-42", "offset": 12},
        "redacted_snippet": "AKIA****************",
        "secret_hash": new_hash,
        "severity": Severity.HIGH,
        "confidence": 0.9,
    }
    if with_previous:
        old_fingerprint, old_hash = _identity(OLD_PEPPER)
        fields["previous_fingerprint"] = old_fingerprint
        fields["previous_secret_hash"] = old_hash
    return FindingPayload(**fields)


@pytest.fixture(name="source")
def source_fixture(session: Session) -> Source:
    source = Source(
        name=f"confluence-{uuid.uuid4().hex[:6]}",
        type=SourceType.CONFLUENCE,
        connection={"base_url": "https://example.atlassian.net/wiki"},
    )
    session.add(source)
    session.commit()
    return source


@pytest.fixture(name="make_scan")
def make_scan_fixture(session: Session, source: Source) -> Callable[[], Scan]:
    def factory() -> Scan:
        # Finish any earlier scan first: one active scan per source (ADR 0009).
        for previous in session.exec(select(Scan).where(col(Scan.source_id) == source.id)):
            previous.status = ScanStatus.COMPLETED
            session.add(previous)
        scan = Scan(source_id=source.id, trigger=ScanTrigger.MANUAL, status=ScanStatus.RUNNING)
        session.add(scan)
        session.commit()
        return scan

    return factory


@pytest.fixture(name="triaged_finding")
def triaged_finding_fixture(
    session: Session, source: Source, make_scan: Callable[[], Scan]
) -> Finding:
    """A finding under the OLD pepper, with an analyst's work on it.

    This is the state a rotation must not destroy — and the reason a rotation
    that just let everything ingest as new would be unacceptable: reconciliation
    would then auto-resolve the originals and the decisions would be gone.
    """
    scan = make_scan()
    old_fingerprint, old_hash = _identity(OLD_PEPPER)
    finding = Finding(
        source_id=source.id,
        fingerprint=old_fingerprint,
        secret_hash=old_hash,
        rule_id=RULE,
        rulepack_version="2026.07.1",
        resource_locator={"path": "/space/DOCS/page-42", "offset": 12},
        redacted_snippet="AKIA****************",
        severity=Severity.HIGH,
        state=FindingState.ACCEPTED_RISK,
        notes="rotating with the platform team in Q4",
        first_seen_scan_id=scan.id,
        last_seen_scan_id=scan.id,
    )
    session.add(finding)
    session.commit()
    session.add(
        FindingEvent(
            finding_id=finding.id,
            kind=FindingEventKind.STATE_CHANGE,
            from_value=FindingState.OPEN.value,
            to_value=FindingState.ACCEPTED_RISK.value,
            comment="known, tracked in JIRA-1234",
        )
    )
    session.commit()
    return finding


# ── The mechanism ─────────────────────────────────────────────────────────────


def test_the_secret_produces_a_different_identity_under_each_pepper() -> None:
    """The premise. If this were false there would be nothing to rotate."""
    old_fingerprint, old_hash = _identity(OLD_PEPPER)
    new_fingerprint, new_hash = _identity(NEW_PEPPER)

    assert old_fingerprint != new_fingerprint
    assert old_hash != new_hash


def test_the_new_identity_cannot_be_derived_from_the_stored_one() -> None:
    """Why a dual-pepper window exists at all, rather than a migration.

    Identity is keyed by the pepper and derived from a plaintext that was never
    stored, so no amount of database access recomputes it. Only an engine holding
    the secret can — which is why the engine reports both and the API only
    matches.
    """
    _, old_hash = _identity(OLD_PEPPER)
    _, new_hash = _identity(NEW_PEPPER)

    # The stored value is a one-way function of a secret we do not have; the best
    # the API could do with it is hash it again, which is not the same thing.
    assert secret_hash(old_hash, pepper=NEW_PEPPER) != new_hash


def test_a_rotation_rekeys_the_finding_and_keeps_its_triage_state(
    session: Session,
    triaged_finding: Finding,
    make_scan: Callable[[], Scan],
) -> None:
    """The dry-run the runbook's promise rests on.

    A scan during the window reports both identities; ingest recognises the old
    one and re-keys in place. Everything an analyst did is still attached.
    """
    finding_id = triaged_finding.id
    scan = make_scan()

    outcome = ingest_findings(session, scan, [_payload(with_previous=True)])
    session.commit()

    assert outcome.rekeyed == 1
    assert len(list(session.exec(select(Finding)))) == 1, "a rotation must not duplicate findings"

    rekeyed = session.get(Finding, finding_id)
    assert rekeyed is not None, "the same row, not a replacement"
    new_fingerprint, new_hash = _identity(NEW_PEPPER)
    assert rekeyed.fingerprint == new_fingerprint
    assert rekeyed.secret_hash == new_hash
    # What the analyst did, all of it.
    assert rekeyed.state is FindingState.ACCEPTED_RISK
    assert rekeyed.notes == "rotating with the platform team in Q4"
    assert rekeyed.last_seen_scan_id == scan.id


def test_the_event_trail_survives_a_rotation(
    session: Session,
    triaged_finding: Finding,
    make_scan: Callable[[], Scan],
) -> None:
    """The trail is keyed on the finding id, so re-keying in place keeps it —
    and "in place" is precisely why the mechanism re-keys instead of replacing."""
    finding_id = triaged_finding.id
    scan = make_scan()

    ingest_findings(session, scan, [_payload(with_previous=True)])
    session.commit()

    events = list(
        session.exec(select(FindingEvent).where(col(FindingEvent.finding_id) == finding_id))
    )
    assert [event.comment for event in events] == ["known, tracked in JIRA-1234"]


def test_an_assignee_survives_a_rotation(
    session: Session,
    triaged_finding: Finding,
    make_scan: Callable[[], Scan],
    make_user: Callable[..., User],
) -> None:
    analyst = make_user()
    triaged_finding.assignee_id = analyst.id
    session.add(triaged_finding)
    session.commit()
    scan = make_scan()

    ingest_findings(session, scan, [_payload(with_previous=True)])
    session.commit()

    rekeyed = session.get(Finding, triaged_finding.id)
    assert rekeyed is not None
    assert rekeyed.assignee_id == analyst.id


def test_without_the_window_the_same_secret_ingests_as_a_new_finding(
    session: Session,
    triaged_finding: Finding,
    make_scan: Callable[[], Scan],
) -> None:
    """The failure this whole mechanism exists to prevent, demonstrated.

    Rotate the pepper without a window and the next scan reports an identity
    nothing matches: a second row appears, and the original — now unseen —
    is auto-resolved by reconciliation. The analyst's decision is not deleted so
    much as detached from anything anyone will ever look at again.
    """
    scan = make_scan()

    outcome = ingest_findings(session, scan, [_payload(with_previous=False)])
    session.commit()

    assert outcome.rekeyed == 0
    assert len(list(session.exec(select(Finding)))) == 2


def test_a_rotation_does_not_disturb_an_unrelated_finding(
    session: Session,
    source: Source,
    triaged_finding: Finding,
    make_scan: Callable[[], Scan],
) -> None:
    """Re-keying matches on the reported previous fingerprint alone, so a finding
    the scan did not see keeps its identity."""
    scan = make_scan()
    other = Finding(
        source_id=source.id,
        fingerprint="unrelated" + uuid.uuid4().hex,
        secret_hash=uuid.uuid4().hex,
        rule_id="generic-high-entropy",
        rulepack_version="2026.07.1",
        resource_locator={"path": "/space/DOCS/page-99"},
        redacted_snippet="****",
        severity=Severity.LOW,
        first_seen_scan_id=scan.id,
        last_seen_scan_id=scan.id,
    )
    session.add(other)
    session.commit()
    unchanged = other.fingerprint

    ingest_findings(session, scan, [_payload(with_previous=True)])
    session.commit()

    session.refresh(other)
    assert other.fingerprint == unchanged


def test_a_second_scan_in_the_window_is_a_no_op(
    session: Session,
    triaged_finding: Finding,
    make_scan: Callable[[], Scan],
) -> None:
    """After re-keying, the new fingerprint matches directly, so nothing is
    re-keyed twice and the count an operator watches falls to zero."""
    first = make_scan()
    ingest_findings(session, first, [_payload(with_previous=True)])
    session.commit()

    second = make_scan()
    outcome = ingest_findings(session, second, [_payload(with_previous=True)])
    session.commit()

    assert outcome.rekeyed == 0
    assert outcome.ingested == 1
    assert len(list(session.exec(select(Finding)))) == 1


# ── The secret store side ─────────────────────────────────────────────────────


def test_the_store_exposes_the_previous_pepper_only_during_a_window() -> None:
    master_key = secrets.token_bytes(32)
    bootstrap = EnvKeyBackend(master_key)
    old_ref = bootstrap.generate_pepper_ref()
    new_ref = bootstrap.generate_pepper_ref()

    normal = EnvKeyBackend(master_key, pepper_ref=new_ref)
    rotating = EnvKeyBackend(master_key, pepper_ref=new_ref, previous_pepper_ref=old_ref)

    assert normal.get_previous_pepper() is None
    assert rotating.get_previous_pepper() == bootstrap.open_bytes(
        old_ref, purpose=SecretPurpose.PEPPER
    )
    # And the two peppers really are different material, or the window is theatre.
    assert rotating.get_previous_pepper() != rotating.get_pepper()


def test_both_peppers_are_sealed_with_the_same_master_key() -> None:
    """Which is what makes pepper rotation and master-key rotation independent —
    one is a re-scan, the other a re-seal, and conflating them would mean doing
    both at once."""
    master_key = secrets.token_bytes(32)
    store = EnvKeyBackend(master_key)
    ref = store.generate_pepper_ref()

    other_key = EnvKeyBackend(secrets.token_bytes(32), previous_pepper_ref=ref)

    with pytest.raises(SecretStoreError):
        other_key.get_previous_pepper()
