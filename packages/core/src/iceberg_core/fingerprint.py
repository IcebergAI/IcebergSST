"""Finding identity: stable, peppered fingerprints (issue #26, ADR 0006).

    fingerprint = hash(connector_type, coarse_locator, rule_id, salted_secret_hash)

Two properties carry the whole design:

**Coarse locators.** The locator that participates in identity is
``(page id, attachment name)`` — never line or character offset. Offsets are
display metadata stored on the finding. If they were part of identity, editing a
paragraph *above* a secret would re-fingerprint it and orphan the analyst's triage
decision. :class:`CoarseLocator` exists so that mistake is not expressible.

**Injected pepper.** Nothing here reads the environment or a module global. The
API fetches the pepper from the secret store and delivers it to engines in the
task lease response (ADR 0009), so the pepper arrives as an argument at every call
site. Rotating it invalidates every finding identity — see ADR 0007 for the
re-keying procedure.

Rule ids are part of identity and therefore a stable contract: renaming or
splitting a rule needs a migration mapping old ids to new (ADR 0006).
"""

import hashlib
import hmac
from dataclasses import dataclass

_DIGEST = hashlib.sha256
_SEPARATOR = b"\x1f"  # ASCII unit separator: cannot occur in ids or locators


@dataclass(frozen=True, slots=True)
class CoarseLocator:
    """The stable part of a resource address — everything identity may use.

    Line/offset are deliberately absent. Keep them on the finding row for
    display, not here.
    """

    resource_id: str
    """Stable id of the containing resource, e.g. a Confluence page id."""

    attachment_name: str | None = None
    """Attachment filename when the match came from an attachment, else None."""

    def canonical(self) -> str:
        """Deterministic string form used as hash input."""
        return f"{self.resource_id}\x1e{self.attachment_name or ''}"


def hash_secret(secret: str, pepper: bytes) -> str:
    """Peppered hash of a secret value.

    HMAC rather than a plain salted digest so the pepper is a proper key: without
    it, a stolen database cannot be brute-forced offline against a wordlist
    (ADR 0004, ADR 0006).
    """
    if not pepper:
        raise ValueError("pepper must not be empty — refusing to produce an unpeppered hash")
    return hmac.new(pepper, secret.encode(), _DIGEST).hexdigest()


def fingerprint(
    *,
    connector_type: str,
    locator: CoarseLocator,
    rule_id: str,
    secret: str,
    pepper: bytes,
) -> str:
    """Compute a finding's stable identity.

    Deterministic across runs and processes for identical inputs. Because the
    locator is coarse, the same secret matched by the same rule several times
    within one resource collapses to a single fingerprint — one finding, not one
    per occurrence.
    """
    return fingerprint_from_hash(
        connector_type=connector_type,
        locator=locator,
        rule_id=rule_id,
        secret_hash=hash_secret(secret, pepper),
    )


def fingerprint_from_hash(
    *,
    connector_type: str,
    locator: CoarseLocator,
    rule_id: str,
    secret_hash: str,
) -> str:
    """Fingerprint from an already-hashed secret.

    The API reconciles findings it never saw in plaintext, so it needs this form;
    the engine uses :func:`fingerprint` while it still holds the match.
    """
    parts = (
        connector_type.encode(),
        locator.canonical().encode(),
        rule_id.encode(),
        secret_hash.encode(),
    )
    return _DIGEST(_SEPARATOR.join(parts)).hexdigest()
