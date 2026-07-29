"""Stable finding identity (ADR 0006).

A finding's fingerprint is what makes triage survive a re-scan::

    fingerprint = HMAC(pepper, connector_type ‖ coarse_locator ‖ rule_id ‖ secret_hash)

Three properties earn their keep:

**Coarse locator.** The locator that feeds the fingerprint is the stable part of
a resource — page id, attachment name — and deliberately *excludes* line and
offset. Offsets are display metadata stored on the finding. If they took part in
identity, editing a paragraph above a secret would produce a "new" finding and
orphan the analyst's decision on the old one. The corollary is intentional: the
same secret matched by the same rule several times in one resource collapses to
one finding.

**Peppered.** Both the secret hash and the fingerprint are HMACs keyed by a
pepper from the secret store, so neither can be brute-forced offline from a
database dump (ADR 0004/0007). The API is the only role that reads the pepper;
engines receive it per task in the lease response (ADR 0009).

**Unambiguous encoding.** Fields are length-prefixed before hashing, so
``("space:page", "file")`` and ``("space", "page:file")`` cannot collide — a
locator containing the separator is normal, not exotic.

Rotating the pepper or bumping :data:`FINGERPRINT_VERSION` changes every
fingerprint in existence; both need the re-key procedure in the rotation runbook,
not a casual edit.
"""

import hashlib
import hmac
import unicodedata
from dataclasses import dataclass

#: Bumping this invalidates every stored finding identity. See ADR 0006/0007.
FINGERPRINT_VERSION = 1

_SECRET_DOMAIN = f"iceberg.secret.v{FINGERPRINT_VERSION}".encode()
_FINGERPRINT_DOMAIN = f"iceberg.fingerprint.v{FINGERPRINT_VERSION}".encode()

#: Below this a pepper is not doing its job; refuse rather than pretend.
MIN_PEPPER_BYTES = 16


@dataclass(frozen=True, slots=True)
class CoarseLocator:
    """The stable identity of a scanned resource — no line, no offset.

    ``sub_resource`` names a part of the resource that is itself stable: an
    attachment filename, a comment id. Anything that changes when the content is
    edited belongs on the finding as display metadata, not here.
    """

    connector_type: str
    resource_id: str
    sub_resource: str | None = None

    def __post_init__(self) -> None:
        if not self.connector_type.strip():
            raise ValueError("connector_type is required")
        if not self.resource_id.strip():
            raise ValueError("resource_id is required")

    def canonical_parts(self) -> tuple[str, ...]:
        return (self.connector_type, self.resource_id, self.sub_resource or "")


def secret_hash(secret: str | bytes, *, pepper: bytes) -> str:
    """Return the peppered hash of a secret value (hex).

    This is the only representation of the secret that may be stored (ADR 0004).
    It is keyed, not merely salted-and-hashed: an attacker holding the database
    cannot test candidate secrets without also holding the pepper.
    """
    _require_pepper(pepper)
    material = secret.encode() if isinstance(secret, str) else secret
    if not material:
        raise ValueError("nothing to hash: empty secret")
    return hmac.new(pepper, _SECRET_DOMAIN + b"\x00" + material, hashlib.sha256).hexdigest()


def fingerprint(
    *,
    locator: CoarseLocator,
    rule_id: str,
    secret_hash: str,
    pepper: bytes,
) -> str:
    """Return the stable fingerprint for a finding (hex).

    ``rule_id`` is part of identity and therefore a stable contract: renaming or
    splitting a rule needs a migration mapping old ids to new (ADR 0006), so rule
    packs must not rename ids casually.
    """
    _require_pepper(pepper)
    if not rule_id.strip():
        raise ValueError("rule_id is required")
    if not secret_hash.strip():
        raise ValueError("secret_hash is required")

    message = _canonicalize((*locator.canonical_parts(), rule_id, secret_hash))
    return hmac.new(pepper, _FINGERPRINT_DOMAIN + b"\x00" + message, hashlib.sha256).hexdigest()


def fingerprint_for_secret(
    *,
    locator: CoarseLocator,
    rule_id: str,
    secret: str | bytes,
    pepper: bytes,
) -> str:
    """Convenience: hash the secret and fingerprint it in one step."""
    return fingerprint(
        locator=locator,
        rule_id=rule_id,
        secret_hash=secret_hash(secret, pepper=pepper),
        pepper=pepper,
    )


def _canonicalize(parts: tuple[str, ...]) -> bytes:
    """Length-prefix each field so no separator can be forged across fields.

    Unicode is normalised to NFC first: the same page title can arrive composed
    or decomposed depending on the client that wrote it, and that must not split
    one finding into two.
    """
    encoded = [unicodedata.normalize("NFC", part).encode() for part in parts]
    return b"".join(f"{len(item)}:".encode() + item + b"|" for item in encoded)


def _require_pepper(pepper: bytes) -> None:
    if len(pepper) < MIN_PEPPER_BYTES:
        raise ValueError(
            f"pepper must be at least {MIN_PEPPER_BYTES} bytes, got {len(pepper)}; "
            "retrieve it with SecretStore.get_pepper()"
        )
