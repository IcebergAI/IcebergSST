"""Exposure-cluster correlation identifiers (ADR 0011, #140).

A correlation id names the relation "these findings hold the same secret value"
and nothing else::

    correlation_id = HMAC(correlation_key, secret_hash)

It is derived from the stored :func:`~iceberg_core.fingerprint.secret_hash`, not
from the secret, and under a **dedicated key that only the API holds**. That
split is the whole design:

**Engines cannot mint one.** The pepper travels to engines in every lease, so
anything derived from it alone could be recomputed by whoever holds a plaintext
secret and a captured lease. The correlation key never appears in a lease or an
engine setting, so possession of a secret buys no ability to test cluster
membership — and a correlation id is never accepted anywhere as authentication
material or as a lookup that returns secret material.

**Rotation is a recompute, not a rescan.** Because the input is the stored
hash, swapping the correlation key and re-deriving every row is a batch job the
API can run on its own (`reindex-correlation`), unlike the pepper whose rotation
needs engines to see plaintext again. There is deliberately no previous-key
window here; the runbook has the procedure.

**Deployment-scoped.** Two deployments with different correlation keys can
never correlate values — which is what "the same credential correlates within
one organization only" means in a single-org system (ADR 0011).
"""

import hashlib
import hmac

#: Bumping this invalidates every stored correlation id. See ADR 0011.
CORRELATION_VERSION = 1

_CORRELATION_DOMAIN = f"iceberg.correlation.v{CORRELATION_VERSION}".encode()

#: Below this the key is not doing its job; refuse rather than pretend.
MIN_CORRELATION_KEY_BYTES = 32

#: The wire contract for ``secret_hash`` (`FindingPayload`), mirrored here so a
#: value that could never have been stored is refused rather than derived.
MIN_SECRET_HASH_LENGTH = 16
MAX_SECRET_HASH_LENGTH = 64


def correlation_id(secret_hash: str, *, key: bytes) -> str:
    """Return the correlation id for a stored secret hash (hex).

    The input is the peppered hash **exactly as stored** on the finding — the
    derivation is case- and byte-sensitive, because "same stored hash" is the
    relation being named. The same secret yields the same id wherever it
    appears; a different pepper (or a row not yet re-keyed during a pepper
    rotation) yields a different id, which is why the ingest re-key path
    recomputes this alongside ``secret_hash``.
    """
    if len(key) < MIN_CORRELATION_KEY_BYTES:
        raise ValueError(
            f"correlation key must be at least {MIN_CORRELATION_KEY_BYTES} bytes, "
            f"got {len(key)}; retrieve it with SecretStore.get_correlation_key()"
        )
    if not MIN_SECRET_HASH_LENGTH <= len(secret_hash) <= MAX_SECRET_HASH_LENGTH:
        raise ValueError(
            f"secret_hash must be {MIN_SECRET_HASH_LENGTH}-{MAX_SECRET_HASH_LENGTH} "
            "characters, as the results wire contract requires"
        )
    message = _CORRELATION_DOMAIN + b"\x00" + secret_hash.encode()
    return hmac.new(key, message, hashlib.sha256).hexdigest()
