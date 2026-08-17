"""Sending a hand-over, and reading the reply (#141).

Deliberately the same wire format as a notification webhook — the same signature
header, the same timestamp-inside-the-MAC, the same refusal to follow redirects —
because an operator who has already wired up one receiver should not have to
learn a second scheme, and because the security properties were argued once in
``iceberg_api.notifications.transports`` and are worth having twice.

The one difference is the direction of information. A notification is
fire-and-forget; a hand-over creates an object in somebody else's system, so the
**reply matters**: it is read for the receiver's own id and a link, which is what
turns a row in this database into something an analyst can click through to.

That reply is somebody else's data. It is bounded, coerced to strings, and never
interpreted beyond being displayed.
"""

import json
from datetime import UTC, datetime
from typing import Any

import httpx2
import structlog
from iceberg_core.config import ApiSettings
from iceberg_core.models import HandoffTarget
from iceberg_core.secrets import SecretStore, SecretStoreError

from iceberg_api.notifications.schemas import SECRET_REF_KEY
from iceberg_api.notifications.transports import (
    EVENT_HEADER,
    SIGNATURE_HEADER,
    TIMESTAMP_HEADER,
    DeliveryError,
    sign,
)

logger = structlog.get_logger()

#: How much of a reply body is read. A receiver returning a hundred megabytes of
#: JSON is not describing one work item, and reading it would be the easiest
#: possible way to exhaust the maintenance loop.
MAX_REPLY_BYTES = 64 * 1024


class WebhookSender:
    """POSTs the hand-over as JSON and reads the work item out of the reply."""

    def __init__(
        self,
        settings: ApiSettings,
        store: SecretStore,
        *,
        transport: httpx2.BaseTransport | None = None,
    ) -> None:
        self._settings = settings
        self._store = store
        #: Injected in tests so the suite never opens a socket.
        self._transport = transport

    def send(self, target: HandoffTarget, payload: dict[str, Any]) -> dict[str, str]:
        url = target.config.get("url")
        if not url:
            raise DeliveryError("handoff target has no url", permanent=True)

        body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        timestamp = str(int(datetime.now(UTC).timestamp()))
        headers = {
            "Content-Type": "application/json",
            EVENT_HEADER: str(payload.get("event", "")),
            TIMESTAMP_HEADER: timestamp,
            # Sent as a header as well as in the body, so a receiver can dedupe
            # before it parses anything — which is the point at which deduping is
            # cheapest and most likely to be implemented.
            "Idempotency-Key": str(payload.get("idempotency_key", "")),
        }
        secret = _target_secret(target, self._store)
        if secret is not None:
            headers[SIGNATURE_HEADER] = sign(body, secret, timestamp)

        try:
            # Streamed, so the status is decided before any of the body is read
            # and the body itself is read against the cap. A failing or
            # redirecting receiver has its (small) body left unread and the
            # connection closed, the same shape `iceberg_connectors.http` reads
            # every attacker-influenced body with.
            with (
                httpx2.Client(
                    timeout=self._settings.webhook_timeout_seconds,
                    # A redirect would silently relocate where findings are sent,
                    # and a hand-over carries more context than an announcement.
                    follow_redirects=False,
                    transport=self._transport,
                ) as client,
                client.stream("POST", url, content=body, headers=headers) as response,
            ):
                _raise_for_status(response)
                reply = _read_capped(response)
        except httpx2.HTTPError as exc:
            raise DeliveryError(f"handoff request failed: {exc.__class__.__name__}") from exc

        return _work_item(reply)


def _raise_for_status(response: httpx2.Response) -> None:
    """Whether the receiver accepted the hand-over, decided before reading it."""
    if 300 <= response.status_code < 400:
        # Redirects are not followed, so a 3xx means the request never reached
        # whatever would have created the work item. Treating it as success —
        # which "anything below 400" quietly did — would record a DELIVERED
        # handoff for a ticket that does not exist, and that is the one thing a
        # delivered row must never mean.
        #
        # Permanent, because the fix is to point the target at the URL the
        # receiver actually serves. Retrying a canonical-host or trailing-slash
        # redirect just produces the same redirect forever.
        raise DeliveryError(
            f"handoff was redirected (HTTP {response.status_code}); "
            f"point the target at the final URL",
            permanent=True,
        )
    if response.status_code >= 400:
        # Only the codes time cannot change are permanent. A 409 is deliberately
        # *not* one of them — a receiver that already has this idempotency key
        # may say so that way, and the next attempt should get its work item id.
        permanent = response.status_code in {400, 401, 403, 405, 410, 413, 414, 415}
        raise DeliveryError(f"handoff returned HTTP {response.status_code}", permanent=permanent)


def _read_capped(response: httpx2.Response) -> bytes | None:
    """The reply body, or None when the receiver sent more than we will read.

    Read against the cap rather than measured after the fact: buffering the whole
    response and *then* checking its length puts the hundred megabytes in the
    maintenance loop's memory first, which is the reverse of what the cap is for.
    One byte over is enough to know, and the rest is never pulled off the socket.
    """
    chunks: list[bytes] = []
    total = 0
    for chunk in response.iter_bytes():
        total += len(chunk)
        if total > MAX_REPLY_BYTES:
            logger.warning("handoff_reply_too_large", limit=MAX_REPLY_BYTES)
            return None
        chunks.append(chunk)
    return b"".join(chunks)


def _work_item(raw: bytes | None) -> dict[str, str]:
    """The receiver's id and link, if it gave any.

    A reply that is not JSON, is JSON of the wrong shape, or was too large to
    read is **not** a failure: the work item was created — that is what the 2xx
    said — and failing the hand-over over a missing field would retry a create
    that already succeeded. The row simply carries no external id, which reads as
    "handed over, receiver did not say where it went".
    """
    if raw is None:
        return {}
    try:
        parsed = json.loads(raw)
    except ValueError:
        return {}
    if not isinstance(parsed, dict):
        return {}
    return {
        key: str(parsed[key])
        for key in ("external_id", "external_url")
        if isinstance(parsed.get(key), str | int)
    }


def _target_secret(target: HandoffTarget, store: SecretStore) -> str | None:
    """The target's signing key, or None. Opened per attempt, never cached."""
    ref = target.config.get(SECRET_REF_KEY)
    if not ref:
        return None
    try:
        return store.open(str(ref)).get_secret_value()
    except SecretStoreError as exc:
        # Configuration, not transport: retrying cannot repair an unreadable ref,
        # and the error names what an operator has to fix.
        raise DeliveryError(f"handoff signing secret is unreadable: {exc}", permanent=True) from exc
