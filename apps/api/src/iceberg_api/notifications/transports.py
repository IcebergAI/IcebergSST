"""Getting an announcement out of the deployment (#60).

Two transports, one interface, so the delivery loop knows nothing about SMTP or
HTTP and tests can substitute a recorder. Both are synchronous and blocking: the
loop that calls them already runs in a worker thread, and a background job is the
right place to wait on somebody else's server.

The failure contract is the important part. A transport either returns, meaning
delivered, or raises :class:`DeliveryError`, meaning *try again later*. Anything
else escaping would be a bug in a transport, and the loop treats it the same way
— a failed attempt, never a lost row.

Egress is a security boundary here, not a detail (docs/security.md § Notification
egress). The receiver is an arbitrary operator-supplied URL, so:

* redirects are not followed — a 302 to somewhere else is a way to move where
  findings land without anyone changing the channel;
* the response body is never read into the error, because it is somebody else's
  data and ends up in our logs;
* the request is signed when the channel has a secret, so a receiver can tell a
  real announcement from anything else that can reach its URL.
"""

import hashlib
import hmac
import json
import smtplib
import ssl
from datetime import UTC, datetime
from email.message import EmailMessage
from typing import Any, Protocol

import httpx2
import structlog
from iceberg_core.config import ApiSettings
from iceberg_core.enums import NotificationChannelType
from iceberg_core.models import NotificationChannel
from iceberg_core.secrets import SecretStore, SecretStoreError

from iceberg_api.notifications.payload import email_body
from iceberg_api.notifications.schemas import SECRET_REF_KEY

logger = structlog.get_logger()

#: Carries the HMAC. Named for the product so it cannot collide with a header the
#: receiver already uses.
SIGNATURE_HEADER = "X-Iceberg-Signature"
#: Signed alongside the body, so a captured request cannot be replayed forever.
TIMESTAMP_HEADER = "X-Iceberg-Timestamp"
EVENT_HEADER = "X-Iceberg-Event"

#: Errors are stored on the delivery row and printed in logs; keep them small.
_MAX_ERROR = 400


class DeliveryError(Exception):
    """A delivery attempt failed. Retryable unless ``permanent`` is set."""

    def __init__(self, message: str, *, permanent: bool = False) -> None:
        super().__init__(message[:_MAX_ERROR])
        #: A misconfigured channel will fail identically forever — retrying a
        #: malformed URL 5 times only delays the operator finding out.
        self.permanent = permanent


class Transport(Protocol):
    """Sends one announcement. Returns on success, raises DeliveryError on failure."""

    def send(
        self,
        channel: NotificationChannel,
        payload: dict[str, Any],
        *,
        subject: str,
    ) -> None: ...


def _channel_secret(channel: NotificationChannel, store: SecretStore) -> str | None:
    """The channel's signing key, or None. Opened per attempt, never cached."""
    ref = channel.config.get(SECRET_REF_KEY)
    if not ref:
        return None
    try:
        return store.open(ref).get_secret_value()
    except SecretStoreError as exc:
        # A ref that will not open is a configuration problem — usually a master
        # key that was rotated without re-sealing — and no number of retries will
        # fix it.
        raise DeliveryError(f"channel secret could not be opened: {exc}", permanent=True) from exc


def sign(body: bytes, secret: str, timestamp: str) -> str:
    """``sha256=<hex>`` over ``timestamp.body``.

    The timestamp is inside the MAC rather than beside it, so it cannot be edited
    without invalidating the signature. Receivers should reject a stale one.
    """
    mac = hmac.new(secret.encode(), f"{timestamp}.".encode() + body, hashlib.sha256)
    return f"sha256={mac.hexdigest()}"


class WebhookTransport:
    """POSTs the payload as JSON to the channel's URL."""

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

    def send(
        self,
        channel: NotificationChannel,
        payload: dict[str, Any],
        *,
        subject: str,
    ) -> None:
        url = channel.config.get("url")
        if not url:
            raise DeliveryError("webhook channel has no url", permanent=True)

        body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        timestamp = str(int(datetime.now(UTC).timestamp()))
        headers = {
            "Content-Type": "application/json",
            EVENT_HEADER: str(payload.get("event", "")),
            TIMESTAMP_HEADER: timestamp,
            **{str(k): str(v) for k, v in channel.config.get("headers", {}).items()},
        }
        secret = _channel_secret(channel, self._store)
        if secret is not None:
            headers[SIGNATURE_HEADER] = sign(body, secret, timestamp)

        try:
            with httpx2.Client(
                timeout=self._settings.webhook_timeout_seconds,
                # See the module docstring: a redirect would silently relocate
                # where findings are sent.
                follow_redirects=False,
                transport=self._transport,
            ) as client:
                response = client.post(url, content=body, headers=headers)
        except httpx2.HTTPError as exc:
            raise DeliveryError(f"webhook request failed: {exc.__class__.__name__}") from exc

        if response.status_code >= 400:
            # 4xx is usually configuration and 5xx usually transient, but a 429 is
            # explicitly "try later" and a 404 can be a receiver mid-deploy. Only
            # the codes that time cannot change count as permanent.
            permanent = response.status_code in {400, 401, 403, 405, 410, 413, 414, 415}
            raise DeliveryError(
                f"webhook returned HTTP {response.status_code}", permanent=permanent
            )


class SmtpTransport:
    """Sends the payload as a plain-text email to the channel's recipients."""

    def __init__(self, settings: ApiSettings) -> None:
        self._settings = settings

    def send(
        self,
        channel: NotificationChannel,
        payload: dict[str, Any],
        *,
        subject: str,
    ) -> None:
        settings = self._settings
        if not settings.smtp_host:
            # Configured channel, unconfigured deployment. Permanent, because
            # retrying cannot supply a relay — and the error says exactly what to
            # set, which is the point of failing loudly instead of dropping mail.
            raise DeliveryError("no SMTP relay configured; set ICEBERG_SMTP_HOST", permanent=True)

        recipients = [str(address) for address in channel.config.get("recipients", [])]
        if not recipients:
            raise DeliveryError("email channel has no recipients", permanent=True)

        message = EmailMessage()
        message["Subject"] = subject
        message["From"] = settings.smtp_from
        message["To"] = ", ".join(recipients)
        message.set_content(email_body(payload))

        try:
            with self._connect() as server:
                server.send_message(message)
        except (OSError, smtplib.SMTPException) as exc:
            # Includes authentication failures, which are configuration — but a
            # relay can also reject credentials while it is degraded, so these
            # stay retryable and exhaust normally rather than giving up at once.
            raise DeliveryError(f"smtp send failed: {exc.__class__.__name__}: {exc}") from exc

    def _connect(self) -> smtplib.SMTP:
        settings = self._settings
        server = smtplib.SMTP(
            host=str(settings.smtp_host),
            port=settings.smtp_port,
            timeout=settings.smtp_timeout_seconds,
        )
        if settings.smtp_starttls:
            # A default context verifies the certificate and hostname. A relay
            # with a self-signed certificate should be fixed, not accommodated:
            # this connection carries where our secrets are.
            server.starttls(context=ssl.create_default_context())
        if settings.smtp_username and settings.smtp_password:
            server.login(settings.smtp_username, settings.smtp_password.get_secret_value())
        return server


def build_transports(
    settings: ApiSettings,
    store: SecretStore,
) -> dict[NotificationChannelType, Transport]:
    """The transport for each channel type. One place the loop looks things up."""
    return {
        NotificationChannelType.WEBHOOK: WebhookTransport(settings, store),
        NotificationChannelType.EMAIL: SmtpTransport(settings),
    }


__all__ = [
    "EVENT_HEADER",
    "SIGNATURE_HEADER",
    "TIMESTAMP_HEADER",
    "DeliveryError",
    "SmtpTransport",
    "Transport",
    "WebhookTransport",
    "build_transports",
    "sign",
]
