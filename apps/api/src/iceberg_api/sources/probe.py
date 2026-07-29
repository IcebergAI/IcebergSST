"""Connectivity probe for `POST /sources/{id}/test` (#32).

**A deliberate stopgap, and the narrowest one available.** ADR 0009 says the API
runs no connector code, and the right long-term home for this is either the
`Connector` interface (#45) or a task an engine leases (#35) — neither of which
exists yet, and the acceptance criterion for #32 is a connectivity check that
reports success or failure without leaking the credential.

So this is one generic HTTP request: no pagination, no content parsing, no
connector logic beyond a single per-type path to ask for. When the connector
framework lands, `probe_source` should become a call through it and this module
should disappear.

Care taken here, because it sends a real credential outbound:

* **No redirects followed.** A source answering `302` to somewhere else must not
  be handed the credential.
* **Nothing echoed.** The result carries a status code and a short sentence; never
  a response body, which can contain both the credential (reflected) and
  attacker-chosen text.
* **Bounded.** One request, ten seconds, response body discarded.

The URL is operator-supplied and may point anywhere, including inside the network
— which is not an accident: Confluence Server lives on private addresses. The
control is that only an admin can trigger it, and that it is logged
(docs/security.md § Outbound requests).
"""

import base64

import httpx2
import structlog
from iceberg_core.enums import SourceType
from iceberg_core.models import Source
from pydantic import SecretStr

from iceberg_api.sources.schemas import ConnectivityResult

#: The cheapest authenticated endpoint per source type: "who am I?".
PROBE_PATHS: dict[SourceType, str] = {
    SourceType.CONFLUENCE: "/rest/api/user/current",
}

TIMEOUT_SECONDS = 10.0

logger = structlog.get_logger()


class ProbeError(Exception):
    """The source cannot be probed at all (unsupported type, no base URL)."""


def authorization_header(credential: SecretStr) -> str:
    """Build the ``Authorization`` value for a stored credential.

    Confluence Cloud wants Basic ``email:api_token``; a bare token (Server PAT,
    or any other source type) is a Bearer credential. The shape of the stored
    string is what distinguishes them, which keeps one opaque credential field
    working for both.
    """
    secret = credential.get_secret_value()
    if ":" in secret:
        encoded = base64.b64encode(secret.encode()).decode()
        return f"Basic {encoded}"
    return f"Bearer {secret}"


async def probe_source(
    source: Source,
    credential: SecretStr,
    *,
    transport: httpx2.AsyncBaseTransport | None = None,
) -> ConnectivityResult:
    """Make one authenticated request and describe what happened."""
    path = PROBE_PATHS.get(source.type)
    if path is None:
        raise ProbeError(f"no connectivity check is defined for {source.type.value} sources yet")

    base_url = str(source.connection.get("base_url") or "").rstrip("/")
    if not base_url:
        raise ProbeError("source connection has no base_url")

    url = f"{base_url}{path}"
    headers = {"Authorization": authorization_header(credential), "Accept": "application/json"}

    try:
        async with httpx2.AsyncClient(
            timeout=TIMEOUT_SECONDS,
            follow_redirects=False,
            transport=transport,
        ) as client:
            response = await client.get(url, headers=headers)
    except httpx2.HTTPError as exc:
        # Type name only: an exception string can contain the URL with credentials
        # embedded, and for a DNS failure it adds nothing anyway.
        reason = type(exc).__name__
        logger.info("source_probe_failed", source_id=str(source.id), reason=reason)
        return ConnectivityResult(
            reachable=False,
            detail=f"could not connect to the source ({reason})",
        )

    return _interpret(response.status_code)


def _interpret(status_code: int) -> ConnectivityResult:
    """Turn a status code into an answer an operator can act on."""
    if 200 <= status_code < 300:
        return ConnectivityResult(
            reachable=True, status_code=status_code, detail="authenticated successfully"
        )
    if status_code in {401, 403}:
        return ConnectivityResult(
            reachable=False,
            status_code=status_code,
            detail="the source rejected the stored credential",
        )
    if status_code == 404:
        return ConnectivityResult(
            reachable=False,
            status_code=status_code,
            detail="reached the host, but its API was not where expected — check base_url",
        )
    if 300 <= status_code < 400:
        return ConnectivityResult(
            reachable=False,
            status_code=status_code,
            detail="the source redirected the request; check base_url (redirects are not followed)",
        )
    return ConnectivityResult(
        reachable=False,
        status_code=status_code,
        detail=f"the source answered with HTTP {status_code}",
    )
