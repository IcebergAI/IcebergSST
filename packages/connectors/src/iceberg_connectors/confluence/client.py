"""Talking to Confluence Cloud's REST v2 API (#47, #49).

Everything the connector needs from the network, and nothing about what the
content means — that is :mod:`iceberg_connectors.confluence.connector`'s job. Kept
apart because the two fail for entirely different reasons: this module deals with
cursors, credentials, and a server asking to be left alone, while the other deals
with markup and attachments.

**Authentication is flavor-shaped, not connector-shaped.** Confluence Cloud
authenticates an API token as HTTP Basic, with the account's email as the username
— the token alone is not a bearer credential. Server/Data Center issues PATs that
*are* bearer credentials. Both arrive here as one opaque string from the task lease
(ADR 0009), and the ``email`` in the source's connection blob is what picks between
them. That keeps #47's "no Cloud-specific assumptions leak into the protocol"
honest: the protocol passes a credential, and the flavor decision lives here.

**The credential is never logged.** Not in a request log, not in an error message,
not in a repr — :class:`Credential` exists to make that structural rather than a
rule people remember. Every log line here names a path and a status and nothing
else.

**Pagination is cursor-based and opaque.** v2 returns a ``_links.next`` and the
only correct thing to do with it is follow it. Constructing the next URL from an
offset would silently skip or repeat pages when content changes mid-scan, which on
a fifty-thousand-page space means missing secrets without any sign that it
happened.

**429 is a normal answer, not an error.** Confluence rate-limits aggressively, and
a scan is precisely the workload that trips it. The server says how long to wait
in ``Retry-After``; honouring that is both faster and politer than backing off
blindly, and ignoring it gets an integration throttled harder.
"""

import base64
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

import httpx2
import structlog

from iceberg_connectors.protocol import ConnectorError, CredentialError

logger = structlog.get_logger()

#: Statuses worth trying again. 429 is handled separately — it carries its own
#: instructions, so it is a wait rather than a retry with a guessed delay.
RETRYABLE_STATUSES = frozenset({500, 502, 503, 504})

#: v2 lives under `/wiki/api/v2` on Cloud. Server/DC mounts elsewhere, which is why
#: this is a default rather than a constant spliced into every path.
DEFAULT_API_PREFIX = "/wiki/api/v2"

#: Cloud's own ceiling for most v2 collections. Asking for more is silently capped,
#: so requesting exactly this is one round trip per page and no surprises.
DEFAULT_PAGE_SIZE = 250

#: A page of results is bounded, but the number of pages is not. Without a cap, a
#: server that answered every `next` with another `next` would spin a task forever
#: — and a task that never ends is worse than one that reports what it found.
MAX_PAGES = 10_000

#: Cloud redirects an attachment download once, to a signed media URL. A handful of
#: hops covers a proxy in front of that; a loop is a broken site, not a file.
MAX_REDIRECTS = 5


class RateLimited(ConnectorError):
    """The server asked to be left alone for longer than this scan can wait."""


class DownloadTooLarge(ConnectorError):
    """A download exceeded its byte cap and was cut off.

    Its own type because the connector's response is specific: count the
    attachment as skipped and keep going. Extraction would have rejected the file
    at its input cap anyway, so nothing was lost by stopping early.
    """

    def __init__(self, seen: int) -> None:
        super().__init__(f"download exceeded the size cap after {seen} bytes")


@dataclass(frozen=True, slots=True)
class Credential:
    """A Confluence credential that will not appear in a log line.

    ``repr`` is overridden rather than trusted: structlog renders arguments with
    ``repr``, exception tracebacks render locals with ``repr``, and a token printed
    once into a log aggregator is a token that has to be rotated. Making the safe
    behaviour the *only* behaviour is cheaper than auditing every call site.
    """

    token: str
    #: Set for Cloud API tokens, which authenticate as Basic `email:token`.
    #: Absent for Server/DC PATs, which are bearer credentials.
    email: str | None = None

    def __repr__(self) -> str:  # pragma: no cover — trivial, but the point of the class
        return "Credential(...)"

    __str__ = __repr__

    def header(self) -> str:
        if self.email:
            pair = base64.b64encode(f"{self.email}:{self.token}".encode()).decode()
            return f"Basic {pair}"
        return f"Bearer {self.token}"


@dataclass(frozen=True, slots=True)
class RateLimitPolicy:
    """How a scan responds to being throttled.

    A scan is a background job, so waiting is nearly always better than failing —
    but not without limit. ``max_wait_seconds`` is what keeps a task from sitting
    on a lease it stopped renewing progress against; past it the task fails and
    says why, and an operator can lower concurrency.
    """

    attempts: int = 5
    base_delay_seconds: float = 1.0
    max_delay_seconds: float = 60.0
    #: The longest single `Retry-After` this scan will honour. Beyond it the answer
    #: is not "wait" but "come back with fewer engines".
    max_wait_seconds: float = 300.0

    def delay_for(self, attempt: int) -> float:
        return float(min(self.base_delay_seconds * (2**attempt), self.max_delay_seconds))


@dataclass(slots=True)
class ConfluenceClient:
    """A minimal, paginating, rate-limit-aware Confluence REST v2 client.

    ``transport`` and ``sleep`` are injectable for the same reason they are on the
    engine's API client: tests drive the real request-building and backoff logic
    against a scripted server without waiting for any of it (#71).
    """

    base_url: str
    credential: Credential | None = None
    api_prefix: str = DEFAULT_API_PREFIX
    page_size: int = DEFAULT_PAGE_SIZE
    rate_limit: RateLimitPolicy = field(default_factory=RateLimitPolicy)
    transport: httpx2.BaseTransport | None = None
    sleep: Callable[[float], None] = time.sleep
    timeout_seconds: float = 60.0

    def __post_init__(self) -> None:
        self.base_url = self.base_url.rstrip("/")

    # ─── Collections ──────────────────────────────────────────────────────────

    def paginate(self, path: str, **params: Any) -> Iterator[dict[str, Any]]:
        """Yield every result across every page of a v2 collection.

        A generator, so a space with fifty thousand pages does not have to exist in
        memory before the first one is scanned — and so a cancelled task stops
        requesting rather than finishing and discarding (ADR 0009 §4).

        The ``next`` link is followed verbatim. It encodes the server's own idea of
        where the cursor is, and rebuilding it from an offset would skip or repeat
        results whenever content changes mid-scan.
        """
        url = self.url(path)
        query: dict[str, Any] | None = {"limit": self.page_size, **params}

        for _page in range(MAX_PAGES):
            payload = self.get_json(url, params=query)
            yield from (item for item in payload.get("results", []) if isinstance(item, dict))

            following = _next_link(payload)
            if not following:
                return
            # The cursor link already carries limit and every filter; passing the
            # original params again would override the cursor on some deployments.
            url, query = self._resolve(following), None

        raise ConnectorError(f"pagination did not terminate after {MAX_PAGES} pages of {path}")

    # ─── Single resources ─────────────────────────────────────────────────────

    def get_json(self, url: str, *, params: dict[str, Any] | None = None) -> dict[str, Any]:
        resolved = self._resolve(url)
        self._require_same_origin(resolved, _path_of(url))
        response = self._request("GET", resolved, params=params)
        try:
            body = response.json()
        except ValueError as exc:
            raise ConnectorError(
                f"confluence returned a non-JSON body for {_path_of(url)}"
            ) from exc
        if not isinstance(body, dict):
            raise ConnectorError(
                f"confluence returned an unexpected body shape for {_path_of(url)}"
            )
        return body

    def get_bytes(self, url: str, *, max_bytes: int) -> bytes:
        """Download an attachment, refusing to buffer more than ``max_bytes``.

        Streamed and cut off rather than read whole: a `Content-Length` is
        attacker-influenced, and a client that trusted it would happily buffer a
        gigabyte from a source that claimed a kilobyte. The caller treats a
        short-circuited download as a skip, not a failure — extraction would have
        rejected the file at its size cap anyway.

        **Redirects are followed, but the credential is not.** Cloud answers an
        attachment download with a redirect to a signed media URL, so refusing to
        follow would mean no attachments at all. But the redirect target is named by
        the response, and a source that could point one at a host it controls would
        be handed this engine's Confluence token — the same reasoning that makes
        ``POST /sources/{id}/test`` refuse redirects outright (docs/security.md).
        The signed URL carries its own authorisation and needs none from us.
        """
        target = self._resolve(url)
        # The first hop carries the credential, so it must be on the site. The
        # download itself may then redirect to an off-origin signed media URL, which
        # the loop below follows with auth stripped.
        self._require_same_origin(target, _path_of(url))
        headers = self._headers(target)

        for _hop in range(MAX_REDIRECTS + 1):
            with (
                self._client() as client,
                client.stream("GET", target, headers=headers) as response,
            ):
                if response.is_redirect and response.headers.get("location"):
                    # Resolved against the current target so a relative Location
                    # works, then stripped of everything that authenticates us.
                    target = str(response.next_request.url) if response.next_request else ""
                    if not target:
                        raise ConnectorError(f"redirect without a target for {_path_of(url)}")
                    headers = {"Accept": "*/*"}
                    continue

                self._raise_for_status(response, _path_of(url))
                chunks: list[bytes] = []
                total = 0
                for chunk in response.iter_bytes():
                    total += len(chunk)
                    if total > max_bytes:
                        # One byte over is enough to know; reading the rest only
                        # costs bandwidth the scan does not need to spend.
                        raise DownloadTooLarge(total)
                    chunks.append(chunk)
                return b"".join(chunks)

        raise ConnectorError(f"more than {MAX_REDIRECTS} redirects for {_path_of(url)}")

    # ─── Transport ────────────────────────────────────────────────────────────

    def _request(self, method: str, url: str, *, params: dict[str, Any] | None) -> httpx2.Response:
        path = _path_of(url)
        waited = 0.0
        last_error: Exception | None = None

        # 429 and 5xx/transport failures have separate budgets. A throttle is a
        # normal answer bounded by how long the scan will wait (`max_wait_seconds`);
        # it must not spend a retry attempt, or a run of throttles would exhaust the
        # attempts and fail with the wrong error long before the wait budget is up.
        # `throttles` grows the fallback backoff without touching the retry budget.
        attempt = 0
        throttles = 0
        while attempt < self.rate_limit.attempts:
            with self._client() as client:
                try:
                    response = client.request(
                        method, url, params=params, headers=self._headers(url)
                    )
                except httpx2.HTTPError as exc:
                    last_error = ConnectorError(f"{type(exc).__name__} reaching {path}")
                    self.sleep(self.rate_limit.delay_for(attempt))
                    attempt += 1
                    continue

            if response.status_code == 429:
                pause = _retry_after(response, fallback=self.rate_limit.delay_for(throttles))
                throttles += 1
                waited += pause
                if waited > self.rate_limit.max_wait_seconds:
                    raise RateLimited(
                        f"confluence rate-limited {path} for more than "
                        f"{self.rate_limit.max_wait_seconds:.0f}s; reduce engine concurrency"
                    )
                logger.info("confluence_rate_limited", path=path, wait_seconds=pause)
                self.sleep(pause)
                continue

            if response.status_code in RETRYABLE_STATUSES:
                last_error = ConnectorError(
                    f"confluence returned {response.status_code} for {path}"
                )
                self.sleep(self.rate_limit.delay_for(attempt))
                attempt += 1
                continue

            self._raise_for_status(response, path)
            return response

        raise ConnectorError(
            f"{method} {path} failed after {self.rate_limit.attempts} attempts"
        ) from last_error

    def _raise_for_status(self, response: httpx2.Response, path: str) -> None:
        if response.status_code in (401, 403):
            # Split out because the operator response is specific and different:
            # rotate the token, or grant the account access to the space.
            raise CredentialError(
                f"confluence rejected the credential for {path} ({response.status_code})"
            )
        if response.status_code >= 400:
            raise ConnectorError(f"confluence returned {response.status_code} for {path}")

    def _client(self) -> httpx2.Client:
        return httpx2.Client(transport=self.transport, timeout=self.timeout_seconds)

    def _headers(self, url: str) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        # The credential authenticates us to the configured site and nowhere else.
        # A URL named by a response — a `next` cursor, an attachment `downloadLink`,
        # a redirect target — that points off-origin must never receive it, or a
        # malicious or compromised source could harvest this engine's Confluence
        # token (docs/security.md). This is the same reasoning that strips auth on
        # redirects; the response-named absolute URLs have the same property.
        if self.credential is not None and self._same_origin(url):
            headers["Authorization"] = self.credential.header()
        return headers

    def _same_origin(self, url: str) -> bool:
        base, other = urlsplit(self.base_url), urlsplit(url)
        return (other.scheme, other.netloc) == (base.scheme, base.netloc)

    def url(self, path: str) -> str:
        """An API path (``/pages/123``) as an absolute URL."""
        return f"{self.base_url}{self.api_prefix}{path}"

    def _resolve(self, url: str) -> str:
        """Absolute URLs pass through; server-relative links get the base back.

        v2's ``next`` and ``downloadLink`` are relative to the site root, not to
        the API prefix — so this deliberately does not reuse :meth:`_url`.
        """
        if url.startswith(("http://", "https://")):
            return url
        return f"{self.base_url}/{url.lstrip('/')}"

    def _require_same_origin(self, url: str, path: str) -> None:
        """Refuse an API call to a host other than the configured site.

        A ``next`` cursor or single-resource URL is always on the site; an absolute
        one that points elsewhere is a response steering the scan off-origin (an
        SSRF attempt), which has no legitimate meaning on the JSON API path."""
        if not self._same_origin(url):
            raise ConnectorError(f"refusing to follow an off-site URL for {path}")


def _next_link(payload: dict[str, Any]) -> str | None:
    links = payload.get("_links")
    if not isinstance(links, dict):
        return None
    following = links.get("next")
    return str(following) if following else None


def _retry_after(response: httpx2.Response, *, fallback: float) -> float:
    """Seconds to wait, from the server if it said and from backoff if it did not.

    Only the delta-seconds form is parsed. `Retry-After` may also be an HTTP date,
    but honouring that means trusting the server's clock against ours, and a skewed
    one produces either a busy loop or a stall — the fallback is better than both.
    """
    raw = response.headers.get("retry-after")
    if raw:
        try:
            parsed = float(raw.strip())
        except ValueError:
            logger.debug("confluence_retry_after_unparsed", value=raw[:32])
        else:
            # A zero or negative wait is not an actionable instruction, and since a
            # throttle no longer consumes a retry attempt, honouring it verbatim
            # would spin. Fall back to backoff, which always advances the budget.
            if parsed > 0:
                return parsed
    return fallback


def _path_of(url: str) -> str:
    """The path alone, for logs and errors.

    Query strings on v2 URLs carry cursors, and a cursor is a bearer-ish token for
    a position in someone's content. It has no business in an error message that
    gets stored on a failed task and shown in the UI.
    """
    return urlsplit(url).path or url
