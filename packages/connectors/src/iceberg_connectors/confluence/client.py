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
import json
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

#: Backstop on a single JSON response, streamed and cut off like an attachment.
#: A hostile or compromised site could answer a page fetch with a multi-gigabyte
#: ``body.storage.value``; without a cap ``response.json()`` would buffer it whole.
#: Generous enough for a full 250-item collection of ordinary pages.
DEFAULT_MAX_JSON_BYTES = 64 * 1024 * 1024


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
class _Redirect:
    """Where a download hop was told to go next.

    A value rather than a branch inside the transport loop, so a download gets the
    same retry and throttle handling as every other request while the redirect
    chain stays where it is legible.
    """

    target: str


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

    One instance is one connection pool, and it lives for one discovery or one
    fetch. Constructing a client per request would pay a TCP and TLS handshake on
    every page, comment, and attachment — hundreds of thousands of them on a
    fifty-thousand-page space, inflating the very load that trips the site's rate
    limiter. :meth:`close` releases it; the connector closes it with the fetch.
    """

    base_url: str
    credential: Credential | None = None
    api_prefix: str = DEFAULT_API_PREFIX
    page_size: int = DEFAULT_PAGE_SIZE
    rate_limit: RateLimitPolicy = field(default_factory=RateLimitPolicy)
    transport: httpx2.BaseTransport | None = None
    sleep: Callable[[float], None] = time.sleep
    timeout_seconds: float = 60.0
    max_json_bytes: int = DEFAULT_MAX_JSON_BYTES
    #: The context base the site reports in ``_links.base``, learned from the first
    #: response that carries one. Seedable for a deployment that reports none.
    link_base: str = ""
    _http: httpx2.Client | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        self.base_url = self.base_url.rstrip("/")
        self.link_base = self.link_base.rstrip("/")

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
            url, query = self.resolve(following), None

        raise ConnectorError(f"pagination did not terminate after {MAX_PAGES} pages of {path}")

    # ─── Single resources ─────────────────────────────────────────────────────

    def get_json(self, url: str, *, params: dict[str, Any] | None = None) -> dict[str, Any]:
        resolved = self.resolve(url)
        self._require_same_origin(resolved, _path_of(url))
        raw = self._request("GET", resolved, params=params)
        try:
            body = json.loads(raw)
        except ValueError as exc:
            raise ConnectorError(
                f"confluence returned a non-JSON body for {_path_of(url)}"
            ) from exc
        if not isinstance(body, dict):
            raise ConnectorError(
                f"confluence returned an unexpected body shape for {_path_of(url)}"
            )
        self._learn_link_base(body)
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

        Every hop runs through the same retry and throttle loop the JSON path uses.
        A download that failed on a single 429 or a dropped connection would drop
        the attachment silently during exactly the throttling a scan provokes, and
        "could not read it" reads in a findings list as "no secrets here".
        """
        path = _path_of(url)
        target = self.resolve(url)
        # The first hop carries the credential, so it must be on the site. The
        # download itself may then redirect to an off-origin signed media URL, which
        # the loop below follows with auth stripped.
        self._require_same_origin(target, path)
        headers = self._headers(target)

        for _hop in range(MAX_REDIRECTS + 1):
            hop = self._stream(
                "GET",
                target,
                params=None,
                headers=headers,
                consume=lambda response: self._download_body(response, path, max_bytes),
            )
            if not isinstance(hop, _Redirect):
                return hop
            # Stripped of everything that authenticates us before following.
            target, headers = hop.target, {"Accept": "*/*"}

        raise ConnectorError(f"more than {MAX_REDIRECTS} redirects for {path}")

    # ─── Transport ────────────────────────────────────────────────────────────

    def _request(self, method: str, url: str, *, params: dict[str, Any] | None) -> bytes:
        """Issue a request through the retry/throttle loop, returning the body bytes.

        Streamed, so a successful response's body is read against a cap rather than
        buffered whole — the same protection ``get_bytes`` gives attachments, since
        a page fetch's JSON is just as attacker-influenced. Error and throttle
        responses have their (small) bodies left unread and the connection closed.
        """
        path = _path_of(url)

        def read(response: httpx2.Response) -> bytes:
            self._raise_for_status(response, path)
            return self._read_capped(response, path)

        return self._stream(method, url, params=params, headers=self._headers(url), consume=read)

    def _stream[ResultT](
        self,
        method: str,
        url: str,
        *,
        params: dict[str, Any] | None,
        headers: dict[str, str],
        consume: Callable[[httpx2.Response], ResultT],
    ) -> ResultT:
        """Retry, throttle, and hand ``consume`` the one response worth reading.

        ``consume`` runs while the stream is still open, so a body is read against a
        cap rather than buffered whole. Anything it raises is the caller's answer;
        anything the transport raises is wrapped as a :class:`ConnectorError`, since
        a raw ``httpx`` error escaping here would sail past the per-page handler in
        the connector and fail a whole space over one dropped connection.
        """
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
            try:
                with self._client().stream(method, url, params=params, headers=headers) as response:
                    status = response.status_code
                    if status != 429 and status not in RETRYABLE_STATUSES:
                        return consume(response)
                    retry_after = (
                        _retry_after(response, fallback=self.rate_limit.delay_for(throttles))
                        if status == 429
                        else None
                    )
            except httpx2.HTTPError as exc:
                last_error = ConnectorError(f"{type(exc).__name__} reaching {path}")
                attempt = self._back_off(attempt)
                continue

            if retry_after is not None:  # 429
                throttles += 1
                waited += retry_after
                if waited > self.rate_limit.max_wait_seconds:
                    raise RateLimited(
                        f"confluence rate-limited {path} for more than "
                        f"{self.rate_limit.max_wait_seconds:.0f}s; reduce engine concurrency"
                    )
                logger.info("confluence_rate_limited", path=path, wait_seconds=retry_after)
                self.sleep(retry_after)
                continue

            last_error = ConnectorError(f"confluence returned {status} for {path}")
            attempt = self._back_off(attempt)

        raise ConnectorError(
            f"{method} {path} failed after {self.rate_limit.attempts} attempts"
        ) from last_error

    def _back_off(self, attempt: int) -> int:
        """Wait before the next attempt, and only if there is one.

        Sleeping after the last attempt is dead time before an error that was
        already decided — 16 s at the defaults, per unreadable resource, across
        every failing page in a space.
        """
        if attempt + 1 < self.rate_limit.attempts:
            self.sleep(self.rate_limit.delay_for(attempt))
        return attempt + 1

    def _download_body(
        self, response: httpx2.Response, path: str, max_bytes: int
    ) -> bytes | _Redirect:
        """One download hop: the bytes, or where to go for them."""
        if response.is_redirect and response.headers.get("location"):
            # Resolved against the current target so a relative Location works.
            target = str(response.next_request.url) if response.next_request else ""
            if not target:
                raise ConnectorError(f"redirect without a target for {path}")
            return _Redirect(target)

        self._raise_for_status(response, path)
        chunks: list[bytes] = []
        total = 0
        for chunk in response.iter_bytes():
            total += len(chunk)
            if total > max_bytes:
                # One byte over is enough to know; reading the rest only costs
                # bandwidth the scan does not need to spend.
                raise DownloadTooLarge(total)
            chunks.append(chunk)
        return b"".join(chunks)

    def _read_capped(self, response: httpx2.Response, path: str) -> bytes:
        """Read a streamed body, refusing to buffer more than ``max_json_bytes``."""
        chunks: list[bytes] = []
        total = 0
        for chunk in response.iter_bytes():
            total += len(chunk)
            if total > self.max_json_bytes:
                raise ConnectorError(
                    f"confluence response for {path} exceeded the {self.max_json_bytes} byte cap"
                )
            chunks.append(chunk)
        return b"".join(chunks)

    def _raise_for_status(self, response: httpx2.Response, path: str) -> None:
        if response.status_code in (401, 403):
            # Split out because the operator response is specific and different:
            # rotate the token, or grant the account access to the space.
            raise CredentialError(
                f"confluence rejected the credential for {path} ({response.status_code})"
            )
        if response.status_code >= 400:
            raise ConnectorError(f"confluence returned {response.status_code} for {path}")

    def close(self) -> None:
        """Release the connection pool. Safe to call more than once."""
        pool, self._http = self._http, None
        if pool is not None:
            pool.close()

    def _client(self) -> httpx2.Client:
        if self._http is None:
            self._http = httpx2.Client(transport=self.transport, timeout=self.timeout_seconds)
        return self._http

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

    def resolve(self, url: str) -> str:
        """A link the site named, as an absolute URL.

        Absolute links pass through. A relative one is resolved against the context
        base the site reports in ``_links.base`` — Cloud's is
        ``https://site.atlassian.net/wiki``, and ``downloadLink`` and ``webui`` are
        relative to *that* rather than to the site root. Resolving them against the
        root 404s every attachment while the UI links beside them work, which is the
        inconsistency this exists to remove; the API prefix is deliberately not
        involved, since none of these links sit under it.
        """
        return _join(self.link_base or self.base_url, url)

    def _learn_link_base(self, body: dict[str, Any]) -> None:
        """Adopt the context base a response reports, if the site is entitled to.

        An off-origin ``base`` is ignored rather than adopted: it is named by the
        response, and honouring one would aim the first (credentialed) download hop
        at a host the source chose — the same harvesting the ``next`` cursor and
        redirect rules refuse.
        """
        links = body.get("_links")
        base = links.get("base") if isinstance(links, dict) else None
        if isinstance(base, str) and base and self._same_origin(base):
            self.link_base = base.rstrip("/")

    def _require_same_origin(self, url: str, path: str) -> None:
        """Refuse an API call to a host other than the configured site.

        A ``next`` cursor or single-resource URL is always on the site; an absolute
        one that points elsewhere is a response steering the scan off-origin (an
        SSRF attempt), which has no legitimate meaning on the JSON API path."""
        if not self._same_origin(url):
            raise ConnectorError(f"refusing to follow an off-site URL for {path}")


def _join(base: str, link: str) -> str:
    """A site-named relative link resolved against a base that may carry a context.

    v2 is not consistent about what its links are relative to: a ``next`` cursor
    arrives carrying the context path already (``/wiki/api/v2/...``) while ``webui``
    and ``downloadLink`` do not (``/spaces/...``, ``/download/...``). Both are
    root-relative strings, so neither plain concatenation nor ``urljoin`` is right
    for both, and guessing wrong means either every attachment 404s or every cursor
    does. The context is therefore added only where it is not already present, which
    needs no live site to be sure of and degrades to the site root for a deployment
    that reports no base at all.
    """
    if link.startswith(("http://", "https://")):
        return link

    split = urlsplit(base)
    context = split.path.rstrip("/")
    path = f"/{link.lstrip('/')}"
    if context and path != context and not path.startswith(f"{context}/"):
        path = f"{context}{path}"
    return f"{split.scheme}://{split.netloc}{path}"


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
