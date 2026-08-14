"""Shared HTTP transport for REST connectors (#144).

Extracted from the Confluence client when Jira became the second connector to need
it. What lives here is everything that is true of *any* credentialed REST source —
being throttled, being redirected, being lied to about a body's size, being steered
off-origin — and nothing about which product is answering. Each product's client
subclasses this and adds only what its API actually shapes differently: its path
prefix, how it paginates, and which statuses mean what.

**Authentication is flavor-shaped, not connector-shaped.** Atlassian Cloud
authenticates an API token as HTTP Basic with the account's email as the username —
the token alone is not a bearer credential. Server/Data Center issues PATs that
*are* bearer credentials. Both arrive as one opaque string from the task lease
(ADR 0009), and the ``email`` in the source's connection blob is what picks between
them. Confluence Cloud and Jira Cloud follow the identical rule, which is why
:class:`Credential` is here rather than in either connector.

**The credential is never logged.** Not in a request log, not in an error message,
not in a repr — :class:`Credential` exists to make that structural rather than a
rule people remember. Every log line here names a path and a status and nothing
else.

**429 is a normal answer, not an error.** Atlassian rate-limits aggressively, and a
scan is precisely the workload that trips it. The server says how long to wait in
``Retry-After``; honouring that is both faster and politer than backing off blindly,
and ignoring it gets an integration throttled harder.

**What a 4xx means is a product decision, not a transport one.** Confluence treats
403 as a credential problem, because a token that cannot read a space is a token to
fix. Jira cannot: per-project and per-issue permission schemes make a 403 on one
issue routine, and aborting a scan over one restricted issue would make an ordinary
Jira permanently partial. Hence :attr:`HttpClient.credential_statuses` and
:attr:`HttpClient.forbidden_statuses` — the split lives in the subclass, so neither
product has to carry the other's assumption.
"""

import base64
import json
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, ClassVar
from urllib.parse import urlsplit

import httpx2
import structlog

from iceberg_connectors.protocol import ConnectorError, CredentialError, RateLimitError

logger = structlog.get_logger()

#: Statuses worth trying again. 429 is handled separately — it carries its own
#: instructions, so it is a wait rather than a retry with a guessed delay.
RETRYABLE_STATUSES = frozenset({500, 502, 503, 504})

#: A page of results is bounded, but the number of pages is not. Without a cap, a
#: server that answered every `next` with another `next` would spin a task forever
#: — and a task that never ends is worse than one that reports what it found.
MAX_PAGES = 10_000

#: Cloud redirects an attachment download once, to a signed media URL. A handful of
#: hops covers a proxy in front of that; a loop is a broken site, not a file.
MAX_REDIRECTS = 5

#: Backstop on a single JSON response, streamed and cut off like an attachment.
#: A hostile or compromised site could answer a fetch with a multi-gigabyte field;
#: without a cap ``response.json()`` would buffer it whole. Generous enough for a
#: full collection page of ordinary records.
DEFAULT_MAX_JSON_BYTES = 64 * 1024 * 1024


class RateLimited(RateLimitError):
    """The server asked to be left alone for longer than this scan can wait."""


class PermissionDenied(ConnectorError):
    """The credential is fine; it just cannot read *this* object.

    Distinct from :class:`CredentialError` because the connector's response is the
    opposite one: count the object, record why, and keep scanning. A source with
    per-object permissions (Jira's project and issue schemes) answers 403 as a
    matter of course, and treating that as a site-wide credential failure would
    abort a whole task over one restricted record — turning an ordinary source into
    a permanently partial scan that never reconciles.
    """


class DownloadTooLarge(ConnectorError):
    """A download exceeded its byte cap and was cut off.

    Its own type because the connector's response is specific: mark the attachment
    incomplete and keep scanning neighboring units. The resulting failed task
    keeps the scan partial, so unseen content cannot drive reconciliation.
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
    """A source credential that will not appear in a log line.

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
class HttpClient:
    """A rate-limit-aware REST client for one credentialed source.

    ``transport`` and ``sleep`` are injectable for the same reason they are on the
    engine's API client: tests drive the real request-building and backoff logic
    against a scripted server without waiting for any of it (#71).

    One instance is one connection pool, and it lives for one discovery or one
    fetch. Constructing a client per request would pay a TCP and TLS handshake on
    every record, comment, and attachment — hundreds of thousands of them on a large
    source, inflating the very load that trips the site's rate limiter.
    :meth:`close` releases it; the connector closes it with the fetch.

    Subclasses set the ``ClassVar``s below and add only *new* fields. They are
    ``ClassVar`` rather than dataclass fields deliberately: a field redeclared in a
    ``slots=True`` subclass would duplicate a slot, and these vary per class rather
    than per instance.
    """

    #: Names the product in every error message and log event, so an operator
    #: reading a failed task knows which system said no.
    product: ClassVar[str] = "source"
    #: Where the API is mounted, when the connection blob does not say.
    default_api_prefix: ClassVar[str] = ""
    #: Statuses meaning "your credential is wrong" — site-wide, abort the task.
    credential_statuses: ClassVar[frozenset[int]] = frozenset({401, 403})
    #: Statuses meaning "not this object" — countable, keep scanning. Empty for a
    #: product whose 403 really is site-wide.
    forbidden_statuses: ClassVar[frozenset[int]] = frozenset()

    base_url: str
    credential: Credential | None = None
    #: Empty means "use :attr:`default_api_prefix`" — resolved in ``__post_init__``
    #: so a subclass default survives a connection blob that omits the key.
    api_prefix: str = ""
    rate_limit: RateLimitPolicy = field(default_factory=RateLimitPolicy)
    transport: httpx2.BaseTransport | None = None
    sleep: Callable[[float], None] = time.sleep
    timeout_seconds: float = 60.0
    max_json_bytes: int = DEFAULT_MAX_JSON_BYTES
    _http: httpx2.Client | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        self.base_url = self.base_url.rstrip("/")
        self.api_prefix = self.api_prefix or self.default_api_prefix
        self._normalise()

    def _normalise(self) -> None:
        """Product-specific base-URL tidying, after the prefix default is resolved.

        A hook rather than a ``super().__post_init__()`` chain: zero-argument
        ``super()`` inside a ``slots=True`` dataclass resolves against the class the
        decorator *replaced*, which fails at runtime in a way that reads as nothing
        to do with slots.
        """

    # ─── Single resources ─────────────────────────────────────────────────────

    def get_json(self, url: str, *, params: dict[str, Any] | None = None) -> dict[str, Any]:
        resolved = self.resolve(url)
        self._require_same_origin(resolved, _path_of(url))
        raw = self._request("GET", resolved, params=params)
        try:
            body = json.loads(raw)
        except ValueError as exc:
            raise ConnectorError(
                f"{self.product} returned a non-JSON body for {_path_of(url)}"
            ) from exc
        if not isinstance(body, dict):
            raise ConnectorError(
                f"{self.product} returned an unexpected body shape for {_path_of(url)}"
            )
        self._learn_links(body)
        return body

    def _learn_links(self, body: dict[str, Any]) -> None:
        """Adopt whatever a response says about where its links are relative to."""

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
        be handed this engine's token — the same reasoning that makes
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
        a record fetch's JSON is just as attacker-influenced. Error and throttle
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
        a raw ``httpx`` error escaping here would sail past the per-object handler in
        the connector and fail a whole scope over one dropped connection.
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
                        _retry_after(
                            response,
                            fallback=self.rate_limit.delay_for(throttles),
                            product=self.product,
                        )
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
                        f"{self.product} rate-limited {path} for more than "
                        f"{self.rate_limit.max_wait_seconds:.0f}s; reduce engine concurrency"
                    )
                logger.info(f"{self.product}_rate_limited", path=path, wait_seconds=retry_after)
                self.sleep(retry_after)
                continue

            last_error = ConnectorError(f"{self.product} returned {status} for {path}")
            attempt = self._back_off(attempt)

        raise ConnectorError(
            f"{method} {path} failed after {self.rate_limit.attempts} attempts"
        ) from last_error

    def _back_off(self, attempt: int) -> int:
        """Wait before the next attempt, and only if there is one.

        Sleeping after the last attempt is dead time before an error that was
        already decided — 16 s at the defaults, per unreadable resource, across
        every failing object in a scope.
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
                    f"{self.product} response for {path} exceeded the "
                    f"{self.max_json_bytes} byte cap"
                )
            chunks.append(chunk)
        return b"".join(chunks)

    def _raise_for_status(self, response: httpx2.Response, path: str) -> None:
        status = response.status_code
        if status in self.credential_statuses:
            # Split out because the operator response is specific and different:
            # rotate the token, or grant the account access to the scope.
            raise CredentialError(f"{self.product} rejected the credential for {path} ({status})")
        if status in self.forbidden_statuses:
            # Not the credential — this object. Countable, and the scan continues.
            raise PermissionDenied(f"{self.product} refused access to {path} ({status})")
        if status >= 400:
            raise ConnectorError(f"{self.product} returned {status} for {path}")

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
        # malicious or compromised source could harvest this engine's token
        # (docs/security.md). This is the same reasoning that strips auth on
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
        """A link the site named, as an absolute URL."""
        return _join(self.base_url, url)

    def _require_same_origin(self, url: str, path: str) -> None:
        """Refuse an API call to a host other than the configured site.

        A cursor or single-resource URL is always on the site; an absolute one that
        points elsewhere is a response steering the scan off-origin (an SSRF
        attempt), which has no legitimate meaning on the JSON API path."""
        if not self._same_origin(url):
            raise ConnectorError(f"refusing to follow an off-site URL for {path}")


def _join(base: str, link: str) -> str:
    """A site-named relative link resolved against a base that may carry a context.

    Atlassian APIs are not consistent about what their links are relative to: a
    Confluence v2 ``next`` cursor arrives carrying the context path already
    (``/wiki/api/v2/...``) while ``webui`` and ``downloadLink`` do not
    (``/spaces/...``, ``/download/...``). Both are root-relative strings, so neither
    plain concatenation nor ``urljoin`` is right for both, and guessing wrong means
    either every attachment 404s or every cursor does. The context is therefore
    added only where it is not already present, which needs no live site to be sure
    of and degrades to the site root for a deployment that reports no base at all.
    """
    if link.startswith(("http://", "https://")):
        return link

    split = urlsplit(base)
    context = split.path.rstrip("/")
    path = f"/{link.lstrip('/')}"
    if context and path != context and not path.startswith(f"{context}/"):
        path = f"{context}{path}"
    return f"{split.scheme}://{split.netloc}{path}"


def _retry_after(response: httpx2.Response, *, fallback: float, product: str) -> float:
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
            logger.debug(f"{product}_retry_after_unparsed", value=raw[:32])
        else:
            # A zero or negative wait is not an actionable instruction, and since a
            # throttle no longer consumes a retry attempt, honouring it verbatim
            # would spin. Fall back to backoff, which always advances the budget.
            if parsed > 0:
                return parsed
    return fallback


def _path_of(url: str) -> str:
    """The path alone, for logs and errors.

    Query strings carry cursors, and a cursor is a bearer-ish token for a position
    in someone's content. It has no business in an error message that gets stored on
    a failed task and shown in the UI.
    """
    return urlsplit(url).path or url
