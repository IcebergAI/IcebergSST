"""The Confluence REST client: auth, cursors, and being throttled (#47, #49).

Driven against the fixture site in `confluence_server.py` rather than a mock, so
the real header building, link resolution, and backoff all run. `sleep` is injected,
so a test of five throttled attempts costs no wall-clock.

The recurring theme is **what the client must not assume**: that a `next` link can
be reconstructed, that a declared size is true, that a 429 is a failure, that a
credential can safely appear in a log line.
"""

from typing import Any

import httpx2
import pytest
from confluence_server import (
    API_TOKEN,
    EMAIL,
    SITE,
    Attachment,
    FakeConfluence,
    Page,
    Space,
    storage_page,
)
from iceberg_connectors.confluence.client import (
    ConfluenceClient,
    Credential,
    DownloadTooLarge,
    RateLimited,
    RateLimitPolicy,
)
from iceberg_connectors.protocol import ConnectorError, CredentialError


def _client(site: FakeConfluence, **overrides: Any) -> tuple[ConfluenceClient, list[float]]:
    slept: list[float] = []
    defaults: dict[str, Any] = {
        "base_url": SITE,
        "credential": Credential(token=API_TOKEN, email=EMAIL),
        "transport": site.transport(),
        "sleep": slept.append,
    }
    return ConfluenceClient(**(defaults | overrides)), slept


def _site(pages: int = 5) -> FakeConfluence:
    return FakeConfluence(
        spaces=[
            Space(
                "s1",
                "DOCS",
                "Documentation",
                pages=[Page(f"p{n}", f"Page {n}", storage_page(f"body {n}")) for n in range(pages)],
            )
        ]
    )


# ─── Credentials ──────────────────────────────────────────────────────────────


def test_a_cloud_api_token_authenticates_as_basic_with_the_account_email() -> None:
    """The token alone is not a bearer credential on Cloud — Basic `email:token` is
    the only form the site accepts, and getting it wrong is a 401 on every request."""
    site = _site()
    client, _ = _client(site)

    list(client.paginate("/spaces"))

    assert site.requests[0].headers["authorization"].startswith("Basic ")


def test_a_bare_token_is_sent_as_a_bearer_credential() -> None:
    """Server/Data Center PATs. One field in the connection blob decides, which is
    what keeps the flavor difference out of the `Connector` protocol (#47)."""
    header = Credential(token="pat-value").header()

    assert header == "Bearer pat-value"


def test_a_rejected_credential_raises_the_error_that_names_the_fix() -> None:
    """`CredentialError` means rotate the token. Retrying will not help, and the
    scan must say so rather than reporting a site with no content."""
    site = FakeConfluence(spaces=[Space("s1", "DOCS", "Docs")], require_credential=True)
    client, _ = _client(site, credential=Credential(token="wrong", email=EMAIL))

    with pytest.raises(CredentialError, match="rejected the credential"):
        list(client.paginate("/spaces"))


def test_an_anonymous_site_needs_no_credential() -> None:
    site = _site()
    site.require_credential = False
    client, _ = _client(site, credential=None)

    assert len(list(client.paginate("/spaces"))) == 1
    assert "authorization" not in site.requests[0].headers


def test_a_credential_does_not_appear_in_its_own_repr() -> None:
    """structlog renders arguments with `repr`, and so do tracebacks. A token
    printed once into a log aggregator is a token that has to be rotated."""
    credential = Credential(token="s3cr3t-token", email=EMAIL)

    assert "s3cr3t" not in repr(credential)
    assert "s3cr3t" not in f"{credential}"


# ─── Pagination ───────────────────────────────────────────────────────────────


def test_every_page_of_a_collection_is_yielded() -> None:
    site = _site(pages=5)
    client, _ = _client(site, page_size=2)

    pages = list(client.paginate("/spaces/s1/pages"))

    assert [page["id"] for page in pages] == ["p0", "p1", "p2", "p3", "p4"]


def test_the_next_link_is_followed_rather_than_reconstructed() -> None:
    """The cursor is opaque by contract. A client that built its own next URL from
    an offset would skip or repeat results whenever content changed mid-scan — on a
    fifty-thousand-page space, missing secrets with no sign it happened."""
    site = _site(pages=5)
    client, _ = _client(site, page_size=2)

    list(client.paginate("/spaces/s1/pages"))

    assert site.cursors_followed() == ["cursor-2", "cursor-4"]


def test_a_collection_that_fits_on_one_page_costs_one_request() -> None:
    site = _site(pages=2)
    client, _ = _client(site, page_size=2)

    list(client.paginate("/spaces/s1/pages"))

    assert len(site.requests) == 1


def test_query_filters_reach_the_first_request() -> None:
    site = FakeConfluence(
        spaces=[Space("s1", "DOCS", "Docs"), Space("s2", "~alice", "Alice", type="personal")]
    )
    client, _ = _client(site)

    spaces = list(client.paginate("/spaces", type="global"))

    assert [space["key"] for space in spaces] == ["DOCS"]


def test_pagination_is_lazy() -> None:
    """A generator by contract: a space with fifty thousand pages must not exist in
    memory before the first one is scanned, and a cancelled task must be able to
    stop requesting rather than finish and discard (ADR 0009 §4)."""
    site = _site(pages=5)
    client, _ = _client(site, page_size=2)

    stream = client.paginate("/spaces/s1/pages")
    next(stream)

    assert len(site.requests) == 1  # ...not three


def test_pagination_that_never_terminates_is_stopped() -> None:
    """A task that never ends is worse than one that reports what it found."""

    def always_more(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(
            200, json={"results": [{"id": "p1"}], "_links": {"next": "/wiki/api/v2/spaces"}}
        )

    client, _ = _client(_site(), transport=httpx2.MockTransport(always_more))

    with pytest.raises(ConnectorError, match="did not terminate"):
        list(client.paginate("/spaces"))


# ─── Rate limiting ────────────────────────────────────────────────────────────


def test_a_429_is_waited_out_for_as_long_as_the_server_asked() -> None:
    """Honouring `Retry-After` is faster than guessing and keeps the integration
    from being throttled harder. A scan is exactly the workload that trips a limit,
    so this is a normal answer rather than an error."""
    site = _site(pages=1)
    site.throttle_first, site.retry_after = 2, 3.0
    client, slept = _client(site)

    pages = list(client.paginate("/spaces/s1/pages"))

    assert [page["id"] for page in pages] == ["p0"]
    assert slept == [3.0, 3.0]


def test_a_429_without_a_retry_after_falls_back_to_backoff() -> None:
    """A proxy in front of Confluence may omit it."""
    site = _site(pages=1)
    site.throttle_first, site.retry_after = 2, None
    client, slept = _client(site, rate_limit=RateLimitPolicy(base_delay_seconds=1.0))

    list(client.paginate("/spaces/s1/pages"))

    assert slept == [1.0, 2.0]  # ...growing, since the server said nothing


def test_an_unparsable_retry_after_falls_back_rather_than_failing() -> None:
    """`Retry-After` may be an HTTP date. Trusting the server's clock against ours
    gives either a busy loop or a stall, so the fallback is better than both."""
    site = _site(pages=1)
    site.throttle_first, site.retry_after = 1, None
    site_transport = site.transport()

    def with_a_date(request: httpx2.Request) -> httpx2.Response:
        response = site_transport.handle_request(request)
        if response.status_code == 429:
            return httpx2.Response(429, headers={"Retry-After": "Wed, 21 Oct 2026 07:28:00 GMT"})
        return response

    client, slept = _client(
        site,
        transport=httpx2.MockTransport(with_a_date),
        rate_limit=RateLimitPolicy(base_delay_seconds=0.5),
    )

    list(client.paginate("/spaces/s1/pages"))

    assert slept == [0.5]


def test_being_throttled_beyond_the_budget_fails_with_advice() -> None:
    """Waiting is nearly always better than failing, but not without limit: the
    task holds a lease, and past a point the answer is fewer engines."""
    site = _site(pages=1)
    site.throttle_first, site.retry_after = 50, 30.0
    client, _ = _client(site, rate_limit=RateLimitPolicy(attempts=20, max_wait_seconds=60.0))

    with pytest.raises(RateLimited, match="reduce engine concurrency"):
        list(client.paginate("/spaces/s1/pages"))


def test_a_5xx_is_retried_and_then_reported() -> None:
    client, slept = _client(
        _site(),
        transport=httpx2.MockTransport(lambda _request: httpx2.Response(503)),
        rate_limit=RateLimitPolicy(attempts=3, base_delay_seconds=0.5),
    )

    with pytest.raises(ConnectorError, match="after 3 attempts"):
        list(client.paginate("/spaces"))

    assert slept == [0.5, 1.0, 2.0]


def test_a_transport_error_is_retried() -> None:
    attempts = {"n": 0}

    def flaky(request: httpx2.Request) -> httpx2.Response:
        attempts["n"] += 1
        if attempts["n"] < 3:
            raise httpx2.ConnectError("connection refused")
        return httpx2.Response(200, json={"results": [{"id": "s1", "key": "DOCS"}]})

    client, _ = _client(_site(), transport=httpx2.MockTransport(flaky))

    assert len(list(client.paginate("/spaces"))) == 1
    assert attempts["n"] == 3


def test_a_404_is_not_retried() -> None:
    """The site's considered answer. Asking again sends the same wrong request."""
    site = _site()
    client, slept = _client(site)

    with pytest.raises(ConnectorError, match="404"):
        list(client.paginate("/spaces/nope/pages"))

    assert slept == []


def test_a_non_json_body_is_reported_with_the_path_and_no_query() -> None:
    """Cursors are a bearer-ish token for a position in someone's content; they have
    no business in an error stored on a failed task and shown in the UI."""
    client, _ = _client(
        _site(),
        transport=httpx2.MockTransport(
            lambda _r: httpx2.Response(200, text="<html>gateway</html>")
        ),
    )

    with pytest.raises(ConnectorError) as caught:
        client.get_json(f"{SITE}/wiki/api/v2/spaces?cursor=secret-cursor")

    assert "cursor" not in str(caught.value)
    assert "/wiki/api/v2/spaces" in str(caught.value)


# ─── Downloads ────────────────────────────────────────────────────────────────


def test_an_attachment_downloads_as_bytes() -> None:
    site = FakeConfluence(
        spaces=[
            Space(
                "s1",
                "DOCS",
                "Docs",
                pages=[
                    Page(
                        "p1",
                        "Runbook",
                        storage_page("see attached"),
                        attachments=[Attachment("notes.txt", b"contents")],
                    )
                ],
            )
        ]
    )
    client, _ = _client(site)

    data = client.get_bytes("/download/attachments/p1-0/notes.txt", max_bytes=1024)

    assert data == b"contents"


def test_a_download_over_the_cap_is_cut_off_rather_than_buffered() -> None:
    """A `Content-Length` is attacker-influenced. A client that trusted it would
    buffer a gigabyte from a source that claimed a kilobyte."""
    site = FakeConfluence(
        spaces=[
            Space(
                "s1",
                "DOCS",
                "Docs",
                pages=[Page("p1", "Big", "", attachments=[Attachment("big.txt", b"x" * 5000)])],
            )
        ]
    )
    client, _ = _client(site)

    with pytest.raises(DownloadTooLarge):
        client.get_bytes("/download/attachments/p1-0/big.txt", max_bytes=1000)


def test_a_download_link_is_resolved_against_the_site_not_the_api_prefix() -> None:
    """v2 returns `downloadLink` relative to the site root, outside `/wiki/api/v2`.
    Resolving it against the prefix 404s on every attachment."""
    site = FakeConfluence(
        spaces=[
            Space(
                "s1",
                "DOCS",
                "Docs",
                pages=[Page("p1", "R", "", attachments=[Attachment("a.txt", b"hi")])],
            )
        ]
    )
    client, _ = _client(site)

    client.get_bytes("/download/attachments/p1-0/a.txt", max_bytes=1024)

    assert site.paths_requested() == ["/download/attachments/p1-0/a.txt"]


def test_a_download_redirect_is_followed_without_the_credential() -> None:
    """Cloud answers an attachment download with a redirect to a signed media URL,
    so refusing to follow means no attachments at all. But the target is named by the
    response, and a source that pointed one at a host it controls would be handed
    this engine's Confluence token. The signed URL authorises itself."""
    seen: list[tuple[str, str | None]] = []

    def redirecting(request: httpx2.Request) -> httpx2.Response:
        seen.append((str(request.url.host), request.headers.get("authorization")))
        if request.url.path.startswith("/download/"):
            return httpx2.Response(302, headers={"Location": "https://media.elsewhere.test/blob"})
        return httpx2.Response(200, content=b"the file")

    client, _ = _client(_site(), transport=httpx2.MockTransport(redirecting))

    assert client.get_bytes("/download/attachments/p1-0/a.txt", max_bytes=1024) == b"the file"
    assert seen[0][1] is not None  # ...sent to the site we configured
    assert seen[1] == ("media.elsewhere.test", None)  # ...and not to wherever it pointed


def test_a_redirect_loop_is_stopped() -> None:
    def in_circles(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(302, headers={"Location": "https://elsewhere.test/again"})

    client, _ = _client(_site(), transport=httpx2.MockTransport(in_circles))

    with pytest.raises(ConnectorError, match="redirects"):
        client.get_bytes("/download/attachments/p1-0/a.txt", max_bytes=1024)


def test_an_absolute_url_passes_through_unchanged() -> None:
    site = _site()
    client, _ = _client(site)

    client.get_json(f"{SITE}/wiki/api/v2/spaces")

    assert site.paths_requested() == ["/wiki/api/v2/spaces"]


def test_an_off_site_next_link_is_refused_and_the_credential_never_sent() -> None:
    """A `next` cursor is server-named; one that points off-origin is a source
    trying to steer the scan (and harvest the token). It must be refused, and no
    request bearing the credential may reach the other host."""
    seen: list[tuple[str, str | None]] = []

    def hostile(request: httpx2.Request) -> httpx2.Response:
        seen.append((str(request.url.host), request.headers.get("authorization")))
        if request.url.host != "wiki.example.test":
            return httpx2.Response(200, json={"results": [], "_links": {}})
        return httpx2.Response(
            200,
            json={"results": [{"id": "p0"}], "_links": {"next": "https://evil.test/harvest"}},
        )

    client, _ = _client(_site(), transport=httpx2.MockTransport(hostile))

    with pytest.raises(ConnectorError, match="off-site"):
        list(client.paginate("/spaces/s1/pages"))

    assert all(host == "wiki.example.test" for host, _ in seen)


def test_an_off_site_download_link_is_refused_before_the_first_request() -> None:
    """The first download hop carries the credential, so it must be on the site."""
    seen: list[str] = []

    def record(request: httpx2.Request) -> httpx2.Response:
        seen.append(str(request.url.host))
        return httpx2.Response(200, content=b"x")

    client, _ = _client(_site(), transport=httpx2.MockTransport(record))

    with pytest.raises(ConnectorError, match="off-site"):
        client.get_bytes("https://evil.test/blob", max_bytes=1024)

    assert seen == []


def test_a_run_of_throttles_waits_out_the_budget_not_the_retry_count() -> None:
    """A throttle is bounded by how long the scan will wait, not by the retry
    budget: more consecutive 429s than `attempts` still waits rather than failing
    early with a misleading 'after N attempts' error."""
    site = _site(pages=1)
    site.throttle_first, site.retry_after = 3, 2.0
    client, slept = _client(
        site, rate_limit=RateLimitPolicy(attempts=2, max_wait_seconds=300.0)
    )

    pages = list(client.paginate("/spaces/s1/pages"))

    assert [page["id"] for page in pages] == ["p0"]
    assert slept == [2.0, 2.0, 2.0]  # three throttles waited out under attempts=2
