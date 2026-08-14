"""Talking to Confluence Cloud's REST v2 API (#47, #49).

Everything the connector needs from the network, and nothing about what the
content means — that is :mod:`iceberg_connectors.confluence.connector`'s job. Kept
apart because the two fail for entirely different reasons: this module deals with
cursors, credentials, and a server asking to be left alone, while the other deals
with markup and attachments.

Most of that is not Confluence-shaped at all, and since #144 it lives in
:mod:`iceberg_connectors.http`: the credential flavor rule, the retry and throttle
budgets, the byte caps, and the same-origin rules that keep this engine's token
from following a link the source named. What remains here is what v2 genuinely does
differently.

**Pagination is cursor-based and opaque.** v2 returns a ``_links.next`` and the
only correct thing to do with it is follow it. Constructing the next URL from an
offset would silently skip or repeat pages when content changes mid-scan, which on
a fifty-thousand-page space means missing secrets without any sign that it
happened.

**Links are relative to a context this module has to learn.** ``_links.base`` names
it, ``downloadLink`` and ``webui`` are relative to *that* rather than to the site
root, and the ``next`` cursor already carries it — hence :meth:`resolve` and the
splice in ``iceberg_connectors.http._join``.

**403 means the credential, here.** Confluence permissions are space-shaped, and an
account that cannot read a configured space is a source to fix rather than a page to
step over. Jira is the opposite and says so in its own client; the split is the
``credential_statuses``/``forbidden_statuses`` pair on
:class:`~iceberg_connectors.http.HttpClient`.
"""

from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any, ClassVar
from urllib.parse import urlsplit

from iceberg_connectors.http import (
    MAX_PAGES,
    Credential,
    DownloadTooLarge,
    HttpClient,
    RateLimited,
    RateLimitPolicy,
    _join,
    _path_of,
)
from iceberg_connectors.protocol import ConnectorError

#: Re-exported so the connector and its tests keep importing the transport types
#: from the client they use, rather than reaching across to a shared module for
#: names that have not changed meaning.
__all__ = [
    "DEFAULT_API_PREFIX",
    "DEFAULT_PAGE_SIZE",
    "ConfluenceClient",
    "Credential",
    "DownloadTooLarge",
    "RateLimitPolicy",
    "RateLimited",
]

#: v2 lives under `/wiki/api/v2` on Cloud. Server/DC mounts elsewhere, which is why
#: this is a default rather than a constant spliced into every path.
DEFAULT_API_PREFIX = "/wiki/api/v2"

#: Cloud's own ceiling for most v2 collections. Asking for more is silently capped,
#: so requesting exactly this is one round trip per page and no surprises.
DEFAULT_PAGE_SIZE = 250


@dataclass(slots=True)
class ConfluenceClient(HttpClient):
    """A minimal, paginating, rate-limit-aware Confluence REST v2 client."""

    product: ClassVar[str] = "confluence"
    default_api_prefix: ClassVar[str] = DEFAULT_API_PREFIX

    page_size: int = DEFAULT_PAGE_SIZE
    #: The context base the site reports in ``_links.base``, learned from the first
    #: response that carries one. Seedable for a deployment that reports none.
    link_base: str = ""

    def _normalise(self) -> None:
        # Compatibility for sources saved from the old UI/seed example. The API
        # prefix already carries `/wiki`; leaving it on the base produces
        # `/wiki/wiki/api/v2`. Only the exact Cloud context with the default prefix
        # is normalised, so custom Server/DC context paths remain untouched.
        split = urlsplit(self.base_url)
        if (
            self.api_prefix == DEFAULT_API_PREFIX
            and split.path.rstrip("/") == "/wiki"
            and not split.query
            and not split.fragment
        ):
            self.base_url = f"{split.scheme}://{split.netloc}"
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
            results = payload.get("results")
            if not isinstance(results, list) or any(not isinstance(item, dict) for item in results):
                raise ConnectorError(
                    f"{self.product} returned an unexpected collection shape for {_path_of(url)}"
                )
            yield from results

            following = _next_link(payload)
            if not following:
                return
            # The cursor link already carries limit and every filter; passing the
            # original params again would override the cursor on some deployments.
            url, query = self.resolve(following), None

        raise ConnectorError(f"pagination did not terminate after {MAX_PAGES} pages of {path}")

    # ─── Link resolution ──────────────────────────────────────────────────────

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

    def _learn_links(self, body: dict[str, Any]) -> None:
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


def _next_link(payload: dict[str, Any]) -> str | None:
    links = payload.get("_links")
    if not isinstance(links, dict):
        return None
    following = links.get("next")
    return str(following) if following else None
