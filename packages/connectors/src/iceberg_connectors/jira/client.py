"""Talking to Jira Cloud's REST v3 API (#144).

Everything the connector needs from the network, and nothing about what an issue
means — that is :mod:`iceberg_connectors.jira.connector`'s job. The transport
itself (credentials, retry and throttle budgets, byte caps, the same-origin rules)
is shared with Confluence in :mod:`iceberg_connectors.http`; what lives here is what
Jira genuinely does differently, and it is more than it looks.

**Jira paginates two different ways, and which one depends on the endpoint.**
Issue search uses an opaque ``nextPageToken``; project search, comments and
changelogs use the older ``startAt``/``isLast`` bean. That is not a Cloud-versus-DC
split and cannot be sniffed once and remembered, so each call site says which it is
talking to rather than the client guessing.

**A repeated page token is treated as a broken server, not as progress.** Atlassian
has open defects in which ``search/jql`` hands back a fresh-looking token that
returns the first page forever and an ``isLast`` that never flips true
(JRACLOUD-94648, JRACLOUD-94632). A scanner that trusted either would loop until the
lease expired, re-reporting the same issues; a scanner that quietly stopped would
report a clean scan of content it never read. Neither is acceptable, so a token that
does not advance raises and the task fails with a reason.

**Issue search returns no total.** The endpoint that replaced ``/search`` dropped it
deliberately. The connector therefore cannot say "5000 existed, I read 4997" — the
remainder is a scope gap, never an invented clean count (``docs/connector-sdk.md``).

**403 is not the credential, here.** Jira permissions are per-project and per-issue,
so an account that can browse a project may still be refused one issue's comments.
Aborting the task over that would make an ordinary Jira permanently partial, so 403
raises :class:`~iceberg_connectors.http.PermissionDenied` — countable, and the scan
continues. 401 remains site-wide. This is the exact inverse of Confluence, whose
space-shaped permissions make a 403 a source to fix.
"""

from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any, ClassVar

from iceberg_connectors.http import MAX_PAGES, HttpClient, _path_of
from iceberg_connectors.protocol import ConnectorError

__all__ = [
    "DEFAULT_API_PREFIX",
    "DEFAULT_PAGE_SIZE",
    "JiraClient",
]

#: v3 lives under `/rest/api/3` on Cloud. Data Center mounts `/rest/api/2` (and
#: answers wiki markup rather than ADF), which is why this is a default rather than
#: a constant spliced into every path.
DEFAULT_API_PREFIX = "/rest/api/3"

#: The enhanced-search ceiling. Asking for more is silently capped, so requesting
#: exactly this is one round trip per page and no surprises.
DEFAULT_PAGE_SIZE = 100


@dataclass(slots=True)
class JiraClient(HttpClient):
    """A paginating, rate-limit-aware Jira REST v3 client."""

    product: ClassVar[str] = "jira"
    default_api_prefix: ClassVar[str] = DEFAULT_API_PREFIX
    #: A rejected credential is site-wide and must stop the task.
    credential_statuses: ClassVar[frozenset[int]] = frozenset({401})
    #: A refused *object* is countable and must not stop the task.
    forbidden_statuses: ClassVar[frozenset[int]] = frozenset({403})

    page_size: int = DEFAULT_PAGE_SIZE

    # ─── Issue search (token pagination) ──────────────────────────────────────

    def search(
        self,
        jql: str,
        *,
        fields: tuple[str, ...] = (),
        expand: str = "",
        limit: int | None = None,
    ) -> Iterator[dict[str, Any]]:
        """Yield every issue matching ``jql``, following ``nextPageToken``.

        A generator, so a window of five thousand issues does not have to exist in
        memory before the first one is scanned — and so a cancelled task stops
        requesting rather than finishing and discarding (ADR 0009 §4).

        ``limit`` caps the *page* size rather than the total, which is what the
        window-bound probes want: one issue is enough to learn a boundary.
        """
        params: dict[str, Any] = {
            "jql": jql,
            "maxResults": limit or self.page_size,
        }
        if fields:
            # CSV rather than a repeated parameter: the enhanced-search endpoint
            # documents the comma-separated form, and a repeated key is silently
            # last-wins on some proxies.
            params["fields"] = ",".join(fields)
        if expand:
            params["expand"] = expand

        url = self.url("/search/jql")
        seen_tokens: set[str] = set()

        for _page in range(MAX_PAGES):
            payload = self.get_json(url, params=params)
            if "startAt" in payload:
                # The offset-shaped bean Data Center still serves. Its `issues` is a
                # perfectly good list, so this has to be checked before the shape
                # check rather than inside it — the first page of a DC response
                # otherwise reads as a complete Cloud result and reports a whole
                # project as scanned from one page of it.
                #
                # Refused rather than paged blindly: offset paging over a project
                # being written to silently skips or repeats issues, which on a
                # large project means missing secrets with no sign that it happened.
                # Refused even when one page would have held everything, so the
                # boundary is a decision rather than a function of project size.
                raise ConnectorError(
                    "jira answered issue search with the Data Center offset shape, "
                    "which this connector does not support yet"
                )
            issues = payload.get("issues")
            if not isinstance(issues, list) or any(not isinstance(i, dict) for i in issues):
                raise ConnectorError(
                    f"{self.product} returned an unexpected search shape for {_path_of(url)}"
                )
            yield from issues

            token = payload.get("nextPageToken")
            if not isinstance(token, str) or not token:
                # Absence of a token is the documented end of the results. `isLast`
                # is deliberately not trusted on its own — it has a standing defect
                # where it never flips true.
                return
            if token in seen_tokens:
                # A token that repeats is a server looping, not a page. Failing here
                # costs one task; trusting it would re-scan the first page until the
                # lease expired.
                raise ConnectorError(
                    f"{self.product} repeated a search page token for {_path_of(url)}"
                )
            seen_tokens.add(token)
            params = {**params, "nextPageToken": token}

        raise ConnectorError(f"issue search did not terminate after {MAX_PAGES} pages")

    def search_one(self, jql: str) -> dict[str, Any] | None:
        """The first issue matching ``jql``, or ``None``.

        Used to learn a project's oldest and newest ``created`` without counting
        anything, since the endpoint no longer reports a total.
        """
        for issue in self.search(jql, fields=("created",), limit=1):
            return issue
        return None

    # ─── Collections (offset pagination) ──────────────────────────────────────

    def paginate(self, path: str, *, key: str, **params: Any) -> Iterator[dict[str, Any]]:
        """Yield every result of an ``startAt``/``isLast`` collection.

        Project search, comments and changelogs all use this older shape. Offset
        paging is safe *here* in a way it would not be for issue search: these
        collections are small and the connector reads each one within a single
        request burst, where issue search runs for as long as a window takes.

        ``startAt`` is advanced from the count actually received rather than from
        the server's echo, and a page that returns nothing while claiming more ends
        the loop — a server that never sets ``isLast`` cannot spin the task.
        """
        url = self.url(path)
        start = 0

        for _page in range(MAX_PAGES):
            payload = self.get_json(
                url, params={**params, "startAt": start, "maxResults": self.page_size}
            )
            values = payload.get(key)
            if not isinstance(values, list) or any(not isinstance(item, dict) for item in values):
                raise ConnectorError(
                    f"{self.product} returned an unexpected collection shape for {_path_of(url)}"
                )
            yield from values

            if not values:
                return
            start += len(values)
            if payload.get("isLast") is True:
                return
            total = payload.get("total")
            if isinstance(total, int) and start >= total:
                return

        raise ConnectorError(f"pagination did not terminate after {MAX_PAGES} pages of {path}")
