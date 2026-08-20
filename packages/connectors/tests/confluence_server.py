"""A stand-in Confluence Cloud site, served in-process (#71).

**The decision this file is.** CI and local dev cannot reach a live Confluence, so
the connector's tests need a Confluence-shaped thing to talk to. Two options:
recorded HTTP responses replayed by a cassette library, or a small server that
answers the real API surface. This is the second, for three reasons:

1. Recording needs a live Cloud site to record *from*, and an API token for it.
   Nobody has one in CI, so the fixtures would be hand-written anyway — at which
   point they are a mock server with worse ergonomics.
2. Cursors are stateful. A cassette replays a fixed sequence of responses; it
   cannot answer "the second page of *this* cursor", so a pagination bug that only
   appears when the cursor is followed would replay green.
3. 429 and its ``Retry-After`` are behaviour, not a payload. Asserting the client
   waits the amount the server asked for needs a server that decides to throttle,
   not a recording of one that did.

What it does *not* do is validate the request shape against Atlassian's OpenAPI
schema — so a payload field renamed upstream would pass here and fail in
production. That risk is real and accepted: the alternative is no offline test at
all, and the shapes below are pinned to the v2 documentation with the deviations
noted where they exist.

The transport is `httpx2.MockTransport`, matching `apps/api/tests/oidc_provider.py`
— the same in-process-server pattern, for the same reason.
"""

import json
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx2
import pytest

SITE = "https://wiki.example.test"
EMAIL = "scanner@example.test"
API_TOKEN = "confluence-api-token"  # a fixture, not a credential

#: AWS's own documented example key. It has never authenticated anything, which is
#: what makes it safe to commit as a seeded test secret.
SEEDED_SECRET = "AKIAIOSFODNN7EXAMPLE"

_CURSOR = re.compile(r"^cursor-(\d+)$")


@dataclass(slots=True)
class Attachment:
    """One file on a page."""

    title: str
    data: bytes = b""
    media_type: str = "text/plain"
    #: What the API *claims* the size is. Settable independently of `data` so a test
    #: can lie the way a hostile source would.
    declared_size: int | None = None
    #: Answer the download with this status instead of the bytes.
    download_status: int = 200
    #: Omit ``downloadLink`` to model a malformed/incomplete API result.
    include_download_link: bool = True

    def as_payload(self, attachment_id: str) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "id": attachment_id,
            "title": self.title,
            "mediaType": self.media_type,
            "fileSize": self.declared_size if self.declared_size is not None else len(self.data),
        }
        if self.include_download_link:
            # Relative to the context base in `_links.base` and outside the API
            # prefix, exactly as v2 returns it — the detail a client that resolved
            # links against the prefix, or against the bare site root, gets wrong.
            payload["downloadLink"] = f"/download/attachments/{attachment_id}/{self.title}"
        return payload


@dataclass(slots=True)
class Comment:
    """A footer or inline comment."""

    id: str
    storage: str
    inline: bool = False
    replies: list[Comment] = field(default_factory=list)
    include_body: bool = True
    body_representation: str = "storage"


@dataclass(slots=True)
class Page:
    """One page, its comments, and its attachments."""

    id: str
    title: str
    storage: str
    comments: list[Comment] = field(default_factory=list)
    attachments: list[Attachment] = field(default_factory=list)
    #: Omit the body from the *list* response, forcing the connector to fetch the
    #: page individually — an older deployment, and a real fallback path.
    body_in_list: bool = True
    #: Independently omit it from the detail response to model a malformed 200.
    body_in_detail: bool = True
    body_representation: str = "storage"
    #: When this revision was published. v2 returns a `version` object on every
    #: page, and its `createdAt` is the only "when did this change" signal the API
    #: offers — there is no `lastModified` on a v2 page.
    version_created_at: str = "2024-01-01T00:00:00.000Z"
    version_number: int = 1
    #: Omit `version` entirely, as a deployment predating it would. Unknown, which
    #: an incremental scan must treat as "read it" rather than "skip it".
    include_version: bool = True

    def as_payload(self, space_id: str, *, with_body: bool) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "id": self.id,
            "title": self.title,
            "spaceId": space_id,
            "status": "current",
            "_links": {"webui": f"/spaces/SPACE/pages/{self.id}/{self.title}"},
        }
        if self.include_version:
            payload["version"] = {
                "createdAt": self.version_created_at,
                "number": self.version_number,
            }
        if with_body:
            payload["body"] = {
                self.body_representation: {
                    "value": self.storage,
                    "representation": self.body_representation,
                }
            }
        return payload


@dataclass(slots=True)
class Space:
    """One space and its pages."""

    id: str
    key: str
    name: str
    pages: list[Page] = field(default_factory=list)
    #: One of the v2 `GET /spaces` enum. The fixture modelled only `global` and
    #: `personal`, which is why a connector asking for `type=global` — and
    #: thereby dropping every collaboration space and knowledge base on a real
    #: site — passed the whole suite (#191).
    type: str = "global"

    def as_payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "key": self.key,
            "name": self.name,
            "type": self.type,
            "status": "current",
        }


@dataclass(slots=True)
class FakeConfluence:
    """A Confluence Cloud site that answers REST v2 over an in-process transport.

    Not a mock: it really pages with real cursors, really checks the
    ``Authorization`` header, and really throttles. A double that could not refuse a
    credential or hand out a second page would only ever prove the happy path.
    """

    spaces: list[Space] = field(default_factory=list)
    #: Results per page. Small by default so two pages of results need two pages,
    #: not two thousand rows of fixture.
    page_size: int = 2
    #: Reject everything until this many requests have been made — how a real site
    #: behaves when a scan hits its rate limit.
    throttle_first: int = 0
    #: Seconds the throttled response asks for. None omits `Retry-After`, which is
    #: also something real proxies do.
    retry_after: float | None = 1.0
    #: Require Basic `EMAIL:API_TOKEN`. False accepts anything, for anonymous sites.
    require_credential: bool = True
    #: Paths containing any of these answer 401 regardless of the credential — a
    #: token that reads spaces but not comments, or one revoked mid-scan.
    unauthorized_paths: tuple[str, ...] = ()
    #: Paths containing any of these answer 500. One page in a space that cannot be
    #: read is the case a scan of fifty thousand has to survive.
    failing_paths: tuple[str, ...] = ()
    #: Paths containing any of these answer 429 forever, however many requests have
    #: already succeeded — one endpoint throttled while the rest of the site answers,
    #: which is what a scan actually meets and what `throttle_first` cannot express.
    throttled_paths: tuple[str, ...] = ()
    #: The context base Cloud reports in `_links.base`, under which it serves both
    #: the API and attachment downloads. None is the Server/DC shape: no base in the
    #: payload, and downloads at the site root.
    link_base: str | None = f"{SITE}/wiki"

    requests: list[httpx2.Request] = field(default_factory=list)
    throttled: int = 0
    #: Every `sort` the site was actually asked for, so a test of the opt-in can
    #: prove it reached the server rather than being applied to the response.
    sorts_requested: list[str] = field(default_factory=list)

    # ─── Transport ────────────────────────────────────────────────────────────

    def transport(self) -> httpx2.MockTransport:
        return httpx2.MockTransport(self.handle)

    def handle(self, request: httpx2.Request) -> httpx2.Response:
        self.requests.append(request)
        path = request.url.path

        if self.throttle_first > self.throttled:
            self.throttled += 1
            return self._throttle()

        if self.require_credential and not self._authorized(request):
            return httpx2.Response(401, json={"errors": ["unauthorized"]})
        if any(fragment in path for fragment in self.unauthorized_paths):
            return httpx2.Response(401, json={"errors": ["forbidden for this token"]})
        if any(fragment in path for fragment in self.throttled_paths):
            return self._throttle()
        if any(fragment in path for fragment in self.failing_paths):
            return httpx2.Response(500, json={"errors": ["internal error"]})

        downloads = f"{self.context}/download/attachments/"
        if path.startswith(downloads):
            return self._download(path.removeprefix(self.context))
        if not path.startswith("/wiki/api/v2/"):
            return httpx2.Response(404, json={"errors": ["no such endpoint"]})

        return self._api(path.removeprefix("/wiki/api/v2"), dict(request.url.params))

    @property
    def context(self) -> str:
        """The path part of `_links.base` — `/wiki` on Cloud, nothing on Server/DC."""
        return urlsplit(self.link_base).path.rstrip("/") if self.link_base else ""

    def _throttle(self) -> httpx2.Response:
        headers = {} if self.retry_after is None else {"Retry-After": str(self.retry_after)}
        return httpx2.Response(429, headers=headers, json={"errors": ["rate limited"]})

    def _authorized(self, request: httpx2.Request) -> bool:
        import base64

        header = request.headers.get("authorization", "")
        if not header.startswith("Basic "):
            return False
        try:
            decoded = base64.b64decode(header.removeprefix("Basic ")).decode()
        except ValueError, UnicodeDecodeError:
            return False
        return decoded == f"{EMAIL}:{API_TOKEN}"

    # ─── Endpoints ────────────────────────────────────────────────────────────

    def _api(self, path: str, params: dict[str, Any]) -> httpx2.Response:
        if path == "/spaces":
            # Single-valued upstream, so this is `==` and not a membership test:
            # there is no server-side way to ask for "every type but one", which
            # is the whole reason the connector filters personal spaces itself.
            wanted_type = params.get("type")
            spaces = [s for s in self.spaces if not wanted_type or s.type == wanted_type]
            return self._collection([s.as_payload() for s in spaces], path, params)

        if match := re.fullmatch(r"/spaces/([^/]+)/pages", path):
            space = self._space(match[1])
            if space is None:
                return httpx2.Response(404, json={"errors": ["no such space"]})
            pages = list(space.pages)
            # `sort` is opt-in upstream: without it the order is the site's own and
            # a connector that assumed newest-first would be reading whatever came
            # back. Honoured here so a test of the opt-in fails when it is not sent.
            sort = str(params.get("sort") or "")
            if sort in ("-modified-date", "modified-date"):
                pages.sort(
                    key=lambda page: page.version_created_at,
                    reverse=sort.startswith("-"),
                )
                self.sorts_requested.append(sort)
            return self._collection(
                [p.as_payload(space.id, with_body=p.body_in_list) for p in pages],
                path,
                params,
            )

        if match := re.fullmatch(r"/pages/([^/]+)", path):
            found = self._page(match[1])
            if found is None:
                return httpx2.Response(404, json={"errors": ["no such page"]})
            space, page = found
            payload = self._with_base(page.as_payload(space.id, with_body=page.body_in_detail))
            return httpx2.Response(200, json=payload)

        if match := re.fullmatch(r"/pages/([^/]+)/(footer|inline)-comments", path):
            found = self._page(match[1])
            if found is None:
                return httpx2.Response(404, json={"errors": ["no such page"]})
            inline = match[2] == "inline"
            comments = [c for c in found[1].comments if c.inline == inline]
            return self._collection(
                [self._comment_payload(c) for c in comments],
                path,
                params,
            )

        if match := re.fullmatch(r"/(footer|inline)-comments/([^/]+)/children", path):
            comment = self._comment(match[2])
            if comment is None:
                return httpx2.Response(404, json={"errors": ["no such comment"]})
            inline = match[1] == "inline"
            if comment.inline != inline:
                return httpx2.Response(404, json={"errors": ["wrong comment type"]})
            return self._collection(
                [self._comment_payload(reply) for reply in comment.replies],
                path,
                params,
            )

        if match := re.fullmatch(r"/pages/([^/]+)/attachments", path):
            found = self._page(match[1])
            if found is None:
                return httpx2.Response(404, json={"errors": ["no such page"]})
            page = found[1]
            return self._collection(
                [a.as_payload(f"{page.id}-{i}") for i, a in enumerate(page.attachments)],
                path,
                params,
            )

        return httpx2.Response(404, json={"errors": ["no such endpoint"]})

    def _download(self, path: str) -> httpx2.Response:
        _, _, _, attachment_id, filename = path.split("/", 4)
        page_id, _, index = attachment_id.rpartition("-")
        found = self._page(page_id)
        if found is None or not index.isdigit():
            return httpx2.Response(404)

        attachments = found[1].attachments
        position = int(index)
        if position >= len(attachments) or attachments[position].title != filename:
            return httpx2.Response(404)

        attachment = attachments[position]
        if attachment.download_status != 200:
            return httpx2.Response(attachment.download_status)
        return httpx2.Response(
            200, content=attachment.data, headers={"Content-Type": attachment.media_type}
        )

    # ─── Cursor pagination ────────────────────────────────────────────────────

    def _collection(
        self, results: list[dict[str, Any]], path: str, params: dict[str, Any]
    ) -> httpx2.Response:
        """One page of results, plus a `next` link when there are more.

        The cursor is an offset behind an opaque string on purpose. A client that
        parsed it and built its own next URL would pass every test here that a
        client following `_links.next` passes — until content shifted mid-scan.
        Keeping it opaque means only the correct client works.
        """
        start = _cursor_offset(params.get("cursor"))
        limit = min(int(params.get("limit", self.page_size)), self.page_size)
        window = results[start : start + limit]

        body: dict[str, Any] = {"results": window}
        if start + limit < len(results):
            # Carrying the context already, unlike `webui` and `downloadLink` — v2 is
            # not consistent about it, and a client that prepended the context to
            # this one would ask for `/wiki/wiki/api/v2`. That inconsistency is a
            # fixture detail worth keeping, because it is the real one.
            #
            # The sort rides along because a cursor is a position *in a result set*,
            # and a result set is defined by its ordering. Real v2 encodes the query
            # into the cursor; dropping it here would page the second request
            # against a differently-ordered list, silently repeating some rows and
            # skipping others — which is exactly the bug an opaque cursor exists to
            # make impossible, so the fake has to model it.
            sort = str(params.get("sort") or "")
            ordering = f"&sort={sort}" if sort else ""
            body["_links"] = {
                "next": (
                    f"/wiki/api/v2{path}?cursor=cursor-{start + limit}&limit={limit}{ordering}"
                )
            }
        return httpx2.Response(200, json=self._with_base(body))

    def _with_base(self, body: dict[str, Any]) -> dict[str, Any]:
        """Add the context base v2 reports alongside a response's other links."""
        if self.link_base:
            body.setdefault("_links", {})["base"] = self.link_base
        return body

    # ─── Lookups ──────────────────────────────────────────────────────────────

    def _space(self, space_id: str) -> Space | None:
        return next((s for s in self.spaces if s.id == space_id), None)

    def _page(self, page_id: str) -> tuple[Space, Page] | None:
        for space in self.spaces:
            for page in space.pages:
                if page.id == page_id:
                    return space, page
        return None

    def _comment(self, comment_id: str) -> Comment | None:
        pending = [
            comment for space in self.spaces for page in space.pages for comment in page.comments
        ]
        while pending:
            comment = pending.pop()
            if comment.id == comment_id:
                return comment
            pending.extend(comment.replies)
        return None

    @staticmethod
    def _comment_payload(comment: Comment) -> dict[str, Any]:
        payload: dict[str, Any] = {"id": comment.id}
        if comment.include_body:
            payload["body"] = {
                comment.body_representation: {
                    "value": comment.storage,
                    "representation": comment.body_representation,
                }
            }
        return payload

    # ─── Convenience ──────────────────────────────────────────────────────────

    @property
    def connection(self) -> dict[str, Any]:
        """The source connection blob for this site, as the API would store it."""
        return {"base_url": SITE, "email": EMAIL}

    def paths_requested(self) -> list[str]:
        return [request.url.path for request in self.requests]

    def cursors_followed(self) -> list[str]:
        """Every cursor value the client sent, in order."""
        cursors: list[str] = []
        for request in self.requests:
            query = parse_qs(urlsplit(str(request.url)).query)
            cursors.extend(query.get("cursor", []))
        return cursors


def _cursor_offset(cursor: Any) -> int:
    if not cursor:
        return 0
    match = _CURSOR.fullmatch(str(cursor))
    return int(match[1]) if match else 0


# ─── Content builders ─────────────────────────────────────────────────────────


def storage_page(*paragraphs: str) -> str:
    """Wrap text in storage-format paragraphs."""
    return "".join(f"<p>{text}</p>" for text in paragraphs)


def storage_code_macro(body: str, *, language: str = "bash") -> str:
    """A `code` macro, CDATA body and all — where a pasted credential lands.

    Written out rather than simplified because the CDATA-inside-`ac:plain-text-body`
    shape is the thing the flattener has to get right, and a simplified version
    would not exercise it.
    """
    return (
        '<ac:structured-macro ac:name="code">'
        f'<ac:parameter ac:name="language">{language}</ac:parameter>'
        f"<ac:plain-text-body><![CDATA[{body}]]></ac:plain-text-body>"
        "</ac:structured-macro>"
    )


def leaky_page_storage() -> str:
    """A page that leaks, in the shape people actually leak things.

    The keyword is prose and the secret is in a code block — adjacent on screen,
    thirty characters of markup apart in the source. That gap is what proximity
    scoring loses if the flattener does not run (ADR 0003), so this fixture is the
    argument for `storage_to_text` existing.
    """
    return storage_page("Deployment runbook", "Set the aws access key before deploying:") + (
        storage_code_macro(f"export AWS_ACCESS_KEY_ID={SEEDED_SECRET}")
    )


def recorded_clients(monkeypatch: pytest.MonkeyPatch) -> list[httpx2.Client]:
    """Every `httpx2.Client` the code under test constructs, as it constructs them.

    A client per request costs a TCP and TLS handshake per request, and an
    in-process transport can never show that — so counting the constructions is the
    only way to assert the pool is held for a scan rather than rebuilt for a page.
    """
    made: list[httpx2.Client] = []
    real = httpx2.Client

    def remember(**kwargs: Any) -> httpx2.Client:
        made.append(real(**kwargs))
        return made[-1]

    monkeypatch.setattr(httpx2, "Client", remember)
    return made


def json_of(response: httpx2.Response) -> dict[str, Any]:
    """Parse a response body, for tests asserting on the fixture itself."""
    parsed = json.loads(response.content)
    assert isinstance(parsed, dict)
    return parsed
