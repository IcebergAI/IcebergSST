"""An in-process Jira Cloud site, for connector tests (#144).

Not a mock: it really pages with real opaque tokens, really evaluates the narrow
slice of JQL the connector emits, really checks the ``Authorization`` header, and
really throttles. A double that could not refuse one issue while answering the next
would only ever prove the happy path — and "one issue is restricted" is the case
that separates a Jira connector from a Confluence one.

Recorded fixtures were rejected for the same reasons they were for Confluence
(``confluence_server.py``): there is no live site to record from in CI, cursors are
stateful, and 429 is a behaviour rather than a payload.

**This does not validate against Atlassian's OpenAPI schema.** A field Atlassian
renames passes here and fails in production. The endpoints modelled below were
written against the published v3 documentation; treat this as a contract with our
own understanding of Jira, not with Jira.

Two documented Atlassian defects are modelled as knobs rather than assumed away,
because a scanner has to survive them: ``repeat_page_token`` reproduces the search
token that never advances (JRACLOUD-94632) and ``never_last`` the ``isLast`` that
never flips true (JRACLOUD-94648).
"""

import base64
import re
from dataclasses import dataclass, field
from typing import Any

import httpx2

SITE = "https://jira.example.test"
EMAIL = "scanner@example.test"
API_TOKEN = "cloud-api-token"
#: A Server/DC personal access token, sent as a bearer rather than as Basic.
PAT = "datacenter-personal-access-token"

#: AWS's own documented example key — a real detector hit that is safe to commit.
SEEDED_SECRET = "AKIAIOSFODNN7EXAMPLE"

API_PREFIX = "/rest/api/3"


def adf(*paragraphs: str) -> dict[str, Any]:
    """An ADF document carrying one paragraph per argument."""
    return {
        "type": "doc",
        "version": 1,
        "content": [
            {"type": "paragraph", "content": [{"type": "text", "text": text}]}
            for text in paragraphs
        ],
    }


def leaky_description() -> dict[str, Any]:
    """A description with the keyword in prose and the value in a code block.

    The shape that justifies flattening at all: proximity scoring needs "password"
    and the value to survive into the same neighbourhood (ADR 0003).
    """
    return {
        "type": "doc",
        "version": 1,
        "content": [
            {
                "type": "paragraph",
                "content": [{"type": "text", "text": "the deploy password is below"}],
            },
            {
                "type": "codeBlock",
                "attrs": {"language": "bash"},
                "content": [{"type": "text", "text": f"AWS_ACCESS_KEY_ID={SEEDED_SECRET}"}],
            },
        ],
    }


@dataclass(slots=True)
class Attachment:
    id: str
    filename: str
    body: bytes = b""
    mime_type: str = "text/plain"
    #: What the payload *claims*, which a client must not trust over what it reads.
    declared_size: int | None = None
    #: Omit `content`, the download URL — metadata a real site occasionally lacks.
    include_content: bool = True
    download_status: int = 200

    def as_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "id": self.id,
            "filename": self.filename,
            "mimeType": self.mime_type,
            "size": self.declared_size if self.declared_size is not None else len(self.body),
        }
        if self.include_content:
            payload["content"] = f"{SITE}/secure/attachment/{self.id}/{self.filename}"
        return payload


@dataclass(slots=True)
class Comment:
    id: str
    body: Any = None
    #: Omit `body` entirely — unread content, which must not read as an empty comment.
    include_body: bool = True

    def as_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"id": self.id, "created": "2024-06-01T10:00:00.000+0000"}
        if self.include_body:
            payload["body"] = self.body if self.body is not None else adf("a comment")
        return payload


@dataclass(slots=True)
class Change:
    """One changelog entry: a set of field transitions recorded together."""

    id: str
    field_id: str = "description"
    from_string: str | None = None
    to_string: str | None = None

    def as_payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "created": "2024-06-02T10:00:00.000+0000",
            "items": [
                {
                    "field": self.field_id,
                    "fieldId": self.field_id,
                    "fromString": self.from_string,
                    "toString": self.to_string,
                }
            ],
        }


@dataclass(slots=True)
class Issue:
    id: str
    key: str
    #: `YYYY-MM-DDTHH:MM`, the ordering and windowing field. Immutable in Jira, which
    #: is why the connector windows on it.
    created: str = "2024-01-01T00:00"
    summary: str = "an issue"
    description: Any = None
    environment: Any = None
    #: Drop `description` from `fields` altogether — a screen scheme that does not
    #: carry it. Unread, not empty.
    include_description: bool = True
    comments: list[Comment] = field(default_factory=list)
    attachments: list[Attachment] = field(default_factory=list)
    changes: list[Change] = field(default_factory=list)

    def as_payload(self, project_key: str) -> dict[str, Any]:
        fields: dict[str, Any] = {
            "summary": self.summary,
            "created": f"{self.created}:00.000+0000",
            "environment": self.environment,
            "attachment": [a.as_payload() for a in self.attachments],
            "project": {"key": project_key},
        }
        if self.include_description:
            fields["description"] = self.description
        return {"id": self.id, "key": self.key, "fields": fields}


@dataclass(slots=True)
class Project:
    id: str
    key: str
    name: str = "A project"
    archived: bool = False
    issues: list[Issue] = field(default_factory=list)

    def as_payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "key": self.key,
            "name": self.name,
            "archived": self.archived,
        }


_PROJECT_CLAUSE = re.compile(r'project\s*=\s*"([^"]+)"', re.IGNORECASE)
_FROM_CLAUSE = re.compile(r'created\s*>=\s*"([^"]+)"', re.IGNORECASE)
_TO_CLAUSE = re.compile(r'created\s*<\s*"([^"]+)"', re.IGNORECASE)
_ORDER_CLAUSE = re.compile(r"ORDER\s+BY\s+created\s+(ASC|DESC)", re.IGNORECASE)


@dataclass(slots=True)
class FakeJira:
    """A Jira Cloud site that answers REST v3 over an in-process transport."""

    projects: list[Project] = field(default_factory=list)
    #: Results per page. Small by default so two pages of results need two pages,
    #: not two hundred rows of fixture.
    page_size: int = 2
    #: Reject everything until this many requests have been made.
    throttle_first: int = 0
    #: Seconds the throttled response asks for. None omits `Retry-After`.
    retry_after: float | None = 1.0
    require_credential: bool = True
    #: Accept a bearer PAT instead of Basic — the Server/DC credential shape.
    accept_bearer: bool = False
    #: Paths containing any of these answer 401 — a revoked or wrong token, which is
    #: site-wide and must stop the task.
    unauthorized_paths: tuple[str, ...] = ()
    #: Paths containing any of these answer 403 — this object only. Routine in Jira,
    #: and the scan must count it and carry on.
    forbidden_paths: tuple[str, ...] = ()
    failing_paths: tuple[str, ...] = ()
    throttled_paths: tuple[str, ...] = ()
    #: Hand back a token that never advances (JRACLOUD-94632).
    repeat_page_token: bool = False
    #: Never set `isLast` true (JRACLOUD-94648).
    never_last: bool = False
    #: Answer issue search with the Data Center offset bean instead.
    offset_shaped_search: bool = False

    requests: list[httpx2.Request] = field(default_factory=list)
    throttled: int = 0

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
            return httpx2.Response(401, json={"errorMessages": ["unauthorized"]})
        if any(fragment in path for fragment in self.unauthorized_paths):
            return httpx2.Response(401, json={"errorMessages": ["token rejected"]})
        if any(fragment in path for fragment in self.forbidden_paths):
            return httpx2.Response(403, json={"errorMessages": ["no permission for this issue"]})
        if any(fragment in path for fragment in self.throttled_paths):
            return self._throttle()
        if any(fragment in path for fragment in self.failing_paths):
            return httpx2.Response(500, json={"errorMessages": ["internal error"]})

        if path.startswith("/secure/attachment/"):
            return self._download(path)
        if not path.startswith(f"{API_PREFIX}/"):
            return httpx2.Response(404, json={"errorMessages": ["no such endpoint"]})

        return self._api(path.removeprefix(API_PREFIX), dict(request.url.params))

    def _throttle(self) -> httpx2.Response:
        headers = {} if self.retry_after is None else {"Retry-After": str(self.retry_after)}
        return httpx2.Response(429, headers=headers, json={"errorMessages": ["rate limited"]})

    def _authorized(self, request: httpx2.Request) -> bool:
        header = request.headers.get("authorization", "")
        if self.accept_bearer and header == f"Bearer {PAT}":
            return True
        if not header.startswith("Basic "):
            return False
        try:
            decoded = base64.b64decode(header.removeprefix("Basic ")).decode()
        except ValueError, UnicodeDecodeError:
            return False
        return decoded == f"{EMAIL}:{API_TOKEN}"

    # ─── Endpoints ────────────────────────────────────────────────────────────

    def _api(self, path: str, params: dict[str, Any]) -> httpx2.Response:
        if path == "/myself":
            return httpx2.Response(200, json={"accountId": "1", "emailAddress": EMAIL})

        if path == "/project/search":
            live = [p for p in self.projects if not p.archived]
            return self._offset([p.as_payload() for p in live], "values", params)

        if path == "/search/jql":
            return self._search(params)

        if match := re.fullmatch(r"/issue/([^/]+)/comment", path):
            issue = self._issue(match[1])
            if issue is None:
                return httpx2.Response(404, json={"errorMessages": ["no such issue"]})
            return self._offset([c.as_payload() for c in issue.comments], "comments", params)

        if match := re.fullmatch(r"/issue/([^/]+)/changelog", path):
            issue = self._issue(match[1])
            if issue is None:
                return httpx2.Response(404, json={"errorMessages": ["no such issue"]})
            return self._offset([c.as_payload() for c in issue.changes], "values", params)

        return httpx2.Response(404, json={"errorMessages": ["no such endpoint"]})

    def _search(self, params: dict[str, Any]) -> httpx2.Response:
        matching = self._matching(str(params.get("jql", "")))
        limit = min(int(params.get("maxResults", self.page_size)), self.page_size)

        start = 0
        token = params.get("nextPageToken")
        if isinstance(token, str) and token.startswith("tok-"):
            start = int(token.removeprefix("tok-"))

        if self.offset_shaped_search:
            # What Data Center serves: the older bean, with a total and no token.
            page = matching[start : start + limit]
            return httpx2.Response(
                200,
                json={
                    "startAt": start,
                    "maxResults": limit,
                    "total": len(matching),
                    "issues": page,
                },
            )

        page = matching[start : start + limit]
        payload: dict[str, Any] = {"issues": page}
        nxt = start + len(page)
        if nxt < len(matching):
            payload["nextPageToken"] = f"tok-{start if self.repeat_page_token else nxt}"
            payload["isLast"] = False
        elif self.never_last:
            payload["isLast"] = False
        else:
            payload["isLast"] = True
        return httpx2.Response(200, json=payload)

    def _matching(self, jql: str) -> list[dict[str, Any]]:
        """Evaluate the narrow slice of JQL the connector actually emits."""
        wanted = _PROJECT_CLAUSE.search(jql)
        lower = _FROM_CLAUSE.search(jql)
        upper = _TO_CLAUSE.search(jql)

        rows: list[tuple[str, dict[str, Any]]] = []
        for project in self.projects:
            if wanted and project.key.casefold() != wanted[1].casefold():
                continue
            for issue in project.issues:
                stamp = issue.created.replace("T", " ")
                if lower and stamp < lower[1]:
                    continue
                if upper and stamp >= upper[1]:
                    continue
                rows.append((stamp, issue.as_payload(project.key)))

        order = _ORDER_CLAUSE.search(jql)
        rows.sort(key=lambda row: row[0], reverse=bool(order and order[1].upper() == "DESC"))
        return [payload for _stamp, payload in rows]

    def _offset(
        self, values: list[dict[str, Any]], key: str, params: dict[str, Any]
    ) -> httpx2.Response:
        start = int(params.get("startAt", 0))
        limit = min(int(params.get("maxResults", self.page_size)), self.page_size)
        page = values[start : start + limit]
        last = start + len(page) >= len(values)
        return httpx2.Response(
            200,
            json={
                "startAt": start,
                "maxResults": limit,
                "total": len(values),
                "isLast": False if self.never_last else last,
                key: page,
            },
        )

    def _download(self, path: str) -> httpx2.Response:
        match = re.fullmatch(r"/secure/attachment/([^/]+)/.*", path)
        if match is None:
            return httpx2.Response(404, json={"errorMessages": ["no such attachment"]})
        for project in self.projects:
            for issue in project.issues:
                for attachment in issue.attachments:
                    if attachment.id == match[1]:
                        if attachment.download_status != 200:
                            return httpx2.Response(attachment.download_status)
                        return httpx2.Response(200, content=attachment.body)
        return httpx2.Response(404, json={"errorMessages": ["no such attachment"]})

    # ─── Lookups ──────────────────────────────────────────────────────────────

    def _issue(self, identifier: str) -> Issue | None:
        for project in self.projects:
            for issue in project.issues:
                if identifier in (issue.id, issue.key):
                    return issue
        return None

    @property
    def connection(self) -> dict[str, Any]:
        return {"base_url": SITE, "email": EMAIL}

    def paths_requested(self) -> list[str]:
        return [request.url.path for request in self.requests]
