"""Scanning Jira projects for secrets (#144).

Issues, their comments, their attachments and — when an operator opts in — their
field history. The shape of the work is Confluence's, and deliberately so: discover
splits the source into fetch specs, fetch streams content units, and every object
enumerated gets exactly one disposition.

**The locator is coarse and stable, and that is what preserves finding identity.**
A finding's fingerprint is derived from it (ADR 0006), so it is the numeric issue id
— never the key, which changes when an issue moves between projects — and, for a
comment, an attachment or a history entry, an id that survives the next scan.

**Discovery windows a project by ``created``, and that is the resume story.** A
reclaimed task restarts its spec from the top (ADR 0009), so how finely discovery
slices is how much work an interruption costs. ``created`` is immutable, so an issue
can never migrate between windows and a boundary can never cause a skip or a
double-scan on a rescan; windows are contiguous and half-open, so a JQL timezone
shift can move a boundary but cannot open a hole. The bounds come from the project's
own oldest and newest issue rather than from the clock, because the conformance kit
runs ``discover`` twice and compares payloads.

This is **not** checkpointed resume, and the connector does not claim
``ConnectorCapability.CHECKPOINTS`` — that contract belongs to #143. What it buys is
that an interrupted task re-reads one bounded window instead of a whole project.

**A 403 is one object, not the site.** Jira permission schemes are per-project and
per-issue, so being refused one issue's comments is ordinary. It is counted and
stepped over; only a 401 and a rate-limit stop the task. Getting this wrong would
make an ordinary Jira permanently partial, which never reconciles.

**Project keys are validated before they are spliced into JQL.** They come from the
server's own project list, which on a compromised or hostile instance is
attacker-influenced. The operator's configured list is only ever matched against
discovered keys, never spliced.
"""

import re
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from typing import Any, ClassVar

import httpx2
import structlog
from iceberg_core.enums import CoverageObjectKind, CoverageReason
from iceberg_core.fingerprint import CoarseLocator

from iceberg_connectors.extraction import ExtractionLimits, ExtractionOutcome, extract_text
from iceberg_connectors.http import (
    Credential,
    PermissionDenied,
    RateLimited,
    RateLimitPolicy,
)
from iceberg_connectors.jira.client import JiraClient
from iceberg_connectors.jira.document import issue_field_text
from iceberg_connectors.protocol import (
    ConnectorCapability,
    ConnectorError,
    ConnectorMetadata,
    CredentialError,
    FetchOutcome,
    TaskSpec,
)
from iceberg_connectors.sandbox import ExtractionSandbox
from iceberg_connectors.units import ContentOrigin, ContentUnit

logger = structlog.get_logger()

JIRA_CONNECTOR_TYPE = "jira"

#: The fields a scan asks for. Anything not listed never arrives, and
#: ``issue_field_text`` reports an absent field as unread rather than empty — so
#: adding a field here is the only way to scan it, and removing one is visible.
ISSUE_FIELDS = ("summary", "description", "environment", "created", "attachment", "project")

#: The rich-text fields joined into the one BODY unit. ``environment`` earns its
#: place: it is the classic "here are the staging credentials" field.
BODY_FIELDS = ("summary", "description", "environment")

#: A project key as Atlassian defines it. Validated before it reaches JQL, because
#: the list it came from is the server's rather than ours.
_PROJECT_KEY = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,254}$")

#: Bucket widths, in days, tried in order until a project's span fits the window
#: budget. A ladder rather than arithmetic so the choice is reproducible and reads
#: as a calendar rather than as a computed number of hours.
_BUCKET_LADDER = (7, 30, 90, 365, 1825, 3650)

#: More windows than this and discovery is producing more scan tasks than it is
#: saving work; the bucket ladder widens instead.
MAX_WINDOWS_PER_PROJECT = 64

#: Discovery POSTs every spec in one submission, persisted in one transaction.
#: A hundred thousand of them is not a thing to attempt.
MAX_TASK_SPECS = 5_000

#: History entries read per issue. Past it the remainder is a scope gap rather than
#: a silent truncation.
MAX_HISTORY_ENTRIES = 1_000


@dataclass(frozen=True, slots=True)
class _Window:
    """A half-open ``created`` range. ``start`` is None on the first window only."""

    start: str | None
    end: str

    def as_params(self) -> dict[str, Any]:
        return {"field": "created", "from": self.start, "to": self.end}


@dataclass(slots=True)
class _LazySandbox:
    """One extraction child per fetch, and only if an attachment turns up.

    Spawning it with the connector would put a process behind every task including
    the many that never see a file; spawning one per attachment would pay a fork per
    file. Closed in ``fetch``'s ``finally``, so a cancelled generator does not leak.
    """

    factory: Callable[[], ExtractionSandbox] | None
    _sandbox: ExtractionSandbox | None = None

    def get(self) -> ExtractionSandbox | None:
        if self.factory is None:
            return None
        if self._sandbox is None:
            self._sandbox = self.factory()
        return self._sandbox

    def close(self) -> None:
        sandbox, self._sandbox = self._sandbox, None
        if sandbox is not None:
            sandbox.close()


@dataclass(slots=True)
class JiraConnector:
    """Scans a Jira Cloud site through REST v3.

    Stateless between tasks by design — the base URL, the scope, and the credential
    all arrive per call, from the source's connection blob and the task lease. An
    engine holds one instance and runs any number of sources through it (ADR 0009).

    ``transport`` and ``sleep`` exist so tests drive the real client against the
    fixture server in ``packages/connectors/tests/jira_server.py``.
    """

    #: How this connector names its scopes, for the engine's coverage accounting.
    scope_key: ClassVar[str] = "projects"
    scope_param: ClassVar[str] = "project_key"
    #: An issue is a record, not a page.
    body_kind: ClassVar[CoverageObjectKind] = CoverageObjectKind.RECORD

    connector_type: str = JIRA_CONNECTOR_TYPE
    metadata: ConnectorMetadata = field(
        default_factory=lambda: ConnectorMetadata(
            connector_type=JIRA_CONNECTOR_TYPE,
            capabilities=frozenset(
                {
                    ConnectorCapability.DISCOVERY,
                    ConnectorCapability.PAGINATION,
                    ConnectorCapability.ATTACHMENTS,
                    ConnectorCapability.COMMENTS,
                    ConnectorCapability.GAP_REPORTING,
                    # Deliberately not CHECKPOINTS: reserved for #143, and
                    # docs/connector-sdk.md forbids declaring it until that
                    # contract exists.
                }
            ),
        )
    )
    extraction_limits: ExtractionLimits = field(default_factory=ExtractionLimits)
    rate_limit: RateLimitPolicy = field(default_factory=RateLimitPolicy)
    #: A *factory*, not an instance: one connector is shared by every worker thread
    #: and an `ExtractionSandbox` is explicitly not thread-safe (#46). None runs
    #: parsers in-process, which is only ever right in a test.
    sandbox_factory: Callable[[], ExtractionSandbox] | None = ExtractionSandbox
    transport: httpx2.BaseTransport | None = None
    sleep: Callable[[float], None] | None = None

    # ─── Discovery ────────────────────────────────────────────────────────────

    def discover(self, connection: Mapping[str, Any], credential: str | None) -> Iterator[TaskSpec]:
        """Split the source into one spec per project and ``created`` window."""
        client = self._client(connection, credential)
        try:
            wanted = {
                str(value).strip().casefold()
                for value in connection.get("projects") or ()
                if str(value).strip()
            }
            include_archived = bool(connection.get("include_archived_projects"))
            # Project search returns live projects only unless asked otherwise, so
            # the opt-in has to reach the *server*: filtering the response cannot
            # include what was never sent. Stated explicitly even for the default
            # case, so the scope of a scan does not depend on a server-side default
            # changing underneath it. `deleted` is never requested — a project in
            # the trash is not in scope.
            statuses = ["live", "archived"] if include_archived else ["live"]

            matched: dict[str, str] = {}
            malformed = False
            specs = 0

            for project in client.paginate("/project/search", key="values", status=statuses):
                key = str(project.get("key") or "").strip()
                if not key or not _PROJECT_KEY.fullmatch(key):
                    logger.warning("jira_project_without_usable_key")
                    malformed = True
                    continue
                # Belt and braces behind the server-side filter: a deployment that
                # ignores `status` must not silently widen the configured scope.
                if project.get("archived") and not include_archived:
                    continue
                if wanted and key.casefold() not in wanted:
                    continue
                if key.casefold() in matched:
                    logger.warning("jira_duplicate_project")
                    malformed = True
                    continue
                matched[key.casefold()] = key

                for window in self._windows(client, key):
                    specs += 1
                    if specs > MAX_TASK_SPECS:
                        raise ConnectorError(
                            f"Jira discovery produced more than {MAX_TASK_SPECS} task specs; "
                            "narrow the configured projects"
                        )
                    yield TaskSpec(
                        label=f"{key} issues created {window.start or 'start'}…{window.end}",
                        params={"project_key": key, "window": window.as_params()},
                    )

            missing = sorted(wanted - set(matched))
            if missing:
                # Fail closed. A configured project that is not there is a scope the
                # operator believes is covered, and a scan that quietly skipped it
                # would auto-resolve every finding in it.
                raise ConnectorError(f"configured Jira projects were not found: {len(missing)}")
            if malformed:
                raise ConnectorError(
                    "Jira discovery returned malformed or duplicate project identity"
                )
        finally:
            client.close()

    def _windows(self, client: JiraClient, key: str) -> list[_Window]:
        """Bounded, reproducible ``created`` ranges covering one project.

        Derived from the project's own oldest and newest issue, never from the
        clock: the conformance kit runs discovery twice against an unchanged fixture
        and compares payloads, and anything keyed on ``now`` would differ.

        The upper bound is pinned to the newest issue seen at discovery, which gives
        the scan an honest point-in-time meaning — content created after discovery
        belongs to the next scan rather than to a window that silently grew.

        That bound is carried at *minute* precision, not rounded up to the next
        midnight. Rounding would readmit everything created later on the same day:
        a spec built at 09:00 would still match an issue filed at 14:00 whenever the
        fetch task actually ran, which is the opposite of pinned. Intermediate
        boundaries stay calendar-aligned, because they only have to be reproducible.
        """
        oldest = client.search_one(f'project = "{key}" ORDER BY created ASC')
        if oldest is None:
            # A project with no issues is legitimately empty. One spec, no window,
            # so the scope is still enumerated and still counted.
            return [_Window(start=None, end="")]
        newest = client.search_one(f'project = "{key}" ORDER BY created DESC')

        first = _created_at(oldest)
        last = _created_at(newest) if newest is not None else first
        if first is None or last is None:
            raise ConnectorError(f"Jira returned an unreadable created date for project {key}")

        # Exclusive, and one minute past the newest issue so that issue is included
        # and nothing filed after discovery is. JQL resolves to the minute, so this
        # is the tightest bound it can express.
        pinned = last + timedelta(minutes=1)
        start_day, end_day = first.date(), pinned.date() + timedelta(days=1)
        span = max((end_day - start_day).days, 1)
        width = next(
            (days for days in _BUCKET_LADDER if _ceil_div(span, days) <= MAX_WINDOWS_PER_PROJECT),
            _BUCKET_LADDER[-1],
        )

        edges: list[date] = []
        cursor = start_day
        while cursor < end_day:
            cursor = min(cursor + timedelta(days=width), end_day)
            edges.append(cursor)

        windows: list[_Window] = []
        for index, edge in enumerate(edges):
            windows.append(
                _Window(
                    # Open at the bottom, so an issue older than the one we probed —
                    # a timezone shift, a clock skew — cannot fall outside every
                    # window and be silently unscanned.
                    start=None if index == 0 else _stamp(edges[index - 1]),
                    # The final edge is the pinned discovery instant rather than the
                    # calendar day after it.
                    end=_minute(pinned) if index == len(edges) - 1 else _stamp(edge),
                )
            )
        return windows

    # ─── Fetch ────────────────────────────────────────────────────────────────

    def fetch(
        self,
        connection: Mapping[str, Any],
        spec: TaskSpec,
        credential: str | None,
        outcome: FetchOutcome,
    ) -> Iterator[ContentUnit]:
        """Scan the issues one window describes."""
        key = str(spec.params.get("project_key") or "").strip()
        if not key or not _PROJECT_KEY.fullmatch(key):
            raise ConnectorError(f"fetch spec carries no usable project key: {spec.label!r}")

        base_url = str(connection.get("base_url") or "").rstrip("/")
        include_comments = bool(connection.get("include_comments", True))
        include_attachments = bool(connection.get("include_attachments", True))
        include_history = bool(connection.get("include_history", False))

        client = self._client(connection, credential)
        sandbox = _LazySandbox(self.sandbox_factory)
        try:
            for issue in client.search(_jql(key, spec.params.get("window")), fields=ISSUE_FIELDS):
                issue_id = str(issue.get("id") or "")
                if not issue_id:
                    outcome.failed_for(CoverageReason.INVALID_METADATA, CoverageObjectKind.RECORD)
                    continue

                display = _display(base_url, key, issue)
                try:
                    yield from self._body_units(issue, issue_id, display, outcome)
                except CredentialError, RateLimited:
                    # Site-wide. Counting it per issue would re-spend the wait
                    # budget once per issue in the window.
                    raise
                except PermissionDenied:
                    outcome.failed_for(
                        CoverageReason.PERMISSION_DENIED, CoverageObjectKind.RECORD, issue_id
                    )
                    continue
                except ConnectorError:
                    outcome.failed_for(
                        CoverageReason.INVALID_RESPONSE, CoverageObjectKind.RECORD, issue_id
                    )
                    logger.warning("jira_issue_failed")
                    continue

                # The generators are handed over unstarted: no body runs until
                # `_collection` iterates, so every failure still surfaces inside
                # its handler.
                if include_comments:
                    yield from self._collection(
                        self._comment_units(client, issue_id, display, outcome),
                        outcome,
                        key,
                        issue_id,
                        "comments",
                    )
                if include_attachments:
                    yield from self._collection(
                        self._attachment_units(client, issue, issue_id, display, sandbox, outcome),
                        outcome,
                        key,
                        issue_id,
                        "attachments",
                    )
                if include_history:
                    yield from self._collection(
                        self._history_units(client, issue_id, display, outcome),
                        outcome,
                        key,
                        issue_id,
                        "history",
                    )
        finally:
            sandbox.close()
            client.close()

    def _collection(
        self,
        units: Iterator[ContentUnit],
        outcome: FetchOutcome,
        key: str,
        issue_id: str,
        name: str,
    ) -> Iterator[ContentUnit]:
        """Run one sub-collection, turning a whole-collection failure into a gap.

        A collection that failed part-way has an unknowable remaining cardinality,
        so it becomes a scope gap rather than an invented count of failed objects
        (``docs/connector-sdk.md``).
        """
        try:
            yield from units
        except CredentialError, RateLimited:
            raise
        except PermissionDenied:
            outcome.scope_gap_for(
                CoverageReason.PERMISSION_DENIED,
                {"project": key, "issue": issue_id, "collection": name},
            )
        except ConnectorError:
            outcome.scope_gap_for(
                CoverageReason.CONNECTOR_ERROR,
                {"project": key, "issue": issue_id, "collection": name},
            )

    def _body_units(
        self,
        issue: Mapping[str, Any],
        issue_id: str,
        display: dict[str, Any],
        outcome: FetchOutcome,
    ) -> Iterator[ContentUnit]:
        """The issue's own rich text, as one unit.

        If *any* of the body fields is unread the whole issue is failed and nothing
        is yielded: a partial body would let the missing part reconcile a finding
        from an earlier complete scan as though someone had cleared the field.
        """
        fields = issue.get("fields")
        if not isinstance(fields, Mapping):
            raise ConnectorError("issue response carried no fields")

        pieces: list[str] = []
        for name in BODY_FIELDS:
            present, text = issue_field_text(fields, name)
            if not present:
                outcome.failed_for(
                    CoverageReason.INVALID_RESPONSE, CoverageObjectKind.RECORD, issue_id
                )
                return
            if text:
                pieces.append(text)

        body = "\n".join(pieces)
        if not body:
            outcome.skipped_for(CoverageReason.EMPTY_CONTENT, CoverageObjectKind.RECORD, issue_id)
            return

        outcome.scanned_for(CoverageObjectKind.RECORD, issue_id)
        yield ContentUnit(
            locator=CoarseLocator(connector_type=JIRA_CONNECTOR_TYPE, resource_id=issue_id),
            text=body,
            origin=ContentOrigin.BODY,
            display=display,
        )

    def _comment_units(
        self,
        client: JiraClient,
        issue_id: str,
        display: dict[str, Any],
        outcome: FetchOutcome,
    ) -> Iterator[ContentUnit]:
        for comment in client.paginate(f"/issue/{issue_id}/comment", key="comments"):
            comment_id = str(comment.get("id") or "")
            if not comment_id:
                outcome.failed_for(CoverageReason.INVALID_METADATA, CoverageObjectKind.COMMENT)
                continue

            present, text = issue_field_text(comment, "body")
            if not present:
                outcome.failed_for(
                    CoverageReason.INVALID_RESPONSE, CoverageObjectKind.COMMENT, comment_id
                )
                continue
            if not text:
                outcome.skipped_for(
                    CoverageReason.EMPTY_CONTENT, CoverageObjectKind.COMMENT, comment_id
                )
                continue

            outcome.scanned_for(CoverageObjectKind.COMMENT, comment_id)
            yield ContentUnit(
                locator=CoarseLocator(
                    connector_type=JIRA_CONNECTOR_TYPE,
                    resource_id=issue_id,
                    sub_resource=f"comment:{comment_id}",
                ),
                text=text,
                origin=ContentOrigin.COMMENT,
                display=display | {"comment_id": comment_id},
            )

    def _history_units(
        self,
        client: JiraClient,
        issue_id: str,
        display: dict[str, Any],
        outcome: FetchOutcome,
    ) -> Iterator[ContentUnit]:
        """Field values that were set and later changed.

        Only ``toString`` is scanned, plus the *first* ``fromString`` seen for each
        field. Every value a field ever held appears as some entry's ``toString``,
        and entry N's ``fromString`` simply repeats entry N-1's — so scanning both
        would report the same credential twice under two different locators. The one
        value that is not covered is whatever the field held at creation, which is
        exactly the first entry's ``fromString``.
        """
        seen_fields: set[str] = set()
        entries = 0

        for entry in client.paginate(f"/issue/{issue_id}/changelog", key="values"):
            entries += 1
            if entries > MAX_HISTORY_ENTRIES:
                # UNREPORTED rather than SIZE_LIMIT: nothing failed and nothing was
                # too big — the connector simply chose not to read further, and the
                # remaining cardinality is unknown. (The SDK also refuses
                # SIZE_LIMIT on a scope gap; it is a per-object failure reason.)
                outcome.scope_gap_for(
                    CoverageReason.UNREPORTED, {"issue": issue_id, "collection": "history"}
                )
                return

            entry_id = str(entry.get("id") or "")
            items = entry.get("items")
            if not entry_id or not isinstance(items, list):
                outcome.failed_for(CoverageReason.INVALID_METADATA, CoverageObjectKind.RECORD)
                continue

            for item in items:
                if not isinstance(item, Mapping):
                    continue
                field_id = str(item.get("fieldId") or item.get("field") or "").strip()
                if not field_id:
                    continue

                values: list[str] = []
                if field_id not in seen_fields:
                    seen_fields.add(field_id)
                    before = item.get("fromString")
                    if isinstance(before, str) and before:
                        values.append(before)
                after = item.get("toString")
                if isinstance(after, str) and after:
                    values.append(after)

                reference = f"{entry_id}:{field_id}"
                if not values:
                    outcome.skipped_for(
                        CoverageReason.EMPTY_CONTENT, CoverageObjectKind.RECORD, reference
                    )
                    continue

                outcome.scanned_for(CoverageObjectKind.RECORD, reference)
                yield ContentUnit(
                    locator=CoarseLocator(
                        connector_type=JIRA_CONNECTOR_TYPE,
                        resource_id=issue_id,
                        # Both halves are stable in Jira, so a rescan updates the
                        # finding rather than orphaning it and minting a new one.
                        sub_resource=f"history:{entry_id}:{field_id}",
                    ),
                    text="\n".join(values),
                    origin=ContentOrigin.BODY,
                    display=display | {"history_id": entry_id, "field": field_id},
                )

    def _attachment_units(
        self,
        client: JiraClient,
        issue: Mapping[str, Any],
        issue_id: str,
        display: dict[str, Any],
        sandbox: _LazySandbox,
        outcome: FetchOutcome,
    ) -> Iterator[ContentUnit]:
        fields = issue.get("fields")
        attachments = fields.get("attachment") if isinstance(fields, Mapping) else None
        if not isinstance(attachments, list):
            return

        for attachment in attachments:
            if not isinstance(attachment, Mapping):
                continue
            name = str(attachment.get("filename") or "").strip()
            link = str(attachment.get("content") or "").strip()
            reference = str(attachment.get("id") or "") or name or None
            if not name or not link:
                outcome.failed_for(
                    CoverageReason.INVALID_METADATA, CoverageObjectKind.ATTACHMENT, reference
                )
                continue

            declared = attachment.get("size")
            if isinstance(declared, int) and declared > self.extraction_limits.max_input_bytes:
                # Refused before the download: the bytes would be discarded anyway.
                outcome.failed_for(
                    CoverageReason.SIZE_LIMIT, CoverageObjectKind.ATTACHMENT, reference
                )
                continue

            try:
                data = client.get_bytes(link, max_bytes=self.extraction_limits.max_input_bytes)
            except CredentialError, RateLimited:
                raise
            except PermissionDenied:
                outcome.failed_for(
                    CoverageReason.PERMISSION_DENIED, CoverageObjectKind.ATTACHMENT, reference
                )
                continue
            except ConnectorError:
                outcome.failed_for(
                    CoverageReason.CONNECTOR_ERROR, CoverageObjectKind.ATTACHMENT, reference
                )
                continue

            extracted = extract_text(
                data, name, limits=self.extraction_limits, sandbox=sandbox.get()
            )
            if not extracted.outcome.is_text:
                if extracted.outcome.is_incomplete:
                    outcome.failed_for(
                        _incomplete_reason(extracted.outcome),
                        CoverageObjectKind.ATTACHMENT,
                        reference,
                    )
                else:
                    outcome.skipped_for(
                        _skipped_reason(extracted.outcome),
                        CoverageObjectKind.ATTACHMENT,
                        reference,
                    )
                if extracted.outcome.is_hostile:
                    logger.warning("jira_attachment_rejected", outcome=extracted.outcome.value)
                continue

            if extracted.truncated:
                # The text still goes to detection, but the object's single
                # disposition is failed — never both scanned and failed.
                outcome.failed_for(
                    CoverageReason.OUTPUT_LIMIT, CoverageObjectKind.ATTACHMENT, reference
                )
                outcome.units += 1
            else:
                outcome.scanned_for(CoverageObjectKind.ATTACHMENT, reference)

            yield ContentUnit(
                locator=CoarseLocator(
                    connector_type=JIRA_CONNECTOR_TYPE,
                    resource_id=issue_id,
                    # The filename, not the attachment id: replacing a file should
                    # update the finding rather than orphan it and mint a new one.
                    sub_resource=f"attachment:{name}",
                ),
                text=extracted.text,
                origin=ContentOrigin.ATTACHMENT,
                display=display
                | {
                    "filename": name,
                    "media_type": str(attachment.get("mimeType") or ""),
                    "truncated": extracted.truncated,
                },
            )

    # ─── Plumbing ─────────────────────────────────────────────────────────────

    def _client(self, connection: Mapping[str, Any], credential: str | None) -> JiraClient:
        base_url = str(connection.get("base_url") or "").strip()
        if not base_url:
            raise ConnectorError("jira source has no base_url configured")

        email = connection.get("email") or connection.get("username")
        options: dict[str, Any] = {
            "base_url": base_url,
            # An absent credential is legitimate: a site may be anonymously readable.
            "credential": Credential(token=credential, email=str(email) if email else None)
            if credential
            else None,
            "rate_limit": self.rate_limit,
            "transport": self.transport,
        }
        prefix = str(connection.get("api_prefix") or "").strip()
        if prefix:
            options["api_prefix"] = prefix
        if self.sleep is not None:
            options["sleep"] = self.sleep
        return JiraClient(**options)


def _display(base_url: str, key: str, issue: Mapping[str, Any]) -> dict[str, Any]:
    """What an analyst sees, and what a `path_glob` suppression matches on.

    At least one of ``path``/``url``/``space``/``title`` must be present or an
    analyst cannot scope a suppression to this content at all
    (``units.GLOB_FRIENDLY_KEYS``). ``path`` is ``PROJECT/ISSUE-1`` so a glob of
    ``ENG/*`` scopes a whole project.
    """
    fields = issue.get("fields")
    summary = ""
    if isinstance(fields, Mapping) and isinstance(fields.get("summary"), str):
        summary = str(fields["summary"])
    issue_key = str(issue.get("key") or "")
    return {
        "path": f"{key}/{issue_key}" if issue_key else key,
        "url": f"{base_url}/browse/{issue_key}" if base_url and issue_key else "",
        "title": summary,
        "project": key,
        "issue_key": issue_key,
    }


def _jql(key: str, window: Any) -> str:
    """The query for one window. ``key`` is validated by the caller."""
    clauses = [f'project = "{key}"']
    if isinstance(window, Mapping):
        start, end = window.get("from"), window.get("to")
        if isinstance(start, str) and start:
            clauses.append(f'created >= "{start}"')
        if isinstance(end, str) and end:
            clauses.append(f'created < "{end}"')
    # Ordered on the immutable field, so paging stays coherent while issues are
    # being created underneath the scan.
    return " AND ".join(clauses) + " ORDER BY created ASC"


def _created_at(issue: Mapping[str, Any]) -> datetime | None:
    """An issue's ``created`` at minute precision.

    Parsed from the leading ``YYYY-MM-DDTHH:MM`` rather than through a full ISO
    parse: Jira renders the offset as ``+0000`` without a colon, and the offset is
    not wanted anyway — JQL evaluates its literals in the account's own timezone, so
    an offset-aware bound would be comparing two different clocks. Windows are
    contiguous and half-open precisely so that a timezone shift can move a boundary
    without opening a hole.
    """
    fields = issue.get("fields")
    raw = fields.get("created") if isinstance(fields, Mapping) else None
    if not isinstance(raw, str) or len(raw) < 16:
        return None
    try:
        return datetime.strptime(raw[:16], "%Y-%m-%dT%H:%M")
    except ValueError:
        return None


def _stamp(value: date) -> str:
    """A calendar boundary as a JQL datetime literal."""
    return f"{value.isoformat()} 00:00"


def _minute(value: datetime) -> str:
    """A pinned instant as a JQL datetime literal. Minute is all JQL accepts."""
    return value.strftime("%Y-%m-%d %H:%M")


def _ceil_div(numerator: int, denominator: int) -> int:
    return -(-numerator // denominator)


def _incomplete_reason(outcome: ExtractionOutcome) -> CoverageReason:
    if outcome is ExtractionOutcome.REJECTED_TOO_LARGE:
        return CoverageReason.SIZE_LIMIT
    if outcome is ExtractionOutcome.FAILED_TIMEOUT:
        return CoverageReason.TIMEOUT
    return CoverageReason.PARSE_ERROR


def _skipped_reason(outcome: ExtractionOutcome) -> CoverageReason:
    if outcome is ExtractionOutcome.SKIPPED_BINARY:
        return CoverageReason.BINARY_CONTENT
    if outcome is ExtractionOutcome.SKIPPED_EMPTY:
        return CoverageReason.EMPTY_CONTENT
    return CoverageReason.UNSUPPORTED_TYPE
