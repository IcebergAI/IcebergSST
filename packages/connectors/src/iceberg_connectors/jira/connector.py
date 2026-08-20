"""Scanning Jira projects for secrets (#144).

Issues, their comments, their attachments and — when an operator opts in — their
field history. The shape of the work is Confluence's, and deliberately so: discover
splits the source into fetch specs, fetch streams content units, and every object
enumerated gets exactly one disposition.

**The locator is coarse and stable, and that is what preserves finding identity.**
A finding's fingerprint is derived from it (ADR 0006), so it is the numeric issue id
— never the key, which changes when an issue moves between projects — and, for a
comment, an attachment or a history entry, an id that survives the next scan.

**A full scan windows a project by ``created``.** ``created`` is immutable, so an
issue can never migrate between windows and a boundary can never cause a skip or a
double-scan on a rescan; windows are contiguous and half-open, so a JQL timezone
shift can move a boundary but cannot open a hole. The bounds come from the project's
own oldest and newest issue rather than from the clock, because the conformance kit
runs ``discover`` twice and compares payloads.

**Within a window, fetch resumes from the last issue it finished** (#143). The
boundary is a whole issue — body, comments, attachments, history — because a
position taken between an issue's own units would let a reclaimed attempt start at
the next issue and never read the rest of them. JQL resolves to the minute and
orders on the date alone, so the whole boundary minute is re-queried and the
position names the issues actually finished in it. Nothing is skipped without that
evidence: a re-read dedupes on fingerprint, whereas a skipped issue is a secret
nobody reports.

**An incremental scan narrows a project to one ``updated`` window instead.**
``updated`` is mutable, so an issue edited mid-scan moves forward in the order and
is at worst read twice. The upper bound is probed *before* the ``created`` bounds,
so anything created or edited after the probes has an ``updated`` beyond it and is
picked up by the next scan rather than falling between the two. A scan that used a
watermark deliberately never looked at unchanged content, which is why the API
refuses to let one auto-resolve anything (ADR 0013).

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

from iceberg_connectors.extraction import (
    ExtractionLimits,
    LazySandbox,
    coverage_reason,
    extract_text,
)
from iceberg_connectors.http import (
    Credential,
    PermissionDenied,
    RateLimited,
    RateLimitPolicy,
)
from iceberg_connectors.jira.client import JiraClient
from iceberg_connectors.jira.document import issue_field_text
from iceberg_connectors.protocol import (
    Checkpoint,
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
ISSUE_FIELDS = (
    "summary",
    "description",
    "environment",
    "created",
    "updated",
    "attachment",
    "project",
)

#: The rich-text fields joined into the one BODY unit. ``environment`` earns its
#: place: it is the classic "here are the staging credentials" field.
BODY_FIELDS = ("summary", "description", "environment")

#: A project key as Atlassian defines it. Validated before it reaches JQL, because
#: the list it came from is the server's rather than ours.
_PROJECT_KEY = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,254}$")

#: The one shape this connector ever writes as a JQL instant — `_minute`'s output,
#: which is all JQL accepts anyway.
#:
#: Everything spliced into a quoted JQL literal is checked against it, because the
#: window bounds arrive on the lease and the resume point arrives on the
#: checkpoint: both have round-tripped through the API's database since this
#: connector wrote them, and a `"` in one would close the literal and change the
#: query rather than merely fail it (#197). An `isinstance(str)` was the whole
#: check before.
_JQL_INSTANT = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}$")


def _instant(value: object) -> str:
    """``value`` if this connector could have written it, else the empty string.

    A bound that does not survive this is **dropped**, not repaired and not
    fatal: the query widens, so the worst case is re-reading issues that dedupe
    on their fingerprint. That is the same trade the resume logic makes a few
    lines down — re-reading costs a duplicate, skipping costs the secret.
    """
    if isinstance(value, str) and _JQL_INSTANT.fullmatch(value):
        return value
    if value not in (None, ""):
        # Not the value itself: it is stored state of unknown provenance, and this
        # log line crosses the engine boundary.
        logger.warning("jira_discarded_unusable_instant", kind=type(value).__name__)
    return ""


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

#: Issues recorded per boundary minute in a checkpoint. Past it the connector
#: stops publishing until the minute rolls over: the position would otherwise grow
#: without bound, and a resumed attempt re-reading one busy minute is cheap.
MAX_MINUTE_IDS = 2_000

#: This connector's own resume-protocol version, independent of the SDK's (#143).
#: Bump it when the meaning of a stored position changes: the engine discards a
#: checkpoint whose version it does not recognise and restarts the spec, which
#: costs a re-read, whereas misreading one costs coverage.
JIRA_CHECKPOINT_VERSION = "1"


@dataclass(frozen=True, slots=True)
class _Window:
    """A half-open range over one date field.

    ``start`` is None on the first ``created`` window only, so an issue older than
    the one discovery probed cannot fall outside every window. An ``updated``
    window always has both bounds: its lower one is the watermark, and an open
    bottom would make it a full scan wearing an incremental label.
    """

    start: str | None
    end: str
    field: str = "created"

    def as_params(self) -> dict[str, Any]:
        return {"field": self.field, "from": self.start, "to": self.end}


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
                    # Both land with #143. Fetch resumes from an issue boundary it
                    # published, and discovery narrows to an `updated` window when
                    # the API hands back a watermark.
                    ConnectorCapability.CHECKPOINTS,
                    ConnectorCapability.INCREMENTAL,
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

    def discover(
        self,
        connection: Mapping[str, Any],
        credential: str | None,
        *,
        cursors: Mapping[str, Any] | None = None,
    ) -> Iterator[TaskSpec]:
        """Split the source into one spec per project and window.

        A project with no watermark is sliced into ``created`` windows covering all
        of it. A project the API handed a watermark for gets a single ``updated``
        window instead, covering only what changed — which is why a scan that used
        one may never auto-resolve anything (ADR 0013).
        """
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

                # Probed *before* the window bounds, deliberately. Everything this
                # scan cannot see — an issue created after the probes, or edited
                # after them — then has an `updated` strictly greater than the
                # bound, so the next incremental scan picks it up. Probing it last
                # would leave a sliver of content that neither scan covers.
                bound, resume_at = self._cursor_bound(client, key)
                since = _watermark(cursors, key)

                for window in self._windows(client, key, since=since, bound=bound):
                    specs += 1
                    if specs > MAX_TASK_SPECS:
                        raise ConnectorError(
                            f"Jira discovery produced more than {MAX_TASK_SPECS} task specs; "
                            "narrow the configured projects"
                        )
                    params: dict[str, Any] = {
                        "project_key": key,
                        "window": window.as_params(),
                    }
                    if resume_at:
                        # The same value on every spec of this project, so whichever
                        # task reports last proposes the same watermark as the rest.
                        # A minute behind the window's end, on purpose: see
                        # `_cursor_bound`.
                        params["cursor_at"] = resume_at
                    yield TaskSpec(
                        label=(
                            f"{key} issues {window.field} {window.start or 'start'}…{window.end}"
                        ),
                        params=params,
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

    def _cursor_bound(self, client: JiraClient, key: str) -> tuple[str, str]:
        """Where this scan's window ends, and where the next one should start.

        They are deliberately a minute apart. JQL resolves to the minute, so an
        issue edited at 10:00:45 and one edited at 10:00:10 are indistinguishable
        to it. The window has to *end* at 10:01 for the newest issue to be inside
        it — but the next scan must *start* at 10:00, re-reading that minute,
        because an edit landing at 10:00:45 after the probe saw 10:00:10 would
        otherwise fall between the two scans and be read by neither.

        Both are empty for a project with no issues, which proposes no watermark at
        all — there is nothing to have read.

        Derived from the project's own data rather than the clock, like every other
        bound here, because the conformance kit runs discovery twice and compares.
        """
        newest = client.search_one(f'project = "{key}" ORDER BY updated DESC')
        if newest is None:
            return "", ""
        edited = _field_at(newest, "updated") or _field_at(newest, "created")
        if edited is None:
            raise ConnectorError(f"Jira returned an unreadable updated date for project {key}")
        return _minute(edited + timedelta(minutes=1)), _minute(edited)

    def _windows(
        self,
        client: JiraClient,
        key: str,
        *,
        since: str = "",
        bound: str = "",
    ) -> list[_Window]:
        """Bounded, reproducible ranges covering the part of a project in scope.

        With a watermark, that is one ``updated`` window: everything edited since
        the last complete scan. It is a single window rather than a laddered set
        because the changed set is bounded by how often full scans are forced —
        ``Source.full_scan_interval_days`` — and a project cannot accumulate an
        unbounded backlog of edits behind it.

        Without one, the ``created`` ladder below covers the whole project.
        """
        if since and bound:
            if since >= bound:
                # Nothing has been edited since the watermark. No spec at all, so
                # the scan does not enumerate a scope it is not going to read.
                return []
            return [_Window(start=since, end=bound, field="updated")]
        return self._created_windows(client, key)

    def _created_windows(self, client: JiraClient, key: str) -> list[_Window]:
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

        window = spec.params.get("window")
        field = _window_field(window)
        resume = _resume_point(outcome.resume_from, window)
        #: Issues finished at `minute`, which is what a resumed attempt skips on.
        #: Reset whenever the minute rolls over, so it stays small.
        minute = ""
        finished: list[str] = []

        client = self._client(connection, credential)
        sandbox = LazySandbox(self.sandbox_factory)
        try:
            for issue in client.search(
                _jql(key, window, resume_from=resume.at if resume else ""),
                fields=ISSUE_FIELDS,
            ):
                issue_id = str(issue.get("id") or "")
                if not issue_id:
                    outcome.failed_for(CoverageReason.INVALID_METADATA, CoverageObjectKind.RECORD)
                    continue

                if resume is not None and resume.covers(issue, field, issue_id):
                    # Already read and already durably reported by the earlier
                    # attempt. Counting it again would double it in the merged
                    # coverage once the API adds the two attempts together.
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

                # After every unit of this issue, never between them. An issue's
                # comments and attachments are read as one indivisible piece of
                # work, so a boundary inside it would let a resumed attempt skip
                # the rest of them (#143).
                at = _field_at(issue, field)
                if at is not None:
                    stamp = _minute(at)
                    if stamp != minute:
                        minute, finished = stamp, []
                    finished.append(issue_id)
                    # The whole boundary minute is re-queried on resume, so the
                    # position has to name which of its issues were finished. An id
                    # comparison would not do: JQL orders on the date alone, so the
                    # order within a minute is unspecified.
                    if len(finished) <= MAX_MINUTE_IDS:
                        outcome.checkpoint_at(
                            JIRA_CHECKPOINT_VERSION,
                            {"field": field, "at": stamp, "seen": list(finished)},
                        )

            bound = spec.params.get("cursor_at")
            if isinstance(bound, str) and bound:
                # Proposed from the bound discovery pinned rather than from what
                # this task happened to read: the API commits it only if the whole
                # scan completed with complete coverage, so "what I read" and "what
                # the scan read" are the same thing by the time it is stored.
                outcome.cursor_at(key, JIRA_CHECKPOINT_VERSION, {"updated": bound})
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
        sandbox: LazySandbox,
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
                        coverage_reason(extracted.outcome),
                        CoverageObjectKind.ATTACHMENT,
                        reference,
                    )
                else:
                    outcome.skipped_for(
                        coverage_reason(extracted.outcome),
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


#: The only date fields a window may name. Whitelisted rather than validated,
#: because the value is spliced into JQL: a spec is persisted and comes back
#: through a lease, so it is not this process's own string by the time it is used.
_WINDOW_FIELDS = frozenset({"created", "updated"})


def _window_field(window: Any) -> str:
    if isinstance(window, Mapping):
        field = window.get("field")
        if isinstance(field, str) and field in _WINDOW_FIELDS:
            return field
    return "created"


def _jql(key: str, window: Any, *, resume_from: str = "") -> str:
    """The query for one window. ``key`` is validated by the caller.

    Ordered on the window's own field so paging stays coherent while the project
    is written to underneath the scan. For a ``created`` window that field is
    immutable and the order is stable outright; for an ``updated`` window an issue
    edited mid-scan moves *forward* in the order, so the worst case is reading it
    twice rather than missing it.
    """
    field = _window_field(window)
    clauses = [f'project = "{key}"']
    bounded = window if isinstance(window, Mapping) else {}
    # Validated, not merely typed: each of these is spliced into a quoted literal
    # and each arrives from stored state (#197).
    start = _instant(bounded.get("from"))
    end = _instant(bounded.get("to"))
    if resumed := _instant(resume_from):
        # A resumed attempt starts at the boundary the last one published rather
        # than at the window's own start. `>=` and not `>`: JQL resolves to the
        # minute, so several issues can share the boundary value, and excluding
        # them would skip whichever ones had not been read.
        start = resumed
    if start:
        clauses.append(f'{field} >= "{start}"')
    if end:
        clauses.append(f'{field} < "{end}"')
    return " AND ".join(clauses) + f" ORDER BY {field} ASC"


@dataclass(frozen=True, slots=True)
class _Resume:
    """A point a previous attempt of this task reached (#143)."""

    at: str
    #: The issues the earlier attempt actually finished at minute :attr:`at`.
    seen: frozenset[str]

    def covers(self, issue: Mapping[str, Any], field: str, issue_id: str) -> bool:
        """Whether the earlier attempt already reported this issue.

        The query re-includes the whole boundary minute, because JQL resolves to
        the minute and a busy project puts many issues in one. Deciding which of
        them to skip needs **positive evidence**, and the only evidence there is is
        the list of ids the earlier attempt recorded having finished.

        An earlier version compared numeric ids instead, on the theory that a lower
        id was read first. Jira orders on the date alone, so the order within a
        minute is unspecified: an issue with a lower id can be delivered *after*
        the one the checkpoint names, and would then be skipped having never been
        read. Re-reading costs a duplicate that dedupes on fingerprint; skipping
        costs the secret.
        """
        if issue_id not in self.seen:
            return False
        stamp = _field_at(issue, field)
        return stamp is not None and _minute(stamp) == self.at


def _resume_point(checkpoint: Checkpoint | None, window: Any) -> _Resume | None:
    """The resume point on the lease, if this build can still act on it."""
    if checkpoint is None or checkpoint.version != JIRA_CHECKPOINT_VERSION:
        return None
    position = checkpoint.position
    at, seen = _instant(position.get("at")), position.get("seen")
    if not at or not isinstance(seen, list) or not seen:
        # Includes a position written before the boundary minute was recorded as a
        # set of ids, and one whose instant is not a shape this connector writes.
        # Unusable is not the same as empty: restart the spec.
        return None
    if position.get("field") != _window_field(window):
        # A position taken over `created` cannot bound an `updated` window: the
        # two orderings have nothing to do with each other, and resuming across
        # them would skip whatever happens to sort earlier under the new field.
        return None
    return _Resume(at=at, seen=frozenset(str(item) for item in seen))


def _watermark(cursors: Mapping[str, Any] | None, key: str) -> str:
    """The ``updated`` instant this project was last completely scanned through."""
    if not cursors:
        return ""
    position = cursors.get(key)
    if not isinstance(position, Mapping):
        return ""
    # Same validation as every other stored instant: an unusable watermark means
    # a full window rather than a query built around it.
    return _instant(position.get("updated"))


def _field_at(issue: Mapping[str, Any], field: str) -> datetime | None:
    """One of an issue's date fields at minute precision. See `_created_at`."""
    fields = issue.get("fields")
    raw = fields.get(field) if isinstance(fields, Mapping) else None
    if not isinstance(raw, str) or len(raw) < 16:
        return None
    try:
        return datetime.strptime(raw[:16], "%Y-%m-%dT%H:%M")
    except ValueError:
        return None


def _created_at(issue: Mapping[str, Any]) -> datetime | None:
    """An issue's ``created`` at minute precision.

    Parsed from the leading ``YYYY-MM-DDTHH:MM`` rather than through a full ISO
    parse: Jira renders the offset as ``+0000`` without a colon, and the offset is
    not wanted anyway — JQL evaluates its literals in the account's own timezone, so
    an offset-aware bound would be comparing two different clocks. Windows are
    contiguous and half-open precisely so that a timezone shift can move a boundary
    without opening a hole.
    """
    return _field_at(issue, "created")


def _stamp(value: date) -> str:
    """A calendar boundary as a JQL datetime literal."""
    return f"{value.isoformat()} 00:00"


def _minute(value: datetime) -> str:
    """A pinned instant as a JQL datetime literal. Minute is all JQL accepts."""
    return value.strftime("%Y-%m-%d %H:%M")


def _ceil_div(numerator: int, denominator: int) -> int:
    return -(-numerator // denominator)
