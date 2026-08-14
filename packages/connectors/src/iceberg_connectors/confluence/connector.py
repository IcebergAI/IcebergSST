"""The Confluence connector (#47, #48, #49 — ADR 0002, 0009).

The first real source. Two phases, as the protocol requires:

* :meth:`ConfluenceConnector.discover` enumerates spaces the scope allows and
  returns one :class:`TaskSpec` per space, so a fifty-space site is fifty tasks
  that engines pick up in parallel rather than one that runs for a day.
* :meth:`ConfluenceConnector.fetch` walks one space, yielding a unit per page
  body, per comment, and per text-extractable attachment.

**One space per task, not one page.** Pages are discovered lazily inside the fetch,
because discovery would otherwise have to page through every page of every space
before a single one is scanned — turning the fastest part of a scan into a serial
prologue, and producing a task table with a row per page.

**The locator is the part that has to be right.** A finding's identity is computed
from it (ADR 0006), so it is the page id and — for a comment or an attachment —
that part's own id. Never the title, which people edit; never the URL, which
carries the title; never the version. Get it wrong and every re-scan orphans the
analyst's triage decisions while looking like it worked (see
:mod:`iceberg_connectors.units`).

**One bad page must not stop a scan of fifty thousand.** Every per-page failure
below is counted into :class:`FetchOutcome` and stepped over so findings from
readable neighbors survive. The engine nevertheless fails that fetch task and the
API marks the scan partial: unread content cannot justify auto-resolving an older
finding or sending completion notifications. Bad credentials and site-wide
failures abort immediately because no later unit can recover from them.
"""

from collections import deque
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Any, ClassVar

import httpx2
import structlog
from iceberg_core.enums import CoverageObjectKind, CoverageReason
from iceberg_core.fingerprint import CoarseLocator

from iceberg_connectors.confluence.client import (
    ConfluenceClient,
    Credential,
    DownloadTooLarge,
    RateLimited,
    RateLimitPolicy,
)
from iceberg_connectors.confluence.storage import storage_to_text, supported_body_text
from iceberg_connectors.extraction import ExtractionLimits, ExtractionOutcome, extract_text
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

CONFLUENCE_CONNECTOR_TYPE = "confluence"

#: Comment endpoints on a v2 page. Both are scanned: an inline comment on a
#: paragraph is where someone answers "what's the password for staging?".
COMMENT_ENDPOINTS = ("footer-comments", "inline-comments")


@dataclass(slots=True)
class ConfluenceConnector:
    """Scans a Confluence Cloud site through REST v2.

    Stateless between tasks by design — the base URL, the scope, and the credential
    all arrive per call, from the source's connection blob and the task lease. An
    engine holds one instance and runs any number of sources through it (ADR 0009).

    ``transport`` and ``sleep`` exist so tests drive the real client against the
    fixture server in ``packages/connectors/tests/confluence_server.py`` (#71).
    """

    #: How this connector names its scopes: the connection-blob key an operator
    #: fills in, and the ``TaskSpec.params`` key a discovered scope comes back
    #: under. The engine reads both to reconcile "requested" against "discovered"
    #: without knowing what a space is (``runner._scope_keys``).
    scope_key: ClassVar[str] = "spaces"
    scope_param: ClassVar[str] = "space_key"
    #: What a ``ContentOrigin.BODY`` unit is, for coverage accounting.
    body_kind: ClassVar[CoverageObjectKind] = CoverageObjectKind.PAGE

    connector_type: str = CONFLUENCE_CONNECTOR_TYPE
    metadata: ConnectorMetadata = field(
        default_factory=lambda: ConnectorMetadata(
            connector_type=CONFLUENCE_CONNECTOR_TYPE,
            capabilities=frozenset(
                {
                    ConnectorCapability.DISCOVERY,
                    ConnectorCapability.PAGINATION,
                    ConnectorCapability.ATTACHMENTS,
                    ConnectorCapability.COMMENTS,
                    ConnectorCapability.GAP_REPORTING,
                }
            ),
        )
    )
    extraction_limits: ExtractionLimits = field(default_factory=ExtractionLimits)
    rate_limit: RateLimitPolicy = field(default_factory=RateLimitPolicy)
    #: Makes the child process attachment parsers run in. A *factory*, not an
    #: instance: one connector is shared by every worker thread, and an
    #: `ExtractionSandbox` is explicitly not thread-safe — sharing one would let a
    #: hostile file in one task kill the extraction of another (#46). Setting it to
    #: None runs parsers in-process, which is only ever right in a test.
    sandbox_factory: Callable[[], ExtractionSandbox] | None = ExtractionSandbox
    transport: httpx2.BaseTransport | None = None
    #: Injected only by tests, so a backoff assertion costs no wall-clock. None
    #: leaves the client on `time.sleep`.
    sleep: Callable[[float], None] | None = None

    # ─── Discovery ────────────────────────────────────────────────────────────

    def discover(self, connection: dict[str, Any], credential: str | None) -> Iterator[TaskSpec]:
        """One spec per space the scope allows.

        Yielding nothing is a legitimate answer — a site with no spaces, or a scope
        that matches none. The scan completes having scanned nothing, and
        reconciliation refuses to auto-resolve on that evidence alone (ADR 0009 §4).
        """
        client = self._client(connection, credential)
        # Casefolded on both sides: space keys are conventionally uppercase, and an
        # operator who typed `docs` for the DOCS space would otherwise get zero task
        # specs and a scan that completes looking clean — the silent empty scan,
        # which is the failure this codebase treats as the dangerous one.
        wanted = {str(key).casefold() for key in connection.get("spaces") or ()}
        matched: set[str] = set()
        matched_ids: set[str] = set()
        seen = 0
        malformed = False

        try:
            for space in client.paginate("/spaces", **_space_filters(connection)):
                key = str(space.get("key") or "")
                if wanted and key.casefold() not in wanted:
                    continue
                space_id = str(space.get("id") or "")
                if not space_id:
                    # Nothing can be fetched without it, and guessing would produce a
                    # task that fails later with a much less obvious message.
                    logger.warning("confluence_space_without_id", space_key=key)
                    malformed = True
                    continue

                normalized_key = key.casefold()
                if normalized_key in matched or space_id in matched_ids:
                    # Mutable cursor pagination can repeat a row, and a broken
                    # deployment can reuse a key/id for different rows. Creating
                    # duplicate fetch tasks would make requested/discovered scope
                    # irreconcilable, so preserve the first spec and fail closed.
                    logger.warning("confluence_duplicate_space")
                    malformed = True
                    continue

                matched.add(normalized_key)
                matched_ids.add(space_id)
                seen += 1
                yield TaskSpec(
                    label=f"space {key or space_id}",
                    params={
                        "space_id": space_id,
                        "space_key": key,
                        "space_name": space.get("name"),
                    },
                )

            if missing := sorted(wanted - matched):
                # The scope named spaces this site did not make fetchable. Matched
                # specs have already been yielded and the runner preserves them,
                # but discovery must fail so the eventual scan remains partial and
                # cannot reconcile unread content as remediated.
                logger.warning("confluence_spaces_not_found", spaces=missing)
                raise ConnectorError(
                    "configured Confluence spaces were not found: " + ", ".join(missing)
                )
            if malformed:
                raise ConnectorError(
                    "Confluence discovery returned malformed or duplicate space identity"
                )
            logger.info("confluence_discovery_complete", spaces=seen, filtered=bool(wanted))
        finally:
            # Reached on an abandoned generator too, so a discovery that stops early
            # does not leak the connection pool.
            client.close()

    # ─── Fetch ────────────────────────────────────────────────────────────────

    def fetch(
        self,
        connection: dict[str, Any],
        spec: TaskSpec,
        credential: str | None,
        outcome: FetchOutcome,
    ) -> Iterator[ContentUnit]:
        """Every scannable unit in one space: bodies, comments, attachments."""
        client = self._client(connection, credential)
        space_id = str(spec.params.get("space_id") or "")
        if not space_id:
            raise ConnectorError(f"fetch spec carries no space_id: {spec.label!r}")

        context = _SpaceContext(
            key=str(spec.params.get("space_key") or ""),
            name=spec.params.get("space_name"),
        )
        want_comments = connection.get("include_comments", True)
        want_attachments = connection.get("include_attachments", True)
        sandbox = _LazySandbox(self.sandbox_factory)

        try:
            for page in client.paginate(f"/spaces/{space_id}/pages", **_body_format()):
                page_id = str(page.get("id") or "")
                if not page_id:
                    outcome.failed_for(
                        CoverageReason.INVALID_METADATA,
                        CoverageObjectKind.PAGE,
                        None,
                    )
                    continue

                try:
                    page, text = self._body(client, page, page_id)
                    # Built once per page, from the page. Everything on a page —
                    # its comments, its attachments — shares the page's path, so
                    # one `path_glob` covers the page and its parts (#44).
                    here = context.for_page(page, page_id, client.resolve)

                except CredentialError, RateLimited:
                    # Neither is about this page. A bad token is bad for the whole
                    # site, and a site throttling past `max_wait_seconds` will
                    # throttle the next page too — counting that as a per-page
                    # failure spends the wait budget again on every one of fifty
                    # thousand pages while the task sits on its lease for hours.
                    # Failing tells the operator what to change: rotate the token,
                    # or run fewer engines.
                    raise
                except ConnectorError as exc:
                    # The page body itself was enumerated but unreadable. Its child
                    # collections were never requested, so they are not fabricated
                    # into the object totals.
                    outcome.failed_for(
                        CoverageReason.INVALID_RESPONSE,
                        CoverageObjectKind.PAGE,
                        page_id,
                    )
                    logger.warning("confluence_page_failed", page_id=page_id, error=str(exc))
                    continue

                yield from self._page_units(text, page_id, here, outcome)
                if want_comments:
                    try:
                        yield from self._comment_units(client, page_id, here, outcome)
                    except CredentialError, RateLimited:
                        raise
                    except ConnectorError as exc:
                        # The collection failed before its remaining object count was
                        # knowable. Record a scope gap, not a made-up failed comment.
                        outcome.scope_gap_for(
                            CoverageReason.CONNECTOR_ERROR,
                            {"page": page_id, "collection": "comments"},
                        )
                        logger.warning(
                            "confluence_comments_failed", page_id=page_id, error=str(exc)
                        )
                if want_attachments:
                    try:
                        yield from self._attachment_units(client, page_id, here, outcome, sandbox)
                    except CredentialError, RateLimited:
                        raise
                    except ConnectorError as exc:
                        outcome.scope_gap_for(
                            CoverageReason.CONNECTOR_ERROR,
                            {"page": page_id, "collection": "attachments"},
                        )
                        logger.warning(
                            "confluence_attachments_failed", page_id=page_id, error=str(exc)
                        )
        finally:
            # Reached on a cancelled task too: closing a generator runs this, so an
            # abandoned fetch does not leak the child process (ADR 0009 §4) or the
            # connection pool.
            sandbox.close()
            client.close()

    def _body(
        self, client: ConfluenceClient, page: dict[str, Any], page_id: str
    ) -> tuple[dict[str, Any], str]:
        """The page payload and its flattened text.

        The list endpoint returns bodies when asked, so this normally costs no
        extra request. It falls back to fetching the page when a deployment answers
        without one rather than skipping the most likely place for a secret — and
        returns the merged payload, because that response also carries the `webui`
        link every unit on the page needs for its display path.
        """
        supported, text = supported_body_text(page)
        if supported:
            return page, text

        detail = client.get_json(client.url(f"/pages/{page_id}"), params=_body_format())
        supported, text = supported_body_text(detail)
        if not supported:
            raise ConnectorError("page response omitted a supported body representation")
        return {**page, **detail}, text

    def _page_units(
        self, text: str, page_id: str, context: _PageContext, outcome: FetchOutcome
    ) -> Iterator[ContentUnit]:
        """The page body, if it has any text."""
        if not text:
            outcome.skipped_for(
                CoverageReason.EMPTY_CONTENT,
                CoverageObjectKind.PAGE,
                page_id,
            )
            return

        outcome.scanned_for(CoverageObjectKind.PAGE, page_id)
        yield ContentUnit(
            locator=CoarseLocator(connector_type=self.connector_type, resource_id=page_id),
            text=text,
            origin=ContentOrigin.BODY,
            display=context.display(),
        )

    def _comment_units(
        self,
        client: ConfluenceClient,
        page_id: str,
        context: _PageContext,
        outcome: FetchOutcome,
    ) -> Iterator[ContentUnit]:
        """Footer and inline comments, each its own unit.

        Separate units rather than appended to the body, because they are separate
        things to fix: a secret in a comment is deleted by its author, a secret in
        the body is edited out of the page. Merging them would also make one
        person's comment change the body's fingerprint.
        """
        for endpoint in COMMENT_ENDPOINTS:
            pending: deque[dict[str, Any]] = deque()
            seen: set[str] = set()
            for comment in client.paginate(f"/pages/{page_id}/{endpoint}", **_body_format()):
                comment_id = str(comment.get("id") or "")
                if not comment_id:
                    outcome.failed_for(
                        CoverageReason.INVALID_METADATA,
                        CoverageObjectKind.COMMENT,
                        None,
                    )
                    continue
                if comment_id in seen:
                    continue
                seen.add(comment_id)
                pending.append(comment)

            # Page collections return roots only. Every comment type has its own
            # cursor-paginated children endpoint, and replies may themselves have
            # children. An iterative walk avoids recursion depth becoming a remote
            # input while ``seen`` prevents a broken API response from cycling.
            while pending:
                comment = pending.popleft()
                comment_id = str(comment["id"])
                supported, text = supported_body_text(comment)

                if not supported:
                    outcome.failed_for(
                        CoverageReason.INVALID_RESPONSE,
                        CoverageObjectKind.COMMENT,
                        comment_id,
                    )
                    logger.warning(
                        "confluence_comment_missing_body",
                        comment_id=comment_id,
                    )
                elif text:
                    outcome.scanned_for(CoverageObjectKind.COMMENT, comment_id)
                    yield ContentUnit(
                        locator=CoarseLocator(
                            connector_type=self.connector_type,
                            resource_id=page_id,
                            # The comment's own id: editing the page must not change
                            # a comment finding's identity, or vice versa.
                            sub_resource=f"comment:{comment_id}",
                        ),
                        text=text,
                        origin=ContentOrigin.COMMENT,
                        display=context.display() | {"comment_id": comment_id},
                    )
                else:
                    outcome.skipped_for(
                        CoverageReason.EMPTY_CONTENT,
                        CoverageObjectKind.COMMENT,
                        comment_id,
                    )

                for reply in client.paginate(
                    f"/{endpoint}/{comment_id}/children", **_body_format()
                ):
                    reply_id = str(reply.get("id") or "")
                    if not reply_id:
                        outcome.failed_for(
                            CoverageReason.INVALID_METADATA,
                            CoverageObjectKind.COMMENT,
                            None,
                        )
                        continue
                    if reply_id in seen:
                        continue
                    seen.add(reply_id)
                    pending.append(reply)

    def _attachment_units(
        self,
        client: ConfluenceClient,
        page_id: str,
        context: _PageContext,
        outcome: FetchOutcome,
        sandbox: _LazySandbox,
    ) -> Iterator[ContentUnit]:
        """Text-extractable attachments, downloaded and parsed in a child process.

        The size check happens twice on purpose: once against the *declared*
        ``fileSize``, so an obviously oversized file costs no bandwidth, and once
        against the bytes actually arriving, because that declaration comes from
        the same place the file does.
        """
        for attachment in client.paginate(f"/pages/{page_id}/attachments"):
            name = str(attachment.get("title") or "")
            link = attachment.get("downloadLink")
            reference = str(attachment.get("id") or "") or name or None
            if not name or not link:
                outcome.failed_for(
                    CoverageReason.INVALID_METADATA,
                    CoverageObjectKind.ATTACHMENT,
                    reference,
                )
                logger.warning(
                    "confluence_attachment_missing_metadata",
                    attachment_id=str(attachment.get("id") or ""),
                )
                continue

            declared = _as_int(attachment.get("fileSize"))
            if declared is not None and declared > self.extraction_limits.max_input_bytes:
                outcome.failed_for(
                    CoverageReason.SIZE_LIMIT,
                    CoverageObjectKind.ATTACHMENT,
                    reference,
                )
                logger.debug("confluence_attachment_too_large", name=name, bytes=declared)
                continue

            try:
                data = client.get_bytes(str(link), max_bytes=self.extraction_limits.max_input_bytes)
            except DownloadTooLarge:
                # It lied about its size, or did not say. The cap is intentional,
                # but unread content cannot justify source-wide reconciliation.
                outcome.failed_for(
                    CoverageReason.SIZE_LIMIT,
                    CoverageObjectKind.ATTACHMENT,
                    reference,
                )
                continue
            except CredentialError, RateLimited:
                raise
            except ConnectorError as exc:
                outcome.failed_for(
                    CoverageReason.CONNECTOR_ERROR,
                    CoverageObjectKind.ATTACHMENT,
                    reference,
                )
                logger.warning("confluence_attachment_failed", name=name, error=str(exc))
                continue

            extracted = extract_text(
                data, name, limits=self.extraction_limits, sandbox=sandbox.get()
            )
            if not extracted.outcome.is_text:
                # An image is an ordinary policy skip. A malformed, oversized,
                # bomb-like, or timed-out document was requested text that could
                # not be read, so it makes the task incomplete instead.
                if extracted.outcome.is_incomplete:
                    outcome.failed_for(
                        _incomplete_extraction_reason(extracted.outcome),
                        CoverageObjectKind.ATTACHMENT,
                        reference,
                    )
                else:
                    outcome.skipped_for(
                        _skipped_extraction_reason(extracted.outcome),
                        CoverageObjectKind.ATTACHMENT,
                        reference,
                    )
                if extracted.outcome.is_hostile:
                    logger.warning(
                        "confluence_attachment_rejected",
                        name=name,
                        outcome=extracted.outcome.value,
                    )
                continue

            if extracted.truncated:
                # Keep the useful prefix as a unit, but do not let the unseen tail
                # auto-resolve a finding from an earlier complete scan.
                outcome.failed_for(
                    CoverageReason.OUTPUT_LIMIT,
                    CoverageObjectKind.ATTACHMENT,
                    reference,
                )
                # The useful prefix still flows through detection, but the object's
                # one coverage disposition is failed — never both scanned and failed.
                outcome.units += 1
            else:
                outcome.scanned_for(CoverageObjectKind.ATTACHMENT, reference)
            yield ContentUnit(
                locator=CoarseLocator(
                    connector_type=self.connector_type,
                    resource_id=page_id,
                    # The filename, not the attachment id: replacing an attachment
                    # with a corrected version should update the finding rather
                    # than orphan it and raise a new one.
                    sub_resource=f"attachment:{name}",
                ),
                text=extracted.text,
                origin=ContentOrigin.ATTACHMENT,
                display=context.display()
                | {
                    "filename": name,
                    "media_type": attachment.get("mediaType"),
                    "truncated": extracted.truncated,
                },
            )

    # ─── Wiring ───────────────────────────────────────────────────────────────

    def _client(self, connection: dict[str, Any], credential: str | None) -> ConfluenceClient:
        base_url = str(connection.get("base_url") or "").strip()
        if not base_url:
            raise ConnectorError("confluence source has no base_url configured")

        kwargs: dict[str, Any] = {
            "base_url": base_url,
            # Absent is legitimate: an anonymous-readable site. A *wrong* one is
            # the source's problem to report, which it does with a 401.
            "credential": Credential(token=credential, email=_email(connection))
            if credential
            else None,
            "rate_limit": self.rate_limit,
            "transport": self.transport,
        }
        if api_prefix := connection.get("api_prefix"):
            kwargs["api_prefix"] = str(api_prefix)
        if self.sleep is not None:
            kwargs["sleep"] = self.sleep
        return ConfluenceClient(**kwargs)


def _incomplete_extraction_reason(outcome: ExtractionOutcome) -> CoverageReason:
    """Map parser-specific values onto the stable public assurance vocabulary."""
    if outcome is ExtractionOutcome.REJECTED_TOO_LARGE:
        return CoverageReason.SIZE_LIMIT
    if outcome is ExtractionOutcome.FAILED_TIMEOUT:
        return CoverageReason.TIMEOUT
    # Compression bombs and parser crashes are both safe parser rejection: the
    # connector detail stays in its local log, while the manifest stays stable.
    return CoverageReason.PARSE_ERROR


def _skipped_extraction_reason(outcome: ExtractionOutcome) -> CoverageReason:
    if outcome is ExtractionOutcome.SKIPPED_BINARY:
        return CoverageReason.BINARY_CONTENT
    if outcome is ExtractionOutcome.SKIPPED_EMPTY:
        return CoverageReason.EMPTY_CONTENT
    return CoverageReason.UNSUPPORTED_TYPE


@dataclass(slots=True)
class _LazySandbox:
    """One extraction child per fetch, spawned only if an attachment needs it.

    Per fetch rather than per connector because the connector is a shared singleton
    and a sandbox is not thread-safe; lazily rather than eagerly because a process
    spawn for a space with no attachments is pure cost.
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
        if self._sandbox is not None:
            self._sandbox.close()
            self._sandbox = None


@dataclass(frozen=True, slots=True)
class _SpaceContext:
    """Display context every unit in a space carries.

    Display-only, all of it — the space key, the title, the URL. It is stored on
    the finding and shown in the UI, and it may change freely between scans without
    orphaning anything, which is exactly why none of it is in the locator.
    """

    key: str
    name: Any

    def for_page(
        self, page: dict[str, Any], page_id: str, resolve: Callable[[str], str]
    ) -> _PageContext:
        webui = _webui(page)
        path = webui or f"/pages/{page_id}"
        # Resolved through the client rather than by splicing on a context path
        # here: `webui` and an attachment's `downloadLink` come from the same
        # `_links` family and must be resolved the same way, or the console shows a
        # page link that works next to an attachment URL that 404s (#124).
        return _PageContext(space=self, title=page.get("title"), path=path, url=resolve(path))


@dataclass(frozen=True, slots=True)
class _PageContext:
    """Where one page is, shared by the page and everything attached to it.

    **Comments and attachments carry the page's path, not one of their own.** They
    have no ``webui`` link of their own, and inventing a synthetic one would mean a
    ``path_glob`` an analyst wrote against a page silently missed the comments and
    attachments on it — suppressing one finding out of three and looking correct
    (#44). Their own identity lives in the locator's ``sub_resource``, where it
    belongs, and in the ``comment_id``/``filename`` display keys.
    """

    space: _SpaceContext
    title: Any
    path: str
    url: str

    def display(self) -> dict[str, Any]:
        # `path` and `url` are what a `path_glob` suppression is matched against
        # (GLOB_FRIENDLY_KEYS); a connector populating neither leaves analysts
        # unable to write one for this source at all.
        return {
            "space": self.space.key,
            "space_name": self.space.name,
            "title": self.title,
            "path": self.path,
            "url": self.url,
        }


def _space_filters(connection: dict[str, Any]) -> dict[str, Any]:
    """Narrow the spaces request where the API can do it for us.

    Personal spaces are excluded by default: they are every user's drafts, they
    dominate the space count on a large site, and scanning them is a decision an
    operator should make deliberately rather than inherit.
    """
    filters: dict[str, Any] = {"status": "current"}
    if not connection.get("include_personal_spaces", False):
        filters["type"] = "global"
    return filters


def _body_format() -> dict[str, Any]:
    """Ask for storage format — the markup, not the rendered view.

    Rendered HTML runs macros, and a macro that pulls content from elsewhere would
    attribute someone else's secret to this page.
    """
    return {"body-format": "storage"}


def _webui(resource: dict[str, Any]) -> str:
    links = resource.get("_links")
    if isinstance(links, dict) and links.get("webui"):
        return str(links["webui"])
    return ""


def _email(connection: dict[str, Any]) -> str | None:
    """The account email, which is what makes a Cloud API token usable.

    Its absence selects bearer auth (Server/DC PATs), so this is the one field
    that decides the flavor — see the client's module docstring.
    """
    email = connection.get("email") or connection.get("username")
    return str(email) if email else None


def _as_int(value: Any) -> int | None:
    try:
        return int(value)
    except TypeError, ValueError:
        return None


__all__ = ["CONFLUENCE_CONNECTOR_TYPE", "ConfluenceConnector", "storage_to_text"]
