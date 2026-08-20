"""Sources: the list, the create/edit form, and the connectivity check (#55).

The credential is the reason this screen needs care. It is write-only at the API
— no response carries the plaintext or the sealed ref — so the form never
receives one to render back. A saved source shows *whether* a credential exists
and offers to replace it; the field is empty every time the page loads, and
leaving it empty on an edit means "keep the one you have".
"""

import uuid
from dataclasses import dataclass
from typing import Annotated, Any

from fastapi import APIRouter, Form, HTTPException, Query, Request, Response
from iceberg_core.enums import SourceType
from pydantic import SecretStr, ValidationError

from iceberg_api.auth.dependencies import CsrfProtected, SecretStoreDep, SessionDep
from iceberg_api.pagination import DEFAULT_LIMIT
from iceberg_api.scans.routes import list_scans, read_source_coverage
from iceberg_api.sources import routes as api
from iceberg_api.sources.cursor_routes import invalidate_source_cursors, read_source_cursors
from iceberg_api.sources.probe import PROBEABLE_TYPES
from iceberg_api.sources.routes import ProberDep
from iceberg_api.sources.schedule_routes import list_schedules
from iceberg_api.sources.schemas import (
    DEFAULT_MAX_FILE_BYTES,
    FileshareProtocol,
    SourceCreate,
    SourceRead,
    SourceUpdate,
)
from iceberg_api.web.dependencies import (
    CurrentViewer,
    Viewer,
    WebAdmin,
    WebAnalyst,
    WebViewer,
)
from iceberg_api.web.forms import checkbox, error_text, optional, string_list
from iceberg_api.web.templating import hx_redirect, render_fragment, render_page

router = APIRouter(include_in_schema=False)

#: The select renders these and nothing else. Every type the API supports
#: (`SUPPORTED_SOURCE_TYPES`) now has form fields, so the two agree — a test holds
#: them in step, because offering a choice this form cannot express would post a
#: Confluence-shaped blob for something else.
SELECTABLE_TYPES = (SourceType.CONFLUENCE, SourceType.JIRA, SourceType.FILESHARE)

#: Types with no per-type block: everything they need is on the shared fields.
_HTTP_TYPES = (SourceType.CONFLUENCE, SourceType.JIRA)


@dataclass(frozen=True, slots=True)
class _FileshareFields:
    """The file-share form's own inputs.

    Grouped rather than added as seven more keywords to :func:`_connection_form`,
    which already carries one parameter per field for the two HTTP connectors.
    A share has nothing in common with them — no URL, no credential, no comments
    or attachments — so its inputs travel together.
    """

    protocol: str
    mount_path: str
    roots: list[str]
    include: list[str]
    exclude: list[str]
    follow_symlinks: bool
    #: Read as text, not `int`, so a blank or mistyped ceiling re-renders the form
    #: with a message instead of earning FastAPI's own 422 before this route runs.
    max_file_bytes: str


def _fileshare_connection(fields: _FileshareFields) -> dict[str, Any]:
    """The blob for a mounted share (#145, #196).

    No `base_url` and no credential: the engine walks a **read-only mount**, which
    is where the host, the share name and the authentication all live. A form that
    offered a token box here would be inviting an admin to store a secret that
    nothing reads.
    """
    typed = fields.max_file_bytes.strip()
    if not typed:
        # Said here rather than left to become a zero the API rejects with a
        # schema message: the form always renders a value, so a blank one is
        # somebody having cleared it.
        raise ValueError("maximum file size is required")
    try:
        ceiling = int(typed)
    except ValueError as exc:
        raise ValueError("maximum file size must be a whole number of bytes") from exc
    return {
        "protocol": fields.protocol,
        "mount_path": fields.mount_path.strip(),
        "roots": fields.roots,
        "include": fields.include,
        "exclude": fields.exclude,
        "follow_symlinks": fields.follow_symlinks,
        "max_file_bytes": ceiling,
    }


def _connection_form(
    source_type: SourceType,
    *,
    base_url: str,
    email: str | None,
    api_prefix: str | None,
    spaces: list[str],
    projects: list[str],
    include_comments: bool,
    include_attachments: bool,
    include_personal_spaces: bool,
    include_history: bool,
    include_archived_projects: bool,
    fileshare: _FileshareFields,
) -> dict[str, Any]:
    """Assemble a connection blob from the form's flat fields, per source type.

    Built here rather than in JavaScript so there is one description of the shape
    and the API's connection model is the only thing that validates it. An empty
    ``email`` is dropped rather than sent: its *presence* is what selects Basic
    ``email:token`` auth, so a blank string would read as "configured"
    (docs/connectors.md § Auth).

    Every type's inputs are posted on every save — the form keeps all the blocks in
    the DOM so switching type does not discard typing — so the fields belonging to
    the other types are simply not read here. The API's ``extra="forbid"`` model is
    the authority either way.
    """
    if source_type is SourceType.FILESHARE:
        # Returns early because a share shares none of the shared fields: sending
        # `base_url` or `include_comments` with it would be rejected by
        # `FileshareConnection`, which forbids extras.
        return _fileshare_connection(fileshare)

    connection: dict[str, Any] = {
        "base_url": base_url.strip(),
        "include_comments": include_comments,
        "include_attachments": include_attachments,
    }
    if source_type is SourceType.CONFLUENCE:
        connection["spaces"] = spaces
        connection["include_personal_spaces"] = include_personal_spaces
    elif source_type is SourceType.JIRA:
        connection["projects"] = projects
        connection["include_history"] = include_history
        connection["include_archived_projects"] = include_archived_projects
    else:  # pragma: no cover — every current type is handled; this guards the next
        # The select and `SUPPORTED_SOURCE_TYPES` agree today, and a test holds
        # them there. This is what a connector added to the API before the console
        # catches up hits: a refusal the form can show, rather than a
        # Confluence-shaped blob posted for something else.
        raise ValueError(f"the {source_type.value} connector is not available yet")

    if email:
        connection["email"] = email
    if api_prefix:
        connection["api_prefix"] = api_prefix
    return connection


def _form_state(source: SourceRead | None, connection: dict[str, Any]) -> dict[str, Any]:
    """What the template and the Alpine island need to redraw the form."""
    return {
        "source": source,
        "connection": connection,
        "types": SELECTABLE_TYPES,
        "protocols": tuple(FileshareProtocol),
        "island": {
            "type": (source.type.value if source else SELECTABLE_TYPES[0].value),
            "spaces": connection.get("spaces", []),
            "projects": connection.get("projects", []),
            "email": connection.get("email", ""),
            # Three chip lists rather than one: a root is a subtree to walk, a
            # glob is a filter over what is found in it, and mixing them up is
            # the mistake this screen exists to make hard.
            "roots": connection.get("roots", []),
            "include": connection.get("include", []),
            "exclude": connection.get("exclude", []),
            # Alpine owns this input (`x-model`), so it has to arrive through the
            # island: a `value=` on the element is overwritten by the model on
            # init, and an unhydrated model posts a blank ceiling.
            "maxFileBytes": str(connection.get("max_file_bytes", DEFAULT_MAX_FILE_BYTES)),
            "hasCredential": source.has_credential if source else False,
            "isNew": source is None,
        },
    }


@router.get("/sources")
async def sources_page(
    request: Request,
    viewer: CurrentViewer,
    user: WebViewer,
    db: SessionDep,
    cursor: Annotated[str | None, Query()] = None,
) -> Response:
    """Every configured source, newest page first."""
    page = await api.list_sources(user=user, db=db, limit=DEFAULT_LIMIT, cursor=cursor)
    return render_page(
        request,
        "sources/list.html",
        viewer,
        {
            "sources": page.items,
            "next_cursor": page.next_cursor,
            "form": _form_state(None, {"spaces": []}),
        },
    )


@router.get("/sources/{source_id}")
async def source_detail(
    request: Request,
    source_id: uuid.UUID,
    viewer: CurrentViewer,
    user: WebViewer,
    db: SessionDep,
) -> Response:
    """One source: how it is configured, what it is scheduled for, what it found."""
    source = await api.read_source(source_id=source_id, user=user, db=db)
    schedules = await list_schedules(
        user=user, db=db, source_id=source_id, limit=DEFAULT_LIMIT, cursor=None
    )
    scans = await list_scans(
        user=user, db=db, source_id=source_id, scan_status=None, active=None, limit=10, cursor=None
    )
    try:
        latest_coverage = await read_source_coverage(source_id=source_id, user=user, db=db)
    except HTTPException as exc:
        if exc.status_code != 404:
            raise
        latest_coverage = None
    return render_page(
        request,
        "sources/detail.html",
        viewer,
        {
            "source": source,
            "schedules": schedules.items,
            "scans": scans.items,
            "latest_coverage": latest_coverage,
            # A share is reached from an *engine*, through a mount this process
            # cannot see; a probe from here would check the wrong machine, so the
            # button is not offered rather than always failing (#196).
            "probeable": source.type in PROBEABLE_TYPES,
            "form": _form_state(source, source.connection),
        },
    )


@router.post("/sources", dependencies=[CsrfProtected])
async def create_source(  # one parameter per form field
    request: Request,
    viewer: CurrentViewer,
    admin: WebAdmin,
    db: SessionDep,
    store: SecretStoreDep,
    name: Annotated[str, Form()],
    source_type: Annotated[str, Form(alias="type")],
    # Both default to empty because a file-share source has neither: the mount
    # carries the host and the authentication, so the form does not render either
    # field and the browser posts nothing for them (#145, #196).
    base_url: Annotated[str, Form()] = "",
    credential: Annotated[str, Form()] = "",
    email: Annotated[str, Form()] = "",
    api_prefix: Annotated[str, Form()] = "",
    spaces: Annotated[list[str], Form()] = [],  # noqa: B006  # FastAPI reads the default, never mutates it
    projects: Annotated[list[str], Form()] = [],  # noqa: B006  # see spaces
    include_comments: Annotated[str | None, Form()] = None,
    include_attachments: Annotated[str | None, Form()] = None,
    include_personal_spaces: Annotated[str | None, Form()] = None,
    include_history: Annotated[str | None, Form()] = None,
    include_archived_projects: Annotated[str | None, Form()] = None,
    protocol: Annotated[str, Form()] = FileshareProtocol.SMB.value,
    mount_path: Annotated[str, Form()] = "",
    roots: Annotated[list[str], Form()] = [],  # noqa: B006  # see spaces
    include: Annotated[list[str], Form()] = [],  # noqa: B006  # see spaces
    exclude: Annotated[list[str], Form()] = [],  # noqa: B006  # see spaces
    follow_symlinks: Annotated[str | None, Form()] = None,
    max_file_bytes: Annotated[str, Form()] = "",
    enabled: Annotated[str | None, Form()] = None,
    csrf_token: Annotated[str, Form()] = "",
) -> Response:
    """Create a source, then go to it.

    A rejected create re-renders the form fragment with the API's own message
    rather than an error page: the analyst's typed values are still on screen,
    which is the whole reason to swap a fragment instead of navigating.
    """
    try:
        chosen = SourceType(source_type)
    except ValueError:
        return _form_error(request, viewer, None, {}, ValueError("unknown source type"))

    connection: dict[str, Any] = {}
    try:
        # Inside the try: a type the console has no form for (hand-posted, since
        # the select offers only SELECTABLE_TYPES) raises ValueError, as does a
        # ceiling that is not a number. Both must re-render the form with the
        # message rather than surfacing as a 500.
        connection = _connection_form(
            chosen,
            base_url=base_url,
            email=optional(email),
            api_prefix=optional(api_prefix),
            spaces=string_list(spaces),
            projects=string_list(projects),
            include_comments=checkbox(include_comments),
            include_attachments=checkbox(include_attachments),
            include_personal_spaces=checkbox(include_personal_spaces),
            include_history=checkbox(include_history),
            include_archived_projects=checkbox(include_archived_projects),
            fileshare=_FileshareFields(
                protocol=protocol,
                mount_path=mount_path,
                roots=string_list(roots),
                include=string_list(include),
                exclude=string_list(exclude),
                follow_symlinks=checkbox(follow_symlinks),
                max_file_bytes=max_file_bytes,
            ),
        )
        body = SourceCreate(
            name=name.strip(),
            type=chosen,
            connection=connection,
            credential=SecretStr(credential) if credential else None,
            enabled=checkbox(enabled),
        )
        created = await api.create_source(body=body, admin=admin, db=db, store=store)
    except (HTTPException, ValidationError, ValueError) as exc:
        return _form_error(request, viewer, None, connection, exc)

    return hx_redirect(f"/sources/{created.id}")


@router.post("/sources/{source_id}", dependencies=[CsrfProtected])
async def update_source(  # one parameter per form field
    request: Request,
    source_id: uuid.UUID,
    viewer: CurrentViewer,
    admin: WebAdmin,
    db: SessionDep,
    store: SecretStoreDep,
    name: Annotated[str, Form()],
    base_url: Annotated[str, Form()] = "",  # see create_source
    credential: Annotated[str, Form()] = "",
    email: Annotated[str, Form()] = "",
    api_prefix: Annotated[str, Form()] = "",
    spaces: Annotated[list[str], Form()] = [],  # noqa: B006  # see create_source
    projects: Annotated[list[str], Form()] = [],  # noqa: B006  # see create_source
    include_comments: Annotated[str | None, Form()] = None,
    include_attachments: Annotated[str | None, Form()] = None,
    include_personal_spaces: Annotated[str | None, Form()] = None,
    include_history: Annotated[str | None, Form()] = None,
    include_archived_projects: Annotated[str | None, Form()] = None,
    protocol: Annotated[str, Form()] = FileshareProtocol.SMB.value,
    mount_path: Annotated[str, Form()] = "",
    roots: Annotated[list[str], Form()] = [],  # noqa: B006  # see spaces
    include: Annotated[list[str], Form()] = [],  # noqa: B006  # see spaces
    exclude: Annotated[list[str], Form()] = [],  # noqa: B006  # see spaces
    follow_symlinks: Annotated[str | None, Form()] = None,
    max_file_bytes: Annotated[str, Form()] = "",
    enabled: Annotated[str | None, Form()] = None,
    csrf_token: Annotated[str, Form()] = "",
) -> Response:
    """Save an edit. A blank credential field leaves the stored one alone."""
    # Read first, because the blob's shape depends on the type and the type is not
    # posted: `SourceUpdate` has no `type` field, so a source's type is immutable
    # after creation. Trusting a client-supplied one would let a form post decide
    # how to interpret a stored source.
    source = await api.read_source(source_id=source_id, user=admin, db=db)

    connection: dict[str, Any] = {}
    try:
        # Inside the try: a stored source of a type this form cannot express — a
        # future connector supported by the API before the console catches up —
        # raises ValueError, and that must re-render the form with the message
        # rather than surfacing as a 500.
        connection = _connection_form(
            source.type,
            base_url=base_url,
            email=optional(email),
            api_prefix=optional(api_prefix),
            spaces=string_list(spaces),
            projects=string_list(projects),
            include_comments=checkbox(include_comments),
            include_attachments=checkbox(include_attachments),
            include_personal_spaces=checkbox(include_personal_spaces),
            include_history=checkbox(include_history),
            include_archived_projects=checkbox(include_archived_projects),
            fileshare=_FileshareFields(
                protocol=protocol,
                mount_path=mount_path,
                roots=string_list(roots),
                include=string_list(include),
                exclude=string_list(exclude),
                follow_symlinks=checkbox(follow_symlinks),
                max_file_bytes=max_file_bytes,
            ),
        )
        changes = SourceUpdate(
            name=name.strip(),
            connection=connection,
            # Supplying one rotates it; omitting it is not "remove", which the
            # API has no way to express and this form must not imply.
            credential=SecretStr(credential) if credential else None,
            enabled=checkbox(enabled),
        )
        await api.update_source(
            source_id=source_id, changes=changes, admin=admin, db=db, store=store
        )
    except (HTTPException, ValidationError, ValueError) as exc:
        return _form_error(request, viewer, source, connection, exc)

    return hx_redirect(f"/sources/{source_id}")


@router.delete("/sources/{source_id}", dependencies=[CsrfProtected])
async def delete_source(
    source_id: uuid.UUID,
    admin: WebAdmin,
    db: SessionDep,
) -> Response:
    """Delete a source. Its scans, findings, and schedules go with it."""
    await api.delete_source(source_id=source_id, admin=admin, db=db)
    return hx_redirect("/sources")


@router.post("/sources/{source_id}/test", dependencies=[CsrfProtected])
async def test_source(
    request: Request,
    source_id: uuid.UUID,
    viewer: CurrentViewer,
    admin: WebAdmin,
    db: SessionDep,
    store: SecretStoreDep,
    prober: ProberDep,
) -> Response:
    """Check the source answers with its stored credential, and say what happened.

    Answers a fragment rather than a page: the result belongs beside the button
    that asked for it. Nothing from the source's response body is rendered — the
    API already reduces it to a reachable flag, a status code, and a bounded
    explanation (docs/security.md § Outbound requests).
    """
    try:
        result = await api.test_source(
            source_id=source_id, admin=admin, db=db, store=store, prober=prober
        )
    except HTTPException as exc:
        return render_fragment(
            request, "connectivity.html", viewer, {"result": None, "error": error_text(exc)}
        )
    return render_fragment(request, "connectivity.html", viewer, {"result": result, "error": None})


@router.get("/sources/{source_id}/cursors")
async def source_cursors_panel(
    request: Request,
    source_id: uuid.UUID,
    viewer: CurrentViewer,
    user: WebAnalyst,
    db: SessionDep,
) -> Response:
    """What this source has read incrementally (#143).

    Its own route rather than part of the detail page because the cursor API is
    analyst-only while the detail page is viewer-accessible. Weakening the API's
    dependency to fit the page would have moved the RBAC decision into the console,
    which is exactly what invariant 4 forbids.
    """
    watermarks = await read_source_cursors(source_id=source_id, analyst=user, db=db)
    return render_fragment(request, "source_cursors.html", viewer, {"watermarks": watermarks})


@router.delete("/sources/{source_id}/cursors", dependencies=[CsrfProtected])
async def drop_source_cursors(
    request: Request,
    source_id: uuid.UUID,
    viewer: CurrentViewer,
    admin: WebAdmin,
    db: SessionDep,
) -> Response:
    """Force the next scan of this source to be a full one."""
    # No local error handling: the only failure is a 404 for a source that cannot
    # have gone missing between rendering this page and clicking the button, and the
    # shell already retargets a genuine 4xx into its error region.
    await invalidate_source_cursors(source_id=source_id, admin=admin, db=db)
    watermarks = await read_source_cursors(source_id=source_id, analyst=admin, db=db)
    return render_fragment(request, "source_cursors.html", viewer, {"watermarks": watermarks})


def _form_error(
    request: Request,
    viewer: Viewer,
    source: SourceRead | None,
    connection: dict[str, Any],
    exc: Exception,
) -> Response:
    """Re-render the form with what the analyst typed and why it was refused.

    Answers 200 with the re-rendered fragment, not the API's 4xx: htmx only swaps
    a 2xx by default, and a 422 here would leave the analyst looking at an
    unchanged form with no explanation of why nothing happened. The failure is
    not hidden — it is the first thing in the fragment, and the API logged it.
    """
    return render_fragment(
        request,
        "source_form.html",
        viewer,
        {"error": error_text(exc), **_form_state(source, connection)},
    )
