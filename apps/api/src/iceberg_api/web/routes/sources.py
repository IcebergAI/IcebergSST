"""Sources: the list, the create/edit form, and the connectivity check (#55).

The credential is the reason this screen needs care. It is write-only at the API
— no response carries the plaintext or the sealed ref — so the form never
receives one to render back. A saved source shows *whether* a credential exists
and offers to replace it; the field is empty every time the page loads, and
leaving it empty on an edit means "keep the one you have".
"""

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Form, HTTPException, Query, Request, Response
from iceberg_core.enums import SourceType
from pydantic import SecretStr, ValidationError

from iceberg_api.auth.dependencies import CsrfProtected, SecretStoreDep, SessionDep
from iceberg_api.pagination import DEFAULT_LIMIT
from iceberg_api.scans.routes import list_scans, read_source_coverage
from iceberg_api.sources import routes as api
from iceberg_api.sources.routes import ProberDep
from iceberg_api.sources.schedule_routes import list_schedules
from iceberg_api.sources.schemas import SourceCreate, SourceRead, SourceUpdate
from iceberg_api.web.dependencies import CurrentViewer, Viewer, WebAdmin, WebViewer
from iceberg_api.web.forms import checkbox, error_text, optional, string_list
from iceberg_api.web.templating import hx_redirect, render_fragment, render_page

router = APIRouter(include_in_schema=False)

#: The select renders these and nothing else, because `validate_connection`
#: refuses the rest with an explanation anyway — offering a choice the API will
#: reject is a worse experience than not offering it.
SELECTABLE_TYPES = (SourceType.CONFLUENCE, SourceType.JIRA)


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
) -> dict[str, Any]:
    """Assemble a connection blob from the form's flat fields, per source type.

    Built here rather than in JavaScript so there is one description of the shape
    and the API's connection model is the only thing that validates it. An empty
    ``email`` is dropped rather than sent: its *presence* is what selects Basic
    ``email:token`` auth, so a blank string would read as "configured"
    (docs/connectors.md § Auth).

    Both types' inputs are posted on every save — the form keeps both blocks in the
    DOM so switching type does not discard typing — so the fields belonging to the
    other type are simply not read here. The API's ``extra="forbid"`` model is the
    authority either way.
    """
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
    else:
        # Never reached through the select, but a hand-posted type must not
        # silently produce a Confluence-shaped blob for something else.
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
        "island": {
            "type": (source.type.value if source else SELECTABLE_TYPES[0].value),
            "spaces": connection.get("spaces", []),
            "projects": connection.get("projects", []),
            "email": connection.get("email", ""),
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
    base_url: Annotated[str, Form()],
    credential: Annotated[str, Form()],
    email: Annotated[str, Form()] = "",
    api_prefix: Annotated[str, Form()] = "",
    spaces: Annotated[list[str], Form()] = [],  # noqa: B006  # FastAPI reads the default, never mutates it
    projects: Annotated[list[str], Form()] = [],  # noqa: B006  # see spaces
    include_comments: Annotated[str | None, Form()] = None,
    include_attachments: Annotated[str | None, Form()] = None,
    include_personal_spaces: Annotated[str | None, Form()] = None,
    include_history: Annotated[str | None, Form()] = None,
    include_archived_projects: Annotated[str | None, Form()] = None,
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
    )
    try:
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
    base_url: Annotated[str, Form()],
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
    enabled: Annotated[str | None, Form()] = None,
    csrf_token: Annotated[str, Form()] = "",
) -> Response:
    """Save an edit. A blank credential field leaves the stored one alone."""
    # Read first, because the blob's shape depends on the type and the type is not
    # posted: `SourceUpdate` has no `type` field, so a source's type is immutable
    # after creation. Trusting a client-supplied one would let a form post decide
    # how to interpret a stored source.
    source = await api.read_source(source_id=source_id, user=admin, db=db)

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
    )
    try:
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
