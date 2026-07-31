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
from iceberg_api.scans.routes import list_scans
from iceberg_api.sources import routes as api
from iceberg_api.sources.routes import ProberDep
from iceberg_api.sources.schedule_routes import list_schedules
from iceberg_api.sources.schemas import SourceCreate, SourceRead, SourceUpdate
from iceberg_api.web.dependencies import CurrentViewer, Viewer, WebAdmin, WebViewer
from iceberg_api.web.forms import checkbox, error_text, optional, string_list
from iceberg_api.web.templating import hx_redirect, render_fragment, render_page

router = APIRouter(include_in_schema=False)

#: MVP scope. The select renders these and nothing else, because
#: `validate_connection` refuses the rest with an explanation anyway — offering a
#: choice the API will reject is a worse experience than not offering it.
SELECTABLE_TYPES = (SourceType.CONFLUENCE,)


def _connection_form(
    *,
    base_url: str,
    email: str | None,
    api_prefix: str | None,
    spaces: list[str],
    include_comments: bool,
    include_attachments: bool,
    include_personal_spaces: bool,
) -> dict[str, Any]:
    """Assemble the Confluence connection blob from the form's flat fields.

    Built here rather than in JavaScript so there is one description of the shape
    and the API's `ConfluenceConnection` model is the only thing that validates
    it. An empty ``email`` is dropped rather than sent: its *presence* is what
    selects Basic ``email:token`` auth, so a blank string would read as
    "configured" (docs/connectors.md § Auth).
    """
    connection: dict[str, Any] = {
        "base_url": base_url.strip(),
        "spaces": spaces,
        "include_comments": include_comments,
        "include_attachments": include_attachments,
        "include_personal_spaces": include_personal_spaces,
    }
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
            "spaces": connection.get("spaces", []),
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
    return render_page(
        request,
        "sources/detail.html",
        viewer,
        {
            "source": source,
            "schedules": schedules.items,
            "scans": scans.items,
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
    include_comments: Annotated[str | None, Form()] = None,
    include_attachments: Annotated[str | None, Form()] = None,
    include_personal_spaces: Annotated[str | None, Form()] = None,
    enabled: Annotated[str | None, Form()] = None,
    csrf_token: Annotated[str, Form()] = "",
) -> Response:
    """Create a source, then go to it.

    A rejected create re-renders the form fragment with the API's own message
    rather than an error page: the analyst's typed values are still on screen,
    which is the whole reason to swap a fragment instead of navigating.
    """
    connection = _connection_form(
        base_url=base_url,
        email=optional(email),
        api_prefix=optional(api_prefix),
        spaces=string_list(spaces),
        include_comments=checkbox(include_comments),
        include_attachments=checkbox(include_attachments),
        include_personal_spaces=checkbox(include_personal_spaces),
    )
    try:
        body = SourceCreate(
            name=name.strip(),
            type=SourceType(source_type),
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
    include_comments: Annotated[str | None, Form()] = None,
    include_attachments: Annotated[str | None, Form()] = None,
    include_personal_spaces: Annotated[str | None, Form()] = None,
    enabled: Annotated[str | None, Form()] = None,
    csrf_token: Annotated[str, Form()] = "",
) -> Response:
    """Save an edit. A blank credential field leaves the stored one alone."""
    connection = _connection_form(
        base_url=base_url,
        email=optional(email),
        api_prefix=optional(api_prefix),
        spaces=string_list(spaces),
        include_comments=checkbox(include_comments),
        include_attachments=checkbox(include_attachments),
        include_personal_spaces=checkbox(include_personal_spaces),
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
        source = await api.read_source(source_id=source_id, user=admin, db=db)
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
