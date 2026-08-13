"""The findings queue, the detail view, and triage (#57).

Two things shape this screen.

**No filter is implicit.** The API applies exactly the filters it is sent, so a
count on this page can always be reconciled against the table. The default view —
open, not suppressed — is therefore a *redirect into an explicit query string*
rather than a server-side default, which means the URL always says what is being
shown and a link to it shows somebody else the same thing.

**Nothing derived from the secret is rendered.** The API never returns
``secret_hash``, and ``redacted_snippet`` was masked inside the engine before it
crossed the wire (ADR 0004). The template shows the snippet and the resource
locator and nothing else, both autoescaped — they came out of somebody else's
Confluence and are the reason the CSP on this page is strict.
"""

import uuid
from datetime import datetime
from typing import Annotated, Any
from urllib.parse import urlsplit

from fastapi import APIRouter, Form, HTTPException, Query, Request, Response
from iceberg_core.enums import FindingState, RemediationActionKind, Severity, UserRole
from pydantic import ValidationError

from iceberg_api.auth.dependencies import CsrfProtected, SessionDep, SettingsDep
from iceberg_api.findings import routes as api
from iceberg_api.findings.schemas import FindingUpdate
from iceberg_api.pagination import DEFAULT_LIMIT
from iceberg_api.remediation.routes import (
    read_guidance,
    record_remediation,
    retract_remediation,
    verify_remediation,
)
from iceberg_api.remediation.schemas import (
    EvidenceLink,
    RemediationCreate,
    RemediationRetract,
    RemediationVerify,
)
from iceberg_api.rules import list_rules
from iceberg_api.sources.routes import list_sources
from iceberg_api.users.routes import list_users
from iceberg_api.web.dependencies import CurrentViewer, WebAnalyst, WebViewer
from iceberg_api.web.forms import error_text, optional
from iceberg_api.web.templating import id_or_none, render_fragment, render_page

router = APIRouter(include_in_schema=False)

#: ``?assignee=me`` — the overview links to it, and it is the one assignee filter
#: an analyst can use without being able to list users (that is admin-only).
ASSIGNEE_ME = "me"


def _enum_or_none(enum: Any, value: str | None) -> Any:
    """A filter value from the query string, ignoring one we do not recognise.

    A stale bookmark or a hand-edited URL should show the unfiltered list, not a
    422 on a read-only page.
    """
    if not value:
        return None
    try:
        return enum(value)
    except ValueError:
        return None


def _bool_or_none(value: str | None) -> bool | None:
    if value in {"true", "false"}:
        return value == "true"
    return None


def _host_label(url: str) -> str:
    """A viewer-safe default label for an evidence link: its host, nothing more.

    Labels are viewer-visible while URLs are not (ADR 0012), so this deliberately
    keeps the path, query and fragment out — those are where a ticket id, a
    document name or an internal route would sit. A URL we cannot parse a host
    from gets a neutral word rather than any part of the string itself.
    """
    host = urlsplit(url.strip()).hostname
    return host[:200] if host else "evidence link"


@router.get("/findings")
async def findings_page(  # one parameter per filter, by design
    request: Request,
    viewer: CurrentViewer,
    user: WebViewer,
    db: SessionDep,
    settings: SettingsDep,
    source_id: Annotated[str | None, Query()] = None,
    state: Annotated[str | None, Query()] = None,
    severity: Annotated[str | None, Query()] = None,
    rule_id: Annotated[str | None, Query()] = None,
    assignee: Annotated[str | None, Query()] = None,
    suppressed: Annotated[str | None, Query()] = None,
    cursor: Annotated[str | None, Query()] = None,
) -> Response:
    """The queue. Every filter is in the URL; none is applied behind your back."""
    assignee_id = user.id if assignee == ASSIGNEE_ME else id_or_none(assignee)

    page = await api.list_findings(
        user=user,
        db=db,
        source_id=id_or_none(source_id),
        state=_enum_or_none(FindingState, state),
        rule_id=optional(rule_id),
        severity=_enum_or_none(Severity, severity),
        assignee_id=assignee_id,
        suppressed=_bool_or_none(suppressed),
        limit=DEFAULT_LIMIT,
        cursor=cursor,
    )
    sources = await list_sources(user=user, db=db, limit=DEFAULT_LIMIT, cursor=None)
    rules = await list_rules(user=user, db=db, settings=settings)

    return render_page(
        request,
        "findings/list.html",
        viewer,
        {
            "findings": page.items,
            "next_cursor": page.next_cursor,
            "source_names": {source.id: source.name for source in sources.items},
            "sources": sources.items,
            "rules": rules.rules,
            "states": list(FindingState),
            "severities": list(Severity),
            "selected": {
                "source_id": source_id or "",
                "state": state or "",
                "severity": severity or "",
                "rule_id": rule_id or "",
                "assignee": assignee or "",
                "suppressed": suppressed or "",
            },
            "query": request.url.query,
        },
    )


@router.get("/findings/{finding_id}")
async def finding_detail(
    request: Request,
    finding_id: uuid.UUID,
    viewer: CurrentViewer,
    user: WebViewer,
    db: SessionDep,
) -> Response:
    """One finding: where it is, what it looks like, and every decision made on it."""
    finding = await api.read_finding(finding_id=finding_id, user=user, db=db)
    return render_page(
        request,
        "findings/detail.html",
        viewer,
        await _detail_context(finding, user, db),
    )


@router.post("/findings/{finding_id}/triage", dependencies=[CsrfProtected])
async def triage(  # one parameter per form field
    request: Request,
    finding_id: uuid.UUID,
    viewer: CurrentViewer,
    analyst: WebAnalyst,
    db: SessionDep,
    settings: SettingsDep,
    state: Annotated[str, Form()],
    assignee: Annotated[str, Form()] = "",
    comment: Annotated[str, Form()] = "",
    notes: Annotated[str | None, Form()] = None,
    csrf_token: Annotated[str, Form()] = "",
) -> Response:
    """Record a triage decision, then re-render the panel with its new history.

    ``assignee`` distinguishes three things a browser cannot: an empty field
    means "leave the assignee alone", ``none`` means unassign, and anything else
    is a user id. That mirrors ``FindingUpdate``, where a field omitted and a
    field set to ``null`` are deliberately different.
    """
    error = None
    try:
        # Inside the try because ``FindingState(state)`` is a parse of a posted
        # string: a stale form or a hand-made request is a rejected decision the
        # analyst should see on the panel, not a 500.
        payload: dict[str, Any] = {"state": FindingState(state) if state else None}
        if comment.strip():
            payload["comment"] = comment.strip()
        if notes is not None:
            payload["notes"] = notes.strip() or None
        if assignee == "none":
            payload["assignee_id"] = None
        elif assignee:
            payload["assignee_id"] = id_or_none(assignee)

        finding = await api.update_finding(
            finding_id=finding_id,
            changes=FindingUpdate(**payload),
            analyst=analyst,
            db=db,
            settings=settings,
        )
    except (HTTPException, ValidationError, ValueError) as exc:
        # A 409 is the state machine refusing a move between judgements, and
        # nothing else in the request was applied either. Show the finding as it
        # actually is, with the reason above it.
        error = error_text(exc)
        finding = await api.read_finding(finding_id=finding_id, user=analyst, db=db)

    context = await _detail_context(finding, analyst, db)
    return render_fragment(request, "triage.html", viewer, context | {"error": error})


async def _detail_context(finding: Any, user: Any, db: Any) -> dict[str, Any]:
    """The finding, its people, and the assignment options this role really has.

    Listing users is admin-only, so an analyst is offered "assign to me" and
    "unassign" rather than a picker they would get a 403 building. Names for the
    events come from the same list when it is available, and fall back to the
    actor id when it is not — an audit trail that hides who acted because the
    reader lacks a directory would be worse than one showing a uuid.
    """
    assignable = []
    names: dict[uuid.UUID, str] = {}
    if user.role is UserRole.ADMIN:
        page = await list_users(admin=user, db=db, limit=DEFAULT_LIMIT, cursor=None)
        assignable = [candidate for candidate in page.items if not candidate.disabled]
        names = {candidate.id: candidate.display_name for candidate in page.items}
    names.setdefault(user.id, user.display_name)

    return {
        "finding": finding,
        "assignable": assignable,
        "user_names": names,
        "states": list(FindingState),
        "island": {"state": finding.state.value},
        "error": None,
        # The remediation panel (#142): advice for this finding's rule, the
        # action-kind options, and a slot for the panel's own form errors.
        "guidance": await read_guidance(rule_id=finding.rule_id, user=user),
        "remediation_kinds": list(RemediationActionKind),
        "remediation_error": None,
    }


@router.post("/findings/{finding_id}/remediations", dependencies=[CsrfProtected])
async def record_remediation_form(  # one parameter per form field
    request: Request,
    finding_id: uuid.UUID,
    viewer: CurrentViewer,
    analyst: WebAnalyst,
    db: SessionDep,
    kind: Annotated[str, Form()],
    occurred_at: Annotated[str, Form()] = "",
    note: Annotated[str, Form()] = "",
    link_url_1: Annotated[str, Form()] = "",
    link_label_1: Annotated[str, Form()] = "",
    link_url_2: Annotated[str, Form()] = "",
    link_label_2: Annotated[str, Form()] = "",
    link_url_3: Annotated[str, Form()] = "",
    link_label_3: Annotated[str, Form()] = "",
    csrf_token: Annotated[str, Form()] = "",
) -> Response:
    """Record a containment action, then re-render the panel with it listed.

    Three static link rows rather than a scripted list (see the partial); a row
    with a URL and no label gets the URL's *host* as its label rather than a 422 —
    the label is for humans, and "fill something in" is not worth a round trip.

    The host, and never the URL: labels are the one part of an evidence link a
    viewer is shown (ADR 0012), so defaulting the label to the URL would hand
    every viewer the path and query the redaction exists to withhold.
    """
    error = None
    try:
        links = []
        for url, label in (
            (link_url_1, link_label_1),
            (link_url_2, link_label_2),
            (link_url_3, link_label_3),
        ):
            if url.strip():
                links.append(EvidenceLink(url=url.strip(), label=label.strip() or _host_label(url)))
        payload = RemediationCreate(
            kind=RemediationActionKind(kind),
            occurred_at=datetime.fromisoformat(occurred_at) if occurred_at.strip() else None,
            note=note.strip() or None,
            evidence_links=links,
        )
        await record_remediation(finding_id=finding_id, payload=payload, analyst=analyst, db=db)
    except (HTTPException, ValidationError, ValueError) as exc:
        error = error_text(exc)

    finding = await api.read_finding(finding_id=finding_id, user=analyst, db=db)
    context = await _detail_context(finding, analyst, db)
    return render_fragment(
        request, "remediation.html", viewer, context | {"remediation_error": error}
    )


@router.post(
    "/findings/{finding_id}/remediations/{remediation_id}/verify",
    dependencies=[CsrfProtected],
)
async def verify_remediation_form(
    request: Request,
    finding_id: uuid.UUID,
    remediation_id: uuid.UUID,
    viewer: CurrentViewer,
    analyst: WebAnalyst,
    db: SessionDep,
    comment: Annotated[str, Form()] = "",
    csrf_token: Annotated[str, Form()] = "",
) -> Response:
    """Mark an action verified; a 409 (already verified/retracted) renders as
    the panel's error rather than a dead end."""
    error = None
    try:
        await verify_remediation(
            finding_id=finding_id,
            remediation_id=remediation_id,
            payload=RemediationVerify(comment=comment.strip() or None),
            analyst=analyst,
            db=db,
        )
    except (HTTPException, ValidationError, ValueError) as exc:
        error = error_text(exc)

    finding = await api.read_finding(finding_id=finding_id, user=analyst, db=db)
    context = await _detail_context(finding, analyst, db)
    return render_fragment(
        request, "remediation.html", viewer, context | {"remediation_error": error}
    )


@router.post(
    "/findings/{finding_id}/remediations/{remediation_id}/retract",
    dependencies=[CsrfProtected],
)
async def retract_remediation_form(
    request: Request,
    finding_id: uuid.UUID,
    remediation_id: uuid.UUID,
    viewer: CurrentViewer,
    analyst: WebAnalyst,
    db: SessionDep,
    reason: Annotated[str, Form()] = "",
    csrf_token: Annotated[str, Form()] = "",
) -> Response:
    """Retract a wrong record. The empty-reason 422 comes back on the panel."""
    error = None
    try:
        await retract_remediation(
            finding_id=finding_id,
            remediation_id=remediation_id,
            payload=RemediationRetract(reason=reason),
            analyst=analyst,
            db=db,
        )
    except (HTTPException, ValidationError, ValueError) as exc:
        error = error_text(exc)

    finding = await api.read_finding(finding_id=finding_id, user=analyst, db=db)
    context = await _detail_context(finding, analyst, db)
    return render_fragment(
        request, "remediation.html", viewer, context | {"remediation_error": error}
    )
