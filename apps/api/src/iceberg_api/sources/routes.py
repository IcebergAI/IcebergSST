"""Source CRUD, credential storage, and the connectivity check (#31, #32).

Writes are admin-only; reading a source is available to any authenticated role,
because an analyst triaging a finding needs to know where it came from.

The credential is the sensitive part. It arrives once, is sealed through the
secret store immediately (ADR 0007), and the row keeps only the opaque ref. No
response includes it — not the plaintext, not the ref — and rotating it is a
separate audited action from editing the source.
"""

import uuid
from collections.abc import Awaitable, Callable
from typing import Annotated, Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from iceberg_core.enums import SourceType
from iceberg_core.models import (
    AUDIT_SOURCE_CREATED,
    AUDIT_SOURCE_CREDENTIAL_ROTATED,
    AUDIT_SOURCE_CREDENTIAL_SET,
    AUDIT_SOURCE_DELETED,
    AUDIT_SOURCE_UPDATED,
    AUDIT_TARGET_SOURCE,
    Source,
)
from iceberg_core.secrets import SecretStoreError
from pydantic import SecretStr, ValidationError
from sqlmodel import select

from iceberg_api import audit
from iceberg_api.auth.dependencies import CsrfProtected, SecretStoreDep, SessionDep
from iceberg_api.auth.rbac import AdminUser, ViewerUser
from iceberg_api.pagination import DEFAULT_LIMIT, MAX_LIMIT, after, build_page, position
from iceberg_api.schemas import Page
from iceberg_api.sources.probe import ProbeError, probe_source
from iceberg_api.sources.schemas import (
    ConnectivityResult,
    SourceCreate,
    SourceRead,
    SourceUpdate,
    validate_connection,
)

router = APIRouter(prefix="/sources", tags=["sources"])
logger = structlog.get_logger()

#: The connectivity check, as a dependency — so tests can substitute a source that
#: answers, and so #45 can swap in a call through the connector interface without
#: touching this route.
Prober = Callable[[Source, SecretStr], Awaitable[ConnectivityResult]]


def get_prober() -> Prober:
    return probe_source


ProberDep = Annotated[Prober, Depends(get_prober)]


def _read(source: Source) -> SourceRead:
    return SourceRead(
        id=source.id,
        name=source.name,
        type=source.type,
        connection=source.connection,
        enabled=source.enabled,
        has_credential=source.credential_ref is not None,
        created_at=source.created_at,
        updated_at=source.updated_at,
    )


def _validated_connection(source_type: SourceType, connection: dict[str, Any]) -> dict[str, Any]:
    """Validate a connection blob, turning either failure mode into a 422."""
    try:
        return validate_connection(source_type, connection)
    except ValidationError as exc:
        # Pydantic's raw errors carry exception objects in ``ctx``, which will not
        # serialize; reduce them to where/what, which is what a client can act on.
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            [
                {"loc": list(error["loc"]), "msg": error["msg"], "type": error["type"]}
                for error in exc.errors()
            ],
        ) from exc
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc


def _load(db: SessionDep, source_id: uuid.UUID) -> Source:
    source = db.get(Source, source_id)
    if source is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "source not found")
    return source


@router.get("")
async def list_sources(
    user: ViewerUser,
    db: SessionDep,
    limit: int = Query(default=DEFAULT_LIMIT, ge=1, le=MAX_LIMIT),
    cursor: str | None = Query(default=None),
) -> Page[SourceRead]:
    """List sources, oldest first, in stable ``(created_at, id)`` order."""
    statement = after(
        select(Source),
        created_at=Source.created_at,  # type: ignore[arg-type]
        row_id=Source.id,  # type: ignore[arg-type]
        cursor=position(cursor),
    )
    rows = list(db.exec(statement.limit(limit + 1)))
    return build_page(rows, limit=limit, read=_read)


@router.get("/{source_id}")
async def read_source(source_id: uuid.UUID, user: ViewerUser, db: SessionDep) -> SourceRead:
    """One source. An analyst triaging a finding needs to see where it came from."""
    return _read(_load(db, source_id))


@router.post("", status_code=status.HTTP_201_CREATED, dependencies=[CsrfProtected])
async def create_source(
    body: SourceCreate,
    admin: AdminUser,
    db: SessionDep,
    store: SecretStoreDep,
) -> SourceRead:
    """Create a source, sealing its credential before anything is persisted."""
    if db.exec(select(Source).where(Source.name == body.name)).first() is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "a source with that name already exists")

    source = Source(
        name=body.name,
        type=body.type,
        connection=_validated_connection(body.type, body.connection),
        enabled=body.enabled,
        created_by_id=admin.id,
    )
    if body.credential is not None:
        source.credential_ref = _seal(store, body.credential.get_secret_value())

    db.add(source)
    db.flush()
    audit.record(
        db,
        actor_id=admin.id,
        action=AUDIT_SOURCE_CREATED,
        target_type=AUDIT_TARGET_SOURCE,
        target_id=source.id,
        to_value=source.name,
        detail={"type": source.type.value},
    )
    if source.credential_ref is not None:
        audit.record(
            db,
            actor_id=admin.id,
            action=AUDIT_SOURCE_CREDENTIAL_SET,
            target_type=AUDIT_TARGET_SOURCE,
            target_id=source.id,
        )
    db.commit()
    db.refresh(source)
    return _read(source)


@router.patch("/{source_id}", dependencies=[CsrfProtected])
async def update_source(
    source_id: uuid.UUID,
    changes: SourceUpdate,
    admin: AdminUser,
    db: SessionDep,
    store: SecretStoreDep,
) -> SourceRead:
    """Edit a source, and rotate its credential if a new one is supplied."""
    source = _load(db, source_id)
    changed: list[str] = []

    if changes.name is not None and changes.name != source.name:
        clash = db.exec(select(Source).where(Source.name == changes.name)).first()
        if clash is not None and clash.id != source.id:
            raise HTTPException(status.HTTP_409_CONFLICT, "a source with that name already exists")
        source.name = changes.name
        changed.append("name")

    if changes.connection is not None:
        source.connection = _validated_connection(source.type, changes.connection)
        changed.append("connection")

    if changes.enabled is not None and changes.enabled != source.enabled:
        source.enabled = changes.enabled
        changed.append("enabled")

    if changed:
        audit.record(
            db,
            actor_id=admin.id,
            action=AUDIT_SOURCE_UPDATED,
            target_type=AUDIT_TARGET_SOURCE,
            target_id=source.id,
            to_value=",".join(changed),
        )

    if changes.credential is not None:
        # Rotation is its own event: "who changed this source" and "who last
        # replaced its credential" are different questions.
        rotated = source.credential_ref is not None
        source.credential_ref = _seal(store, changes.credential.get_secret_value())
        audit.record(
            db,
            actor_id=admin.id,
            action=AUDIT_SOURCE_CREDENTIAL_ROTATED if rotated else AUDIT_SOURCE_CREDENTIAL_SET,
            target_type=AUDIT_TARGET_SOURCE,
            target_id=source.id,
        )

    db.add(source)
    db.commit()
    db.refresh(source)
    return _read(source)


@router.delete("/{source_id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=[CsrfProtected])
async def delete_source(
    source_id: uuid.UUID,
    admin: AdminUser,
    db: SessionDep,
) -> Response:
    """Delete a source. Its scans, findings, and schedules cascade with it."""
    source = _load(db, source_id)
    audit.record(
        db,
        actor_id=admin.id,
        action=AUDIT_SOURCE_DELETED,
        target_type=AUDIT_TARGET_SOURCE,
        target_id=source.id,
        from_value=source.name,
    )
    db.delete(source)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/{source_id}/test", dependencies=[CsrfProtected])
async def test_source(
    source_id: uuid.UUID,
    admin: AdminUser,
    db: SessionDep,
    store: SecretStoreDep,
    prober: ProberDep,
) -> ConnectivityResult:
    """Check that the source answers with the stored credential.

    Deliberately admin-only: it makes an outbound request to an operator-supplied
    URL with a real credential (docs/security.md § Outbound requests).
    """
    source = _load(db, source_id)
    if source.credential_ref is None:
        raise HTTPException(status.HTTP_409_CONFLICT, "source has no stored credential to test")

    try:
        credential = store.open(source.credential_ref)
    except SecretStoreError as exc:
        # A ref that will not open means the master key changed or the row was
        # tampered with. Either way the operator needs to hear it plainly.
        logger.warning("source_credential_unreadable", source_id=str(source.id))
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "stored credential could not be decrypted; re-enter it",
        ) from exc

    logger.info("source_connectivity_test", source_id=str(source.id), actor_id=str(admin.id))
    try:
        result = await prober(source, credential)
    except ProbeError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    return result


def _seal(store: SecretStoreDep, plaintext: str) -> str:
    if not plaintext.strip():
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "credential must not be blank")
    try:
        return store.seal(plaintext)
    except SecretStoreError as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc)) from exc
