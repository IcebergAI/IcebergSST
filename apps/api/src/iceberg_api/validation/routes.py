"""Admin CRUD for opt-in credential validation policies (#151)."""

import uuid

from fastapi import APIRouter, HTTPException, Response, status
from iceberg_core.models import (
    AUDIT_TARGET_VALIDATION_POLICY,
    AUDIT_VALIDATION_POLICY_CREATED,
    AUDIT_VALIDATION_POLICY_DELETED,
    AUDIT_VALIDATION_POLICY_UPDATED,
    ValidationPolicy,
)

from iceberg_api import audit
from iceberg_api.auth.dependencies import CsrfProtected, SessionDep
from iceberg_api.auth.rbac import AdminUser
from iceberg_api.validation import service
from iceberg_api.validation.schemas import (
    ValidationPolicyCreate,
    ValidationPolicyRead,
    ValidationPolicyUpdate,
)

router = APIRouter(prefix="/validation-policies", tags=["validation-policies"])


def _load(db: SessionDep, policy_id: uuid.UUID) -> ValidationPolicy:
    policy = service.get_policy(db, policy_id)
    if policy is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "validation policy not found")
    return policy


@router.get("")
async def list_validation_policies(admin: AdminUser, db: SessionDep) -> list[ValidationPolicyRead]:
    return [ValidationPolicyRead.model_validate(policy) for policy in service.list_policies(db)]


@router.get("/{policy_id}")
async def read_validation_policy(
    policy_id: uuid.UUID, admin: AdminUser, db: SessionDep
) -> ValidationPolicyRead:
    return ValidationPolicyRead.model_validate(_load(db, policy_id))


@router.post("", status_code=status.HTTP_201_CREATED, dependencies=[CsrfProtected])
async def create_validation_policy(
    body: ValidationPolicyCreate, admin: AdminUser, db: SessionDep
) -> ValidationPolicyRead:
    try:
        policy = service.create_policy(db, body)
    except service.PolicyConflict as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    except service.InvalidPolicy as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    audit.record(
        db,
        actor_id=admin.id,
        action=AUDIT_VALIDATION_POLICY_CREATED,
        target_type=AUDIT_TARGET_VALIDATION_POLICY,
        target_id=policy.id,
        to_value="enabled" if policy.enabled else "disabled",
        detail={
            "rule_id": policy.rule_id,
            "provider": policy.provider,
            "validator_id": policy.validator_id,
            "contract_version": policy.contract_version,
            "rationale": policy.rationale,
        },
    )
    db.commit()
    db.refresh(policy)
    return ValidationPolicyRead.model_validate(policy)


@router.patch("/{policy_id}", dependencies=[CsrfProtected])
async def update_validation_policy(
    policy_id: uuid.UUID,
    changes: ValidationPolicyUpdate,
    admin: AdminUser,
    db: SessionDep,
) -> ValidationPolicyRead:
    policy = _load(db, policy_id)
    try:
        changed = service.update_policy(db, policy, changes)
    except service.InvalidPolicy as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    if changed:
        audit.record(
            db,
            actor_id=admin.id,
            action=AUDIT_VALIDATION_POLICY_UPDATED,
            target_type=AUDIT_TARGET_VALIDATION_POLICY,
            target_id=policy.id,
            to_value=",".join(changed),
        )
        db.commit()
        db.refresh(policy)
    return ValidationPolicyRead.model_validate(policy)


@router.delete("/{policy_id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=[CsrfProtected])
async def delete_validation_policy(
    policy_id: uuid.UUID, admin: AdminUser, db: SessionDep
) -> Response:
    policy = _load(db, policy_id)
    audit.record(
        db,
        actor_id=admin.id,
        action=AUDIT_VALIDATION_POLICY_DELETED,
        target_type=AUDIT_TARGET_VALIDATION_POLICY,
        target_id=policy.id,
        from_value="enabled" if policy.enabled else "disabled",
        detail={"rule_id": policy.rule_id, "provider": policy.provider},
    )
    db.delete(policy)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
