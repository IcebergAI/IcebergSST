"""Policy persistence and fail-closed result authorization (#151)."""

import uuid

from iceberg_core.models import ValidationPolicy
from iceberg_core.validation import validator_contract, validator_supports_rule
from sqlmodel import Session, col, select

from iceberg_api.engines.schemas import FindingPayload, LeaseValidationPolicy
from iceberg_api.validation.schemas import ValidationPolicyCreate, ValidationPolicyUpdate


class PolicyConflict(ValueError):
    """A detector/provider pair already has a policy."""


class UnauthorizedValidation(ValueError):
    """An engine reported validation outside current explicit authorization."""


class InvalidPolicy(ValueError):
    """A policy names a detector/validator pair that has not been reviewed."""


def list_policies(db: Session) -> list[ValidationPolicy]:
    return list(
        db.exec(
            select(ValidationPolicy).order_by(
                col(ValidationPolicy.rule_id), col(ValidationPolicy.provider)
            )
        )
    )


def get_policy(db: Session, policy_id: uuid.UUID) -> ValidationPolicy | None:
    return db.get(ValidationPolicy, policy_id)


def create_policy(db: Session, body: ValidationPolicyCreate) -> ValidationPolicy:
    if not _valid_contract(
        body.validator_id,
        body.rule_id,
        provider=body.provider,
        contract_version=body.contract_version,
    ):
        raise InvalidPolicy("validator is not approved for this rule")
    existing = db.exec(
        select(ValidationPolicy)
        .where(col(ValidationPolicy.rule_id) == body.rule_id)
        .where(col(ValidationPolicy.provider) == body.provider)
    ).first()
    if existing is not None:
        raise PolicyConflict("a policy already exists for this rule and provider")
    policy = ValidationPolicy(**body.model_dump())
    db.add(policy)
    db.flush()
    return policy


def update_policy(
    db: Session, policy: ValidationPolicy, changes: ValidationPolicyUpdate
) -> list[str]:
    validator_id = changes.validator_id or policy.validator_id
    contract_version = changes.contract_version or policy.contract_version
    if not _valid_contract(
        validator_id,
        policy.rule_id,
        provider=policy.provider,
        contract_version=contract_version,
    ):
        raise InvalidPolicy("validator is not approved for this rule")
    changed: list[str] = []
    for name, value in changes.model_dump(exclude_unset=True).items():
        if getattr(policy, name) != value:
            setattr(policy, name, value)
            changed.append(name)
    if changed:
        db.add(policy)
    return changed


def _valid_contract(
    validator_id: str,
    rule_id: str,
    *,
    provider: str,
    contract_version: str,
) -> bool:
    return validator_supports_rule(validator_id, rule_id) and validator_contract(validator_id) == (
        provider,
        contract_version,
    )


def enabled_lease_snapshot(db: Session, *, deployment_enabled: bool) -> list[LeaseValidationPolicy]:
    """Freeze the enabled resource bounds into a lease response."""
    if not deployment_enabled:
        return []
    policies = list(
        db.exec(
            select(ValidationPolicy)
            .where(col(ValidationPolicy.enabled).is_(True))
            .order_by(col(ValidationPolicy.rule_id), col(ValidationPolicy.provider))
        )
    )
    return [
        LeaseValidationPolicy(
            policy_id=policy.id,
            rule_id=policy.rule_id,
            validator_id=policy.validator_id,
            timeout_seconds=policy.timeout_seconds,
            requests_per_minute=policy.requests_per_minute,
            max_attempts_per_task=policy.max_attempts_per_task,
        )
        for policy in policies
    ]


def require_authorized_results(
    db: Session,
    payloads: list[FindingPayload],
    *,
    deployment_enabled: bool,
) -> None:
    """Reject validation metadata not covered by a currently enabled contract."""
    reported = [payload for payload in payloads if payload.validation is not None]
    if not reported:
        return
    if not deployment_enabled:
        raise UnauthorizedValidation("credential validation is disabled by deployment policy")

    policies = list(
        db.exec(select(ValidationPolicy).where(col(ValidationPolicy.enabled).is_(True)))
    )
    authorized = {
        (
            policy.rule_id,
            policy.provider,
            policy.validator_id,
            policy.contract_version,
        )
        for policy in policies
    }
    for payload in reported:
        result = payload.validation
        if result is None:  # narrowed above; keeps type checkers honest
            continue
        key = (payload.rule_id, result.provider, result.validator_id, result.contract_version)
        if key not in authorized:
            raise UnauthorizedValidation("validation result is not covered by an enabled policy")
