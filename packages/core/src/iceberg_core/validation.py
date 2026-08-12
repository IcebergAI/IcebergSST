"""Reviewed detector/validator eligibility shared across API and engines."""

# Exact pairs only. Adding a detector here is a security review decision: policy
# CRUD rejects every other combination, even when an administrator supplies a
# syntactically valid validator id.
VALIDATOR_RULES: dict[str, frozenset[str]] = {
    "github-token-v1": frozenset({"github-token", "github-fine-grained-pat"}),
}
VALIDATOR_CONTRACTS: dict[str, tuple[str, str]] = {
    "github-token-v1": ("github", "1"),
}


def validator_supports_rule(validator_id: str, rule_id: str) -> bool:
    return rule_id in VALIDATOR_RULES.get(validator_id, frozenset())


def validator_contract(validator_id: str) -> tuple[str, str] | None:
    return VALIDATOR_CONTRACTS.get(validator_id)


__all__ = [
    "VALIDATOR_CONTRACTS",
    "VALIDATOR_RULES",
    "validator_contract",
    "validator_supports_rule",
]
