"""``GET /rules`` — what the fleet is actually detecting (#70, ADR 0008).

Read-only, and deliberately sourced from the engines rather than from anything the
API ships. Rule packs live inside engine images: the API has no rule pack to
list, and one hard-coded here would describe what the fleet is *supposed* to be
running, which is exactly the thing this endpoint exists to check.

That makes disagreement a first-class answer rather than an error. During a rolling
deploy two rule-pack versions are both in force, and a response that picked one
would be wrong about half the fleet — so the payload reports every version seen,
how many engines report each, and which rules that yields.

Rules are metadata only: id, description, severity. The regex stays in the image
(ADR 0008), and an API that served patterns would be inviting a client to
re-implement detection against them.
"""

from collections import defaultdict

import structlog
from fastapi import APIRouter
from iceberg_core.enums import EngineStatus, Severity
from iceberg_core.models import Engine
from pydantic import BaseModel, ConfigDict, Field
from sqlmodel import col, select

from iceberg_api.auth.dependencies import SessionDep, SettingsDep
from iceberg_api.auth.rbac import ViewerUser

router = APIRouter(prefix="/rules", tags=["rules"])
logger = structlog.get_logger()

#: Engines in these states are not running anything, so their pack is history.
_LIVE_STATUSES = (EngineStatus.ACTIVE, EngineStatus.DRAINING)


class RulepackVersionRead(BaseModel):
    """One rule-pack version in force, and who is running it."""

    version: str
    engine_count: int
    #: Named so an operator mid-deploy can see *which* engine is behind.
    engines: list[str] = Field(default_factory=list)
    rule_count: int


class RuleRead(BaseModel):
    """One rule, as reported by the engines running it."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    description: str
    severity: Severity
    #: Every pack version defining this rule. More than one during a deploy; a
    #: rule missing from a version an engine still runs is why this is a list.
    rulepack_versions: list[str] = Field(default_factory=list)


class RulesRead(BaseModel):
    """``GET /rules``: the detection surface currently in force."""

    #: False during a rolling deploy, or when an engine is running a stale image.
    #: A finding's `rulepack_version` says which pack produced it either way.
    fleet_consistent: bool
    rulepack_versions: list[RulepackVersionRead]
    rules: list[RuleRead]
    #: The minimum confidence a match needs to be stored. Served here because it
    #: is as much a part of "what gets detected" as the rules are.
    confidence_threshold: float
    #: Engines that have not reported a pack yet — registered but never heartbeat,
    #: or running an image too old to report one.
    engines_without_a_rulepack: list[str] = Field(default_factory=list)


@router.get("")
async def list_rules(user: ViewerUser, db: SessionDep, settings: SettingsDep) -> RulesRead:
    """List the rules the live fleet reports, with their pack versions."""
    engines = list(db.exec(select(Engine).where(col(Engine.status).in_(_LIVE_STATUSES))))

    versions: dict[str, list[str]] = defaultdict(list)
    rule_counts: dict[str, int] = {}
    # rule id -> (description, severity, versions). First reporter wins on the
    # description: two packs describing one rule differently is a curiosity, not
    # something to surface as two rules.
    rules: dict[str, tuple[str, Severity, set[str]]] = {}
    silent: list[str] = []

    for engine in engines:
        report = engine.rulepack or {}
        version = str(report.get("version") or "").strip()
        if not version:
            silent.append(engine.name)
            continue

        versions[version].append(engine.name)
        entries = report.get("rules")
        entries = entries if isinstance(entries, list) else []
        rule_counts[version] = len(entries)

        for entry in entries:
            if not isinstance(entry, dict):  # pragma: no cover — schema-validated on the way in
                continue
            rule_id = str(entry.get("id", "")).strip()
            if not rule_id:
                continue
            description, severity, seen = rules.get(
                rule_id, (str(entry.get("description", "")), _severity(entry), set())
            )
            rules[rule_id] = (description, severity, seen | {version})

    return RulesRead(
        fleet_consistent=len(versions) <= 1,
        rulepack_versions=[
            RulepackVersionRead(
                version=version,
                engine_count=len(names),
                engines=sorted(names),
                rule_count=rule_counts.get(version, 0),
            )
            for version, names in sorted(versions.items())
        ],
        rules=[
            RuleRead(
                id=rule_id,
                description=description,
                severity=severity,
                rulepack_versions=sorted(seen),
            )
            for rule_id, (description, severity, seen) in sorted(rules.items())
        ],
        confidence_threshold=settings.confidence_threshold,
        engines_without_a_rulepack=sorted(silent),
    )


def _severity(entry: dict[str, object]) -> Severity:
    """A reported severity, or the safest default.

    Registration validates this, so an unusable value means a row written before
    that validation existed. `medium` rather than a crash: a rules listing is a
    read-only view, and failing it wholesale over one malformed row would be a
    worse outcome than showing the rule with a placeholder severity.
    """
    try:
        return Severity(str(entry.get("severity", "")))
    except ValueError:
        logger.info("rulepack_rule_severity_unreadable", rule_id=str(entry.get("id", "")))
        return Severity.MEDIUM
