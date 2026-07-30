"""Rule packs: the versioned, code-defined half of detection (ADR 0003, 0008).

A rule pack is YAML shipped inside the engine image, loaded once into frozen
objects. Rules are code, not runtime data — the reason ADR 0008 gives is that a
UI-editable regex is an untrusted program an engine would have to fetch, validate,
and run against every page it reads.

Loading is where a bad pack has to die. A pack that half-loads is worse than one
that refuses to: a rule silently dropped for a typo means a secret type nobody is
looking for, and nothing downstream would report its absence. So every problem
here raises :class:`RulePackError` naming the rule, and the loader has no
tolerant mode.

The checks are deliberately more than schema validation:

* **Regexes must compile**, and must survive :func:`assert_no_catastrophic_backtracking`.
  A pathological pattern in a pack that scans attachment text is an availability
  bug with a remote trigger.
* **Redaction strategies are resolved at load**, through
  :func:`~iceberg_core.redaction.RedactionPolicy.from_strategy_name`, so a typo in
  ``redaction:`` cannot fall back to revealing more than intended.
* **Ids are unique within a pack**, because a finding records only ``rule_id`` and
  two rules sharing one would make findings unattributable.
"""

import math
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from iceberg_core.enums import Severity
from iceberg_core.redaction import RedactionPolicy


class _StrictLoader(yaml.SafeLoader):
    """A safe loader that refuses duplicate mapping keys.

    PyYAML keeps the last value for a repeated key, so a rule carrying two
    ``regex:`` lines would load with the first silently discarded — the half-loaded
    rule this module exists to reject (ADR 0008)."""


def _construct_mapping_no_duplicates(
    loader: _StrictLoader, node: yaml.MappingNode
) -> dict[object, object]:
    seen: set[object] = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=True)
        if key in seen:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key {key!r}",
                key_node.start_mark,
            )
        seen.add(key)
    return loader.construct_mapping(node, deep=True)


_StrictLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping_no_duplicates
)

#: Where the packs that ship with this package live.
RULEPACK_DIR = Path(__file__).parent / "rulepacks"

#: The pack loaded when a caller does not name one.
DEFAULT_RULEPACK = "seed"

#: Keys a rule may carry. Anything else is a typo or a feature nobody implemented,
#: and both should fail rather than be ignored.
_RULE_KEYS = frozenset(
    {
        "id",
        "description",
        "severity",
        "regex",
        "flags",
        "entropy_min",
        "keywords",
        "keyword_window",
        "requires_keyword",
        "redaction",
        "redaction_keep",
        "base_confidence",
    }
)

_PACK_KEYS = frozenset({"version", "description", "rules"})

#: Regex flags a pack may ask for, by name. Not `re.VERBOSE` — whitespace that
#: does not mean whitespace is how a rule ends up matching more than its author
#: read it as.
_FLAGS = {
    "ignorecase": re.IGNORECASE,
    "multiline": re.MULTILINE,
    "dotall": re.DOTALL,
}

_RULE_ID_RE = re.compile(r"\A[a-z0-9]+(?:-[a-z0-9]+)*\Z")


class RulePackError(Exception):
    """A rule pack could not be loaded. Always names the offending rule."""


@dataclass(frozen=True, slots=True)
class Rule:
    """One detection rule, fully resolved.

    ``entropy_min``/``keywords`` are the two gates ADR 0003 describes. A rule with
    neither is pure regex — right for a structurally unmistakable secret like an
    AWS key id, wrong for anything that looks like ordinary text.
    """

    id: str
    description: str
    severity: Severity
    pattern: re.Pattern[str]

    #: Minimum Shannon entropy of the matched text. ``None`` means the regex is
    #: sufficient on its own.
    entropy_min: float | None = None

    #: Words that, near a match, make it more likely to be a real secret.
    keywords: tuple[str, ...] = ()
    #: How far either side of the match to look for them, in characters.
    keyword_window: int = 64
    #: When true, a match with no keyword nearby is discarded rather than scored
    #: down. This is what makes a generic high-entropy rule usable at all
    #: (docs/rules.md): unqualified, it matches every hash and UUID in the corpus.
    requires_keyword: bool = False

    #: How matches of this rule are masked for the stored snippet (ADR 0004).
    redaction: RedactionPolicy = field(default_factory=RedactionPolicy)

    #: Confidence before the entropy and proximity signals adjust it.
    base_confidence: float = 0.5

    #: The named capture group holding the secret, when the pattern needs context
    #: around it to match (``password=(?P<secret>…)``). Falls back to the whole
    #: match, which is what most rules want.
    SECRET_GROUP = "secret"  # noqa: S105  # a regex group name, not a credential


@dataclass(frozen=True, slots=True)
class RulePack:
    """A versioned set of rules.

    ``version`` is stamped on every finding the pack produces, so a result can be
    reproduced against the rules that made it (ADR 0008). It is a plain string
    rather than a number: packs are dated, not counted.
    """

    version: str
    rules: tuple[Rule, ...]
    description: str = ""

    def __post_init__(self) -> None:
        if not self.version.strip():
            raise RulePackError("rule pack has no version")

    def rule(self, rule_id: str) -> Rule:
        for rule in self.rules:
            if rule.id == rule_id:
                return rule
        raise KeyError(rule_id)


def load_pack(source: Path | str) -> RulePack:
    """Load a pack from a YAML file path, or from a YAML document.

    Accepting text as well as a path is what lets the tests state a two-rule pack
    inline instead of maintaining a directory of fixture files.
    """
    if isinstance(source, Path):
        try:
            raw = source.read_text(encoding="utf-8")
        except OSError as exc:
            raise RulePackError(f"cannot read rule pack {source}: {exc}") from exc
    else:
        raw = source

    try:
        document = yaml.load(raw, Loader=_StrictLoader)  # noqa: S506  # _StrictLoader is a SafeLoader
    except yaml.YAMLError as exc:
        raise RulePackError(f"rule pack is not valid YAML: {exc}") from exc

    if not isinstance(document, dict):
        raise RulePackError("rule pack must be a mapping with 'version' and 'rules'")
    _reject_unknown(document.keys(), _PACK_KEYS, "rule pack")

    entries = document.get("rules")
    if not isinstance(entries, list) or not entries:
        raise RulePackError("rule pack must define a non-empty 'rules' list")

    rules = tuple(_build_rule(entry, index) for index, entry in enumerate(entries))
    _reject_duplicate_ids(rules)

    return RulePack(
        version=str(document.get("version", "")),
        description=str(document.get("description", "")),
        rules=rules,
    )


def load_named_pack(name: str = DEFAULT_RULEPACK) -> RulePack:
    """Load one of the packs shipped in this package by bare name."""
    path = RULEPACK_DIR / f"{name}.yaml"
    if not path.is_file():
        available = ", ".join(sorted(p.stem for p in RULEPACK_DIR.glob("*.yaml"))) or "none"
        raise RulePackError(f"unknown rule pack {name!r}; available: {available}")
    return load_pack(path)


def _build_rule(entry: object, index: int) -> Rule:
    if not isinstance(entry, dict):
        raise RulePackError(f"rule #{index} is not a mapping")

    rule_id = str(entry.get("id", "")).strip()
    where = f"rule {rule_id!r}" if rule_id else f"rule #{index}"
    if not _RULE_ID_RE.match(rule_id):
        # Ids end up in URLs, suppression patterns, and metric labels; keeping them
        # to lowercase-and-hyphens means none of those need escaping rules.
        raise RulePackError(f"{where}: id must be lowercase words joined by hyphens")

    _reject_unknown(entry.keys(), _RULE_KEYS, where)

    for required in ("description", "severity", "regex"):
        value = entry.get(required)
        # A non-string scalar here is a mistake, not something to coerce: an
        # unquoted `regex: [abc]` parses as a YAML list, and `str(...)` of it would
        # compile a pattern nobody wrote instead of failing the load (ADR 0008).
        if not isinstance(value, str) or not value.strip():
            raise RulePackError(f"{where}: {required} must be a non-empty string")

    try:
        severity = Severity(entry["severity"])
    except ValueError as exc:
        known = ", ".join(member.value for member in Severity)
        raise RulePackError(f"{where}: unknown severity; known: {known}") from exc

    pattern = _compile(entry["regex"], entry.get("flags", []), where)
    keywords = _keywords(entry.get("keywords", []), where)
    requires_keyword = bool(entry.get("requires_keyword", False))
    if requires_keyword and not keywords:
        raise RulePackError(f"{where}: requires_keyword needs at least one keyword")

    try:
        redaction = RedactionPolicy.from_strategy_name(
            str(entry.get("redaction", RedactionPolicy().strategy.value)),
            **({"keep": int(entry["redaction_keep"])} if "redaction_keep" in entry else {}),
        )
    except (ValueError, TypeError) as exc:
        raise RulePackError(f"{where}: {exc}") from exc

    return Rule(
        id=rule_id,
        description=entry["description"].strip(),
        severity=severity,
        pattern=pattern,
        entropy_min=_optional_float(entry.get("entropy_min"), where, "entropy_min"),
        keywords=keywords,
        keyword_window=_positive_int(entry.get("keyword_window", 64), where, "keyword_window"),
        requires_keyword=requires_keyword,
        redaction=redaction,
        base_confidence=_unit_float(entry.get("base_confidence", 0.5), where, "base_confidence"),
    )


def _compile(source: str, flag_names: object, where: str) -> re.Pattern[str]:
    if not isinstance(flag_names, list):
        raise RulePackError(f"{where}: flags must be a list")

    flags = re.NOFLAG
    for name in flag_names:
        try:
            flags |= _FLAGS[str(name).lower()]
        except KeyError as exc:
            known = ", ".join(sorted(_FLAGS))
            raise RulePackError(f"{where}: unknown flag {name!r}; known: {known}") from exc

    assert_no_catastrophic_backtracking(source, where)
    try:
        return re.compile(source, flags)
    except re.error as exc:
        raise RulePackError(f"{where}: regex does not compile: {exc}") from exc


def assert_no_catastrophic_backtracking(pattern: str, where: str = "pattern") -> None:
    """Refuse a pattern whose worst case is exponential.

    Python's :mod:`re` is a backtracking engine with no timeout, and rules run over
    attachment text an attacker may control. The classic blow-up is an unbounded
    quantifier applied to a group that itself contains one — ``(\\w+)+`` — where the
    engine has exponentially many ways to split the same input before it can
    conclude the match failed.

    This is a static, deliberately conservative check, not a proof: it catches the
    shape that causes the failure in practice and rejects it at load time, when a
    human is reading the diff. It does not make every accepted pattern fast, so
    content units stay size-capped as well.
    """
    unbounded = _unbounded_quantifier_positions(pattern)
    for open_index, close_index in _group_spans(pattern):
        if not _followed_by_unbounded(pattern, close_index):
            continue
        if any(open_index < position < close_index for position in unbounded):
            raise RulePackError(
                f"{where}: nested unbounded quantifier at offset {open_index} "
                f"({pattern[open_index : close_index + 2]!r}); rewrite it with a bounded "
                f"repetition — this shape backtracks exponentially"
            )


def _scan(pattern: str) -> list[tuple[int, str]]:
    """(index, character) for every structural character, skipping escapes and classes."""
    out: list[tuple[int, str]] = []
    index, length = 0, len(pattern)
    while index < length:
        char = pattern[index]
        if char == "\\":
            index += 2
            continue
        if char == "[":
            index = _skip_character_class(pattern, index)
            continue
        out.append((index, char))
        index += 1
    return out


def _skip_character_class(pattern: str, index: int) -> int:
    """Return the index just past the ``[...]`` class beginning at ``index``.

    A ``]`` immediately after ``[`` or ``[^`` is a literal member, not the close —
    ``[]*]`` is a class of ``]`` and ``*``, a linear pattern that must not be
    misread as ending at the first ``]`` and rejected as catastrophic."""
    length = len(pattern)
    index += 1  # past the opening '['
    if index < length and pattern[index] == "^":
        index += 1
    if index < length and pattern[index] == "]":  # literal first member
        index += 1
    while index < length and pattern[index] != "]":
        index += 2 if pattern[index] == "\\" else 1
    return index + 1  # past the closing ']'


def _group_spans(pattern: str) -> list[tuple[int, int]]:
    """Index pairs for each ``(...)`` group, innermost first."""
    stack: list[int] = []
    spans: list[tuple[int, int]] = []
    for index, char in _scan(pattern):
        if char == "(":
            stack.append(index)
        elif char == ")" and stack:
            spans.append((stack.pop(), index))
    return spans


def _unbounded_quantifier_positions(pattern: str) -> list[int]:
    """Indexes of variable-length quantifiers (``*``, ``+``, ``{n,}``, ``{n,m}``
    with ``m != n``) outside character classes.

    A *fixed* repetition (``{n}`` or ``{n,n}``) adds no length ambiguity, so nesting
    it under an outer repetition backtracks linearly. A *variable* one does not: the
    engine has several ways to divide the same input, and ``(?:x{2,64})+`` blows up
    exactly like ``(?:x{2,})+``. Both are refused."""
    positions: list[int] = []
    for index, char in _scan(pattern):
        if char in "*+":
            positions.append(index)
        elif char == "{":
            closing = pattern.find("}", index)
            if closing != -1 and _is_variable_repetition(pattern[index + 1 : closing]):
                positions.append(index)
    return positions


def _is_variable_repetition(spec: str) -> bool:
    """Whether a ``{...}`` body describes a variable count: ``n,`` (unbounded) or
    ``n,m`` with ``m != n``. A bare ``n`` or ``n,n`` is fixed."""
    if "," not in spec:
        return False
    low, _, high = spec.partition(",")
    if high.strip() == "":
        return True
    try:
        return int(low) != int(high)
    except ValueError:
        return False


def _followed_by_unbounded(pattern: str, close_index: int) -> bool:
    """Whether the group closing at ``close_index`` is itself repeated unboundedly."""
    tail = pattern[close_index + 1 : close_index + 2]
    if tail in ("*", "+"):
        return True
    if tail == "{":
        closing = pattern.find("}", close_index)
        return closing != -1 and _is_variable_repetition(pattern[close_index + 2 : closing])
    return False


def _keywords(value: object, where: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise RulePackError(f"{where}: keywords must be a list")
    # Lowercased once here rather than per match: proximity search is case-
    # insensitive, and doing it at load keeps that out of the hot loop.
    cleaned = tuple(str(word).strip().lower() for word in value if str(word).strip())
    if len(set(cleaned)) != len(cleaned):
        raise RulePackError(f"{where}: keywords must not repeat")
    return cleaned


def _optional_float(value: object, where: str, name: str) -> float | None:
    if value is None:
        return None
    # `bool` is an `int` to Python and never a number a rule author meant.
    if isinstance(value, bool) or not isinstance(value, int | float | str):
        raise RulePackError(f"{where}: {name} must be a number")
    try:
        parsed = float(value)
    except ValueError as exc:
        raise RulePackError(f"{where}: {name} must be a number") from exc
    if not math.isfinite(parsed):
        # `.nan` would disable the gate (every comparison is False) and `.inf`
        # would make the rule dead; both are typos, not a tuning choice.
        raise RulePackError(f"{where}: {name} must be a finite number")
    if parsed < 0:
        raise RulePackError(f"{where}: {name} must not be negative")
    return parsed


def _positive_int(value: object, where: str, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int | str):
        raise RulePackError(f"{where}: {name} must be an integer")
    try:
        parsed = int(value)
    except ValueError as exc:
        raise RulePackError(f"{where}: {name} must be an integer") from exc
    if parsed <= 0:
        raise RulePackError(f"{where}: {name} must be positive")
    return parsed


def _unit_float(value: object, where: str, name: str) -> float:
    parsed = _optional_float(value, where, name)
    if parsed is None or not 0.0 <= parsed <= 1.0:
        raise RulePackError(f"{where}: {name} must be between 0 and 1")
    return parsed


def _reject_unknown(keys: Iterable[object], allowed: frozenset[str], where: str) -> None:
    surplus = sorted(str(key) for key in keys if str(key) not in allowed)
    if surplus:
        raise RulePackError(
            f"{where}: unknown key(s) {', '.join(surplus)}; known: {', '.join(sorted(allowed))}"
        )


def _reject_duplicate_ids(rules: tuple[Rule, ...]) -> None:
    seen: set[str] = set()
    for rule in rules:
        if rule.id in seen:
            raise RulePackError(f"rule {rule.id!r}: duplicate id in the same pack")
        seen.add(rule.id)
