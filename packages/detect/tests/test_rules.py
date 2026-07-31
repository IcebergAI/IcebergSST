"""Rule-pack loading and validation (#41).

The property under test throughout: a bad pack raises. A rule silently dropped
for a typo is a secret type nobody is looking for, and nothing downstream would
report its absence.
"""

import textwrap
from pathlib import Path

import pytest
from iceberg_core.enums import Severity
from iceberg_core.redaction import RedactionStrategy
from iceberg_detect.rules import (
    RULEPACK_DIR,
    RulePackError,
    assert_no_catastrophic_backtracking,
    load_named_pack,
    load_pack,
)

MINIMAL = """
version: "2026.01.1"
rules:
  - id: example-rule
    description: An example
    severity: high
    regex: 'AKIA[0-9A-Z]{16}'
"""


#: The `rules:` half of a valid pack, for tests about the pack-level fields.
_ONE_RULE = "rules: [{id: a, description: d, severity: low, regex: x}]"

#: A valid one-rule pack, per field. Tests override one field at a time, so the
#: failure under test is the only thing wrong with the document.
_DEFAULTS = {
    "id": "example-rule",
    "description": "An example",
    "severity": "high",
    "regex": "'AKIA[0-9A-Z]{16}'",
}


def _pack(*overrides: str, version: str = '"2026.01.1"') -> str:
    """A single-rule pack with ``overrides`` replacing or adding rule fields."""
    replaced = {line.split(":", 1)[0].strip() for line in overrides}
    fields = [f"{key}: {value}" for key, value in _DEFAULTS.items() if key not in replaced]
    fields += list(overrides)
    body = "\n".join([f"  - {fields[0]}", *(f"    {field}" for field in fields[1:])])
    return f"version: {version}\nrules:\n{body}\n"


def test_a_minimal_pack_loads_into_typed_rules() -> None:
    pack = load_pack(MINIMAL)

    assert pack.version == "2026.01.1"
    rule = pack.rule("example-rule")
    assert rule.severity is Severity.HIGH
    assert rule.pattern.search("AKIAIOSFODNN7EXAMPLE") is not None
    # Defaults: regex alone, no proximity requirement, nothing revealed.
    assert rule.entropy_min is None
    assert rule.keywords == ()
    assert rule.redaction.strategy is RedactionStrategy.FULL


def test_the_packaged_seed_pack_loads() -> None:
    """The pack that ships in the image is exercised by the same loader."""
    pack = load_named_pack()

    assert pack.version
    assert len(pack.rules) > 10
    assert len({rule.id for rule in pack.rules}) == len(pack.rules)


def test_an_unknown_pack_name_says_what_is_available() -> None:
    with pytest.raises(RulePackError, match="available:"):
        load_named_pack("does-not-exist")


def test_every_shipped_pack_loads() -> None:
    """A pack added to the directory is covered without touching this test."""
    packs = sorted(RULEPACK_DIR.glob("*.yaml"))

    assert packs, "no rule packs ship with this package"
    for path in packs:
        assert load_pack(Path(path)).rules


@pytest.mark.parametrize(
    ("body", "message"),
    [
        ("regex: '[unclosed'", "does not compile"),
        ("severity: apocalyptic", "unknown severity"),
        ("redaction: keep_everything", "unknown redaction strategy"),
        ("flags: [verbose]", "unknown flag"),
        ("entropy_min: high", "must be a number"),
        ("entropy_min: -1", "must not be negative"),
        ("entropy_min: .nan", "must be a finite number"),
        ("entropy_min: .inf", "must be a finite number"),
        ("regex: [abc]", "regex must be a non-empty string"),
        ("regex: 42", "regex must be a non-empty string"),
        ("keyword_window: 0", "must be positive"),
        ("base_confidence: 1.5", "must be between 0 and 1"),
        ("keywords: [aws, aws]", "must not repeat"),
        ("requires_keyword: true", "requires_keyword needs at least one keyword"),
        ("colour: blue", "unknown key"),
    ],
)
def test_a_bad_rule_field_fails_at_load_naming_the_rule(body: str, message: str) -> None:
    with pytest.raises(RulePackError, match=message) as raised:
        load_pack(_pack(body))

    assert "example-rule" in str(raised.value)


@pytest.mark.parametrize(
    ("document", "message"),
    [
        ("[]", "must be a mapping"),
        ('version: "1"', "non-empty 'rules' list"),
        ('version: "1"\nrules: []', "non-empty 'rules' list"),
        ('version: "1"\nrules: [1]', "not a mapping"),
        (
            'version: "1"\nextra: no\nrules: [{id: a, description: d, severity: low, regex: x}]',
            "unknown key",
        ),
        ('version: "1"\nrules: \'[unbalanced', "not valid YAML"),
        (
            'version: "1"\nrules:\n  - id: a\n    description: d\n    severity: low\n'
            "    regex: 'a'\n    regex: 'b'\n",
            "duplicate key",
        ),
    ],
)
def test_a_malformed_pack_fails_at_load(document: str, message: str) -> None:
    with pytest.raises(RulePackError, match=message):
        load_pack(document)


def test_a_pack_without_a_version_is_refused() -> None:
    """The version is stamped on every finding; without it nothing is reproducible."""
    with pytest.raises(RulePackError, match="no version"):
        load_pack(_ONE_RULE)


@pytest.mark.parametrize("version", ['"  "', "", "null", "true", "2026.1"])
def test_a_pack_version_must_be_a_non_empty_yaml_string(version: str) -> None:
    """Coercing with `str()` turned a valueless `version:` key into the literal
    "None", which passes every non-empty check and is then stamped on every finding
    the pack produces."""
    with pytest.raises(RulePackError, match="version must be a non-empty string"):
        load_pack(f"version: {version}\n{_ONE_RULE}")


@pytest.mark.parametrize("description", ["", "null", "false", "3"])
def test_a_pack_description_is_held_to_the_same_standard(description: str) -> None:
    with pytest.raises(RulePackError, match="description must be a non-empty string"):
        load_pack(f'version: "1"\ndescription: {description}\n{_ONE_RULE}')


def test_a_pack_may_omit_its_description_entirely() -> None:
    """Absent is a choice; present-but-valueless is a typo."""
    assert load_pack(f'version: "1"\n{_ONE_RULE}').description == ""


def test_duplicate_rule_ids_are_refused() -> None:
    """A finding records only `rule_id`; two rules sharing one is unattributable."""
    document = textwrap.dedent("""
        version: "2026.01.1"
        rules:
          - id: same-id
            description: First
            severity: low
            regex: 'a'
          - id: same-id
            description: Second
            severity: low
            regex: 'b'
    """)

    with pytest.raises(RulePackError, match="duplicate id"):
        load_pack(document)


@pytest.mark.parametrize("rule_id", ["Has-Caps", "under_scored", "trailing-", "", "has space"])
def test_a_rule_id_must_be_lowercase_hyphenated(rule_id: str) -> None:
    """Ids reach URLs, suppression patterns, and metric labels unescaped."""
    document = textwrap.dedent(f"""
        version: "2026.01.1"
        rules:
          - id: "{rule_id}"
            description: An example
            severity: low
            regex: 'a'
    """)

    with pytest.raises(RulePackError, match="lowercase words joined by hyphens"):
        load_pack(document)


def test_a_missing_file_says_so() -> None:
    with pytest.raises(RulePackError, match="cannot read rule pack"):
        load_pack(Path("/nonexistent/pack.yaml"))


def test_redaction_keep_is_carried_onto_the_policy() -> None:
    pack = load_pack(_pack("redaction: keep_prefix", "redaction_keep: 8"))

    policy = pack.rule("example-rule").redaction
    assert policy.strategy is RedactionStrategy.KEEP_PREFIX
    assert policy.keep == 8


def test_an_unknown_rule_id_is_a_key_error() -> None:
    with pytest.raises(KeyError):
        load_pack(MINIMAL).rule("no-such-rule")


@pytest.mark.parametrize(
    "pattern",
    [
        r"(\w+)+",
        r"(a+)*b",
        r"(x*)+y",
        r"([A-Za-z0-9]+)+=",
        r"(?:[a-z]{2,})+",
        # A variable-width bounded range is as exponential as an unbounded one when
        # a group repeats it: the engine has many ways to divide the same input.
        r"(?:[a-z]{2,64})+X",
        # `{,n}` is Python's own spelling of `{0,n}`; reading the empty low bound as
        # a parse failure classified this as fixed and let it through.
        r"(?:x{,64})+X",
        r"(?:\w{1,8})+$",
        r"([a-z]{3,5})*z",
    ],
)
def test_exponential_patterns_are_refused_at_load(pattern: str) -> None:
    """`re` has no timeout, and rules run over attacker-supplied attachment text."""
    with pytest.raises(RulePackError, match="nested unbounded quantifier"):
        assert_no_catastrophic_backtracking(pattern)


@pytest.mark.parametrize("pattern", [r"(a|a)+b", r"(?:a|ab)+c", r"(a|a|b)*x", r"(?:ab|a){2,64}"])
def test_repeated_alternations_are_refused_at_load(pattern: str) -> None:
    """Branches that can match the same text give the engine exponentially many ways
    to reach one position — `(a|a)+b` quadruples per two characters of input. Which
    branches overlap is not decidable here, so the whole shape is refused."""
    with pytest.raises(RulePackError, match="repeated alternation"):
        assert_no_catastrophic_backtracking(pattern)


@pytest.mark.parametrize(
    "pattern",
    [
        r"AKIA[0-9A-Z]{16}",
        r"(?:AKIA|ASIA)[0-9A-Z]{16}",
        r"gh[pousr]_[A-Za-z0-9]{36,255}",
        r"-----BEGIN [\s\S]{0,8000}?-----END",
        r"(?P<secret>[^@/\s]{6,128})@",
        r"(a+)b+",  # two quantifiers, but neither repeats the other
        r"\(\w+\)+",  # escaped parens are literals, not a group
        r"[(]a+[)]+",  # a bracketed paren is a character, not a group
        r"([]*]x)*y",  # a literal leading ] is a class member, not the close
        r"(?:[a-z]{4})+X",  # a fixed count adds no ambiguity to divide
        r"(?:[a-z]{3,3})+X",  # an equal-bound range is fixed too
        r"(?:AKIA|ASIA)x*",  # an alternation nothing repeats
        r"(?:RSA |EC )?PRIVATE",  # at most one repetition, so no way to divide
        r"(?:(?:a|b)x)+",  # the `|` belongs to the inner group, which is not repeated
    ],
)
def test_safe_patterns_are_accepted(pattern: str) -> None:
    assert_no_catastrophic_backtracking(pattern)


def test_the_shipped_pack_passes_the_backtracking_check() -> None:
    """Belt and braces: the check runs at load, so this asserts it was not bypassed."""
    for path in RULEPACK_DIR.glob("*.yaml"):
        load_pack(Path(path))
