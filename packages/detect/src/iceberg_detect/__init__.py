"""Detection engine and versioned rule packs (regex + entropy + keyword proximity).

Importable surface for the engine worker (ADR 0002/0003)::

    pack = load_named_pack()                       # the packaged seed pack
    result = detect(unit_text, pack, threshold=…)  # redacted, scored matches

Nothing here touches the database or the network, and nothing here reads the
environment: a rule pack is a file in this package, and the threshold arrives from
the caller. That is what lets the engine import it without acquiring either.
"""

from iceberg_detect.engine import (
    DEFAULT_CONFIDENCE_THRESHOLD,
    MAX_MATCHES_PER_UNIT,
    DetectedSecret,
    DetectionResult,
    detect,
)
from iceberg_detect.rules import (
    DEFAULT_RULEPACK,
    Rule,
    RulePack,
    RulePackError,
    load_named_pack,
    load_pack,
)
from iceberg_detect.signals import Signals, confidence, keyword_near, shannon_entropy

__version__ = "0.1.0"

__all__ = [
    "DEFAULT_CONFIDENCE_THRESHOLD",
    "DEFAULT_RULEPACK",
    "MAX_MATCHES_PER_UNIT",
    "DetectedSecret",
    "DetectionResult",
    "Rule",
    "RulePack",
    "RulePackError",
    "Signals",
    "__version__",
    "confidence",
    "detect",
    "keyword_near",
    "load_named_pack",
    "load_pack",
    "shannon_entropy",
]
