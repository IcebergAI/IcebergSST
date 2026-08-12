"""The packaged guidance catalog: loading, validation, lookup (#142, ADR 0011).

Guidance lives beside the API rather than inside rule packs: rule packs ship in
engine images, so guidance riding them would couple advice releases to engine
rollouts and force the closed engine wire schema (`extra="forbid"`) to grow.
Advice is operator-facing content only the API renders — versioned in git like
a rule pack, decoupled from every deployable but this one.

Validation is loud and at startup: a catalog with an unknown key or a missing
``default`` entry fails the process, not the first analyst to open a finding.
"""

from functools import lru_cache
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

CATALOG_PATH = Path(__file__).parent / "guidance.yaml"


class GuidanceEntry(BaseModel):
    """Advice for one rule id: the four actions #142 requires kept separate."""

    model_config = ConfigDict(extra="forbid")

    title: str = Field(min_length=1, max_length=200)
    revoke: list[str] = Field(default_factory=list)
    rotate: list[str] = Field(default_factory=list)
    scope_reduce: list[str] = Field(default_factory=list)
    remove_source: list[str] = Field(default_factory=list)
    #: Provider documentation URLs, rendered as links.
    references: list[str] = Field(default_factory=list)


class GuidanceCatalog(BaseModel):
    """The whole pack. ``entries`` must include ``default``."""

    model_config = ConfigDict(extra="forbid")

    version: str = Field(min_length=1, max_length=64)
    entries: dict[str, GuidanceEntry]

    def lookup(self, rule_id: str) -> tuple[GuidanceEntry, Literal["rule", "default"]]:
        """The entry for ``rule_id``, falling back to ``default``.

        The second element says which was served, so the UI can be honest about
        showing generic advice for a rule with no entry of its own.
        """
        entry = self.entries.get(rule_id)
        if entry is not None:
            return entry, "rule"
        return self.entries["default"], "default"


class GuidanceError(ValueError):
    """The packaged catalog is malformed — a packaging bug, not user input."""


@lru_cache(maxsize=1)
def load_catalog() -> GuidanceCatalog:
    """Parse and validate the packaged catalog once per process."""
    try:
        raw = yaml.safe_load(CATALOG_PATH.read_text())
    except (OSError, yaml.YAMLError) as exc:
        raise GuidanceError(f"guidance catalog unreadable: {exc}") from exc
    catalog = GuidanceCatalog.model_validate(raw)
    if "default" not in catalog.entries:
        raise GuidanceError("guidance catalog must carry a 'default' entry")
    return catalog
