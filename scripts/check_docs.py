#!/usr/bin/env python3
"""Fail when the documentation refers to something that is not there.

Three kinds of rot, each cheap to detect and expensive to find by hand:

* **A link to a file that has moved.** The original check, and still the common
  one — a runbook renamed with its references left behind reads as a complete
  document right up to the moment somebody clicks.
* **A `make` target that no longer exists.** The docs are full of `make check`,
  `make rehearse`, `make helm-verify`. A renamed target leaves an instruction
  that fails on the first command a new contributor runs, which is the worst
  possible place to have a stale doc.
* **A configuration variable that no longer exists.** Every setting is
  `ICEBERG_`-prefixed, which makes them findable in prose without a vocabulary
  list. Checked against the settings classes rather than against `.env.example`:
  the example file is the *compose* surface (`tests/test_deploy_invariants.py`
  holds it to that), while a renamed field is the drift that leaves an operator
  setting a variable nothing reads.

Scoped to files git tracks. `rglob("*.md")` also walks a contributor's local tool
directories, which is how this exits non-zero on a permission error in a file
that has nothing to do with the project — and a check that fails for reasons
unrelated to the change is one people learn to ignore.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit

LINK = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")

#: `make check` **as code** — inline backticks, or a line in a fenced block.
#: Matching it in prose would catch "make it clear" and "make the engine", which
#: is how a check like this ends up being one people disable.
MAKE_TARGET = re.compile(
    r"`make ([a-z][a-z0-9-]*)[^`]*`"  # inline code
    r"|^\s{0,3}make ([a-z][a-z0-9-]*)",  # a command line in a fenced block
    re.MULTILINE,
)

#: A Makefile target definition, ignoring the pattern rules and `.PHONY`.
MAKE_DEFINITION = re.compile(r"^([a-z][a-z0-9-]*):", re.MULTILINE)

#: A configuration variable, wherever it is written. All of them share a prefix,
#: which is what makes this findable without a vocabulary list.
ENV_VARIABLE = re.compile(r"\bICEBERG_[A-Z0-9_]+\b")

#: Named in documentation but not a settings field: variables read by something
#: other than pydantic-settings, or supplied per-run rather than configured.
ENV_EXEMPT = frozenset(
    {
        # Read by the compose stack rather than by pydantic-settings: it selects
        # the published port, which no application code has an opinion about.
        "ICEBERG_API_PORT",
    }
)


def tracked_documents(root: Path) -> list[Path]:
    """Every Markdown file git tracks, as absolute paths."""
    listed = subprocess.run(  # git, with a fixed argument list
        ["git", "ls-files", "-z", "*.md"],  # noqa: S607  # resolved from PATH, as everywhere else
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    )
    return [root / name for name in listed.stdout.split("\0") if name]


def local_targets(root: Path) -> list[tuple[Path, str, Path]]:
    """Repository-local links that point at nothing."""
    failures: list[tuple[Path, str, Path]] = []
    for document in tracked_documents(root):
        text = document.read_text(encoding="utf-8")
        for raw in LINK.findall(text):
            target = raw.strip().split(maxsplit=1)[0].strip("<>")
            parsed = urlsplit(target)
            if parsed.scheme or parsed.netloc or target.startswith("#"):
                continue
            path = (document.parent / unquote(parsed.path)).resolve()
            if not path.is_relative_to(root.resolve()) or not path.exists():
                failures.append((document, target, path))
    return failures


def make_targets(root: Path) -> list[tuple[Path, str]]:
    """Documented `make` commands with no matching target."""
    defined = set(MAKE_DEFINITION.findall((root / "Makefile").read_text(encoding="utf-8")))
    if not defined:  # pragma: no cover — the pattern would be silently checking nothing
        raise ValueError("no targets found in the Makefile; the pattern is wrong")

    failures: list[tuple[Path, str]] = []
    for document in tracked_documents(root):
        for inline, fenced in MAKE_TARGET.findall(document.read_text(encoding="utf-8")):
            name = inline or fenced
            if name and name not in defined:
                failures.append((document, name))
    return failures


def settings_variables() -> set[str]:
    """Every `ICEBERG_*` variable the settings classes actually read."""
    from iceberg_core.config import (
        ApiSettings,
        CoreSettings,
        EngineSettings,
        SecretStoreSettings,
    )

    # Both roles, because the deployment docs configure both and a variable only
    # the engine reads is no less real than one only the API does.
    names: set[str] = set()
    for model in (CoreSettings, SecretStoreSettings, ApiSettings, EngineSettings):
        prefix = model.model_config.get("env_prefix", "")
        names.update(f"{prefix}{field}".upper() for field in model.model_fields)
    return names


def env_variables(root: Path) -> list[tuple[Path, str]]:
    """Documented configuration variables that no settings field backs."""
    documented = settings_variables() | ENV_EXEMPT
    if not documented:  # pragma: no cover — same reasoning as above
        raise ValueError("no settings fields found; the reflection is wrong")

    failures: list[tuple[Path, str]] = []
    for document in tracked_documents(root):
        for name in ENV_VARIABLE.findall(document.read_text(encoding="utf-8")):
            if name not in documented:
                failures.append((document, name))
    return failures


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    failed = False

    for document, target, resolved in local_targets(root):
        failed = True
        print(f"{document.relative_to(root)}: missing link {target!r} -> {resolved}")
    for document, name in make_targets(root):
        failed = True
        print(f"{document.relative_to(root)}: documents `make {name}`, which the Makefile has not")
    for document, name in env_variables(root):
        failed = True
        print(f"{document.relative_to(root)}: names {name}, which no setting backs")

    if not failed:
        print(f"{len(tracked_documents(root))} documents check out")
    return int(failed)


if __name__ == "__main__":
    sys.exit(main())
