#!/usr/bin/env python3
"""Fail when a repository-local Markdown link points at a missing file."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit

LINK = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")


def local_targets(root: Path) -> list[tuple[Path, str, Path]]:
    failures: list[tuple[Path, str, Path]] = []
    for document in sorted(root.rglob("*.md")):
        ignored = {".git", ".venv", ".mypy_cache", ".pytest_cache", ".ruff_cache"}
        if any(part in ignored for part in document.parts):
            continue
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


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    failures = local_targets(root)
    for document, target, resolved in failures:
        print(f"{document.relative_to(root)}: missing link {target!r} -> {resolved}")
    return int(bool(failures))


if __name__ == "__main__":
    sys.exit(main())
