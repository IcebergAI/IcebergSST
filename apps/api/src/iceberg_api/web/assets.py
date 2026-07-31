"""The vendored-asset manifest, read once per process.

``web/vendor_assets.py`` writes ``static/assets.lock.json`` with a version, a
path, and a ``sha384`` integrity for every third-party file the UI loads.
``base.html`` reads this to emit ``integrity=`` attributes, which is the half of
the strict-CSP story ``script-src 'self'`` does not cover: same-origin says
*where* a script came from, SRI says *that it is the file we reviewed*.
"""

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

STATIC_DIR = Path(__file__).resolve().parent / "static"
TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
LOCK_PATH = STATIC_DIR / "assets.lock.json"


class AssetError(RuntimeError):
    """The manifest is missing or does not describe an asset a template needs."""


@lru_cache(maxsize=1)
def asset_manifest() -> dict[str, dict[str, Any]]:
    """Every vendored asset, keyed by the name templates use.

    Cached for the process: the file is written at build time and never changes
    while the app is running, and re-reading it per request would put a disk hit
    in front of every page render.
    """
    try:
        loaded = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise AssetError(
            f"{LOCK_PATH} is missing; regenerate it with `uv run python web/vendor_assets.py`"
        ) from exc
    except json.JSONDecodeError as exc:
        raise AssetError(f"{LOCK_PATH} is not valid JSON") from exc

    for name, entry in loaded.items():
        if not isinstance(entry, dict) or "path" not in entry or "integrity" not in entry:
            raise AssetError(f"asset {name!r} is missing its path or integrity")
    return dict(loaded)
