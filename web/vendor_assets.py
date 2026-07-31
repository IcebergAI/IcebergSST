#!/usr/bin/env python3
"""Vendor the web UI's frontend dependencies and write ``assets.lock.json``.

The UI serves every runtime frontend dependency from ``/static`` (first-party)
rather than a CDN, with Subresource Integrity on each vendored file. That is what
makes the strict Content-Security-Policy in ``iceberg_api.web.security`` possible:
``script-src 'self'`` with no ``'unsafe-inline'`` and no ``'unsafe-eval'``, and a
``font-src 'self'`` that keeps the app working offline and inside an air-gapped
deployment.

This script is the reproducible regenerator. It pins exact upstream versions
below, downloads each asset into ``apps/api/src/iceberg_api/web/static/``, and
writes ``static/assets.lock.json`` (version + path + ``sha384`` integrity), which
``base.html`` reads to emit the ``integrity=`` attributes.

There is no Node toolchain and no CSS build step: the design system is
hand-authored plain CSS (``static/css/iceberg.css``), the same choice IcebergCM
made — see ``docs/web.md`` § Asset pipeline for why Tailwind is not in the loop.

Sources are **npm registry tarballs**, not a CDN: a jsdelivr/unpkg URL is a third
party in the supply chain and is unreachable from a locked-down build network,
while ``registry.npmjs.org`` is what the lock file already trusts.

Usage (after editing a pin to bump a version):

    uv run python web/vendor_assets.py

``apps/api/tests/test_web_invariants.py`` verifies the committed files against
the lock offline, so CI notices a hand-edited vendor file without a network call.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import re
import sys
import tarfile
from pathlib import Path

import httpx

# --------------------------------------------------------------------------- #
# Pinned versions — bump here, re-run, review the diff, commit the result.
# --------------------------------------------------------------------------- #

#: The CSP build of Alpine (``@alpinejs/csp``), which evaluates directive
#: expressions without ``eval()``. The cost is that every ``x-data`` must name a
#: component registered through ``Alpine.data()`` — see ``static/js/tags.js``.
ALPINE_VERSION = "3.15.12"
HTMX_VERSION = "2.0.10"

#: Mirrors the font families the design system declares (``--fs-sans`` /
#: ``--fs-mono`` / ``--fs-serif``). Only latin + latin-ext are kept.
FONTS_CSS_URL = (
    "https://fonts.googleapis.com/css2?"
    "family=Archivo:wght@400;500;600;700;800&"
    "family=JetBrains+Mono:wght@400;500;600;700&"
    "family=Spectral:ital,wght@0,400;0,500;0,600;1,400&display=swap"
)
KEEP_FONT_SUBSETS = {"latin", "latin-ext"}

#: A modern desktop UA, so the css2 endpoint answers with woff2 @font-face blocks
#: rather than the ttf fallback it serves to unknown clients.
_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "apps" / "api" / "src" / "iceberg_api" / "web" / "static"
LOCK_PATH = STATIC / "assets.lock.json"
TIMEOUT = 60.0


def sri(data: bytes) -> str:
    """Subresource-Integrity digest string: ``sha384-<base64>``."""
    return "sha384-" + base64.b64encode(hashlib.sha384(data).digest()).decode("ascii")


def _write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def _get(url: str, **kwargs: object) -> httpx.Response:
    response = httpx.get(url, timeout=TIMEOUT, follow_redirects=True, **kwargs)  # type: ignore[arg-type]
    response.raise_for_status()
    return response


def _from_npm(package: str, version: str, member: str) -> bytes:
    """One file out of an npm tarball, without unpacking the rest of it."""
    # The registry's tarball URL drops any scope from the filename:
    # @alpinejs/csp -> .../@alpinejs/csp/-/csp-3.15.12.tgz
    basename = package.rsplit("/", 1)[-1]
    url = f"https://registry.npmjs.org/{package}/-/{basename}-{version}.tgz"
    with tarfile.open(fileobj=io.BytesIO(_get(url).content), mode="r:gz") as archive:
        extracted = archive.extractfile(f"package/{member}")
        if extracted is None:  # pragma: no cover — a bad pin, not a runtime path
            raise SystemExit(f"{package}@{version} has no {member}")
        return extracted.read()


def vendor_alpine() -> dict[str, object]:
    data = _from_npm("@alpinejs/csp", ALPINE_VERSION, "dist/cdn.min.js")
    rel = "js/vendor/alpine.min.js"
    _write(STATIC / rel, data)
    print(f"  alpine (csp) {ALPINE_VERSION}  ({len(data):,} bytes)")
    return {"version": ALPINE_VERSION, "path": rel, "integrity": sri(data)}


def vendor_htmx() -> dict[str, object]:
    data = _from_npm("htmx.org", HTMX_VERSION, "dist/htmx.min.js")
    rel = "js/vendor/htmx.min.js"
    _write(STATIC / rel, data)
    print(f"  htmx         {HTMX_VERSION}  ({len(data):,} bytes)")
    return {"version": HTMX_VERSION, "path": rel, "integrity": sri(data)}


_FACE_RE = re.compile(r"/\*\s*(?P<subset>[\w-]+)\s*\*/\s*(?P<block>@font-face\s*\{.*?\})", re.S)
_FAMILY_RE = re.compile(r"font-family:\s*'([^']+)'")
_WEIGHT_RE = re.compile(r"font-weight:\s*(\d+)")
_STYLE_RE = re.compile(r"font-style:\s*(\w+)")
_URL_RE = re.compile(r"url\((https://fonts\.gstatic\.com/[^)]+\.woff2)\)")


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def vendor_fonts() -> dict[str, object]:
    """Download the woff2 files and rewrite the @font-face CSS to point at /static.

    Self-hosted rather than linked: a Google Fonts ``<link>`` would need
    ``font-src``/``style-src`` to name a third party, and the app has to render in
    a network that cannot reach one.
    """
    css = _get(FONTS_CSS_URL, headers={"User-Agent": _UA}).text
    kept: list[str] = []
    seen: set[str] = set()

    for match in _FACE_RE.finditer(css):
        subset = match.group("subset")
        if subset not in KEEP_FONT_SUBSETS:
            continue
        block = match.group("block")
        url_match = _URL_RE.search(block)
        family_match = _FAMILY_RE.search(block)
        if not url_match or not family_match:
            continue

        family = family_match.group(1)
        weight_match = _WEIGHT_RE.search(block)
        style_match = _STYLE_RE.search(block)
        weight = weight_match.group(1) if weight_match else "400"
        style = style_match.group(1) if style_match else "normal"

        filename = f"{_slug(family)}-{weight}-{style}-{subset}.woff2"
        if filename not in seen:
            _write(STATIC / "fonts" / filename, _get(url_match.group(1)).content)
            seen.add(filename)
        kept.append(
            f"/* {family} {weight} {style} {subset} */\n"
            + block.replace(url_match.group(1), f"/static/fonts/{filename}")
        )

    if not kept:
        raise SystemExit("no @font-face blocks parsed — did the css2 response shape change?")

    body = (
        "/* Generated by web/vendor_assets.py — self-hosted Google Fonts.\n"
        "   Do not edit by hand; re-run the script to regenerate. */\n\n" + "\n\n".join(kept) + "\n"
    )
    data = body.encode("utf-8")
    rel = "css/vendor/fonts.css"
    _write(STATIC / rel, data)
    print(f"  fonts        {len(seen)} woff2  ({len(data):,} bytes css)")
    return {
        "version": "google-fonts",
        "path": rel,
        "integrity": sri(data),
        "files": sorted(seen),
    }


def main() -> int:
    print("Vendoring the web UI's frontend assets…")
    lock = {
        "alpine": vendor_alpine(),
        "htmx": vendor_htmx(),
        "fonts": vendor_fonts(),
    }
    LOCK_PATH.write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Wrote {LOCK_PATH.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
