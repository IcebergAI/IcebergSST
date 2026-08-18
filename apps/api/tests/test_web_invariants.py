"""Invariants that keep the web UI a client of the API rather than a second one.

The M3 UI could very easily have grown its own queries — it renders lists and
details, and a `select()` is right there. That would give the product two
implementations of "which findings may this person see", and the one nobody
audits is the one that leaks. So the boundary is asserted here rather than
described in a comment:

* no module under ``iceberg_api.web`` touches the database;
* every mutating browser route carries CSRF protection;
* no HTML endpoint appears in the OpenAPI document;
* the vendored assets on disk are the ones the lock file describes.
"""

import ast
import base64
import hashlib
import json
import re
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.routing import APIRoute
from iceberg_api.app import API_PREFIX
from iceberg_api.auth.dependencies import require_csrf
from iceberg_api.web import assets as web_assets
from iceberg_api.web.routes import router as web_router

WEB_PACKAGE = Path(web_assets.__file__).resolve().parent
WEB_MODULES = sorted(WEB_PACKAGE.rglob("*.py"))

#: Ways a module would reach the database. The web layer must use none of them —
#: it holds a `Session` only to hand it to the API handler it is calling.
FORBIDDEN_CALLS = frozenset({"select", "exec", "commit", "refresh", "flush"})
FORBIDDEN_IMPORTS = ("sqlmodel", "sqlalchemy", "iceberg_core.db")

#: The shared Iceberg palette, copied from the canonical source —
#: ``IcebergCM/src/icebergcm/web/static/app.css``, which carries the same values
#: as ``iceberg``'s ``iceberg.css`` (docs/web.md § Provenance). Pinned here rather
#: than read from a sibling checkout because CI has no sibling checkout: the point
#: is to fail when *this* repo drifts, and the fix is to go back to that file.
CANONICAL_TOKENS = {
    "--accent": "oklch(0.66 0.118 226)",
    "--ink": "oklch(0.26 0.026 262)",
    "--paper": "oklch(0.984 0.006 240)",
    "--rail": "oklch(0.225 0.024 256)",
    "--line": "oklch(0.915 0.008 248)",
}


def test_the_web_package_has_modules_to_check() -> None:
    """A guard on the guards: an empty glob would pass every test below."""
    assert len(WEB_MODULES) >= 10


@pytest.mark.parametrize("module", WEB_MODULES, ids=lambda path: path.name)
def test_no_web_module_imports_the_orm(module: Path) -> None:
    """Parsed, not substring-matched: this repo imports as ``from X import Y``,
    which a check for the literal text ``import X`` never sees."""
    tree = ast.parse(module.read_text(encoding="utf-8"), filename=str(module))
    offenders: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            names = [node.module] if node.module else []
        else:
            continue
        offenders.extend(
            name
            for name in names
            if any(name == banned or name.startswith(f"{banned}.") for banned in FORBIDDEN_IMPORTS)
        )

    assert offenders == [], (
        f"{module.name} imports {offenders}; the web layer reaches the database "
        "only by calling an API route handler"
    )


@pytest.mark.parametrize("module", WEB_MODULES, ids=lambda path: path.name)
def test_no_web_module_builds_a_query_or_commits(module: Path) -> None:
    """`db` is passed through to an API handler, never used here.

    Two nets: the query-shaped names anywhere (a bare ``select()`` from any
    receiver), and *any* method call on a name called ``db`` — which is what
    catches ``db.get(Finding, id)`` or ``db.add(...)``, reads and writes the
    generic name check cannot see.
    """
    tree = ast.parse(module.read_text(encoding="utf-8"), filename=str(module))
    offenders: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        target = node.func
        name = (
            target.attr
            if isinstance(target, ast.Attribute)
            else target.id
            if isinstance(target, ast.Name)
            else None
        )
        if name in FORBIDDEN_CALLS:
            offenders.append(f"{name}() at line {node.lineno}")
        elif (
            isinstance(target, ast.Attribute)
            and isinstance(target.value, ast.Name)
            and target.value.id == "db"
        ):
            offenders.append(f"db.{target.attr}() at line {node.lineno}")

    assert offenders == [], f"{module.name} touches the database directly: {offenders}"


def _routes_of(router: object) -> list[APIRoute]:
    """Flatten a router tree into its API routes.

    Walked from the web router itself rather than from ``app.routes``: FastAPI
    keeps an included router as a lazy placeholder, and the paths inside it are
    the *unprefixed* ones — so a scan of the application would not be able to
    tell ``/findings`` the page from ``/findings`` the API route that is mounted
    under ``/api/v1``. Starting at the web router removes the ambiguity.
    """
    from fastapi.routing import _IncludedRouter

    found: list[APIRoute] = []
    pending = list(getattr(router, "routes", []))
    while pending:
        route = pending.pop()
        if isinstance(route, _IncludedRouter):
            pending.extend(route.original_router.routes)
        elif isinstance(route, APIRoute):
            found.append(route)
    return found


WEB_ROUTES = _routes_of(web_router)


def test_the_web_router_carries_every_screen() -> None:
    paths = {route.path for route in WEB_ROUTES}

    assert {"/", "/login", "/logout", "/findings/{finding_id}", "/scans/{scan_id}/status"} <= paths
    assert len(paths) >= 15


def test_no_html_endpoint_appears_in_the_openapi_document(app: FastAPI) -> None:
    """The schema is the API's contract; HTML routes in it would describe a second."""
    documented = set(app.openapi()["paths"])

    assert all(route.path not in documented for route in WEB_ROUTES)
    assert all(not route.include_in_schema for route in WEB_ROUTES)
    # And the API's own surface is still documented, so this is not passing by
    # having accidentally emptied the schema.
    assert f"{API_PREFIX}/findings" in documented


def test_every_mutating_web_route_is_csrf_protected() -> None:
    """Cookie auth means a browser attaches credentials to cross-site requests."""
    unprotected: list[str] = []
    for route in WEB_ROUTES:
        mutating = (route.methods or set()) & {"POST", "PUT", "PATCH", "DELETE"}
        if not mutating:
            continue
        if not _depends_on(route, require_csrf):
            unprotected.append(f"{sorted(mutating)} {route.path}")

    assert unprotected == [], f"mutating web routes without CSRF protection: {unprotected}"


def _depends_on(route: APIRoute, target: object) -> bool:
    """Whether ``target`` appears anywhere in a route's dependency tree."""
    pending = [route.dependant]
    while pending:
        dependant = pending.pop()
        if dependant.call is target:
            return True
        pending.extend(dependant.dependencies)
    return False


# ─── Vendored assets ─────────────────────────────────────────────────────────


def test_the_static_tree_is_served_from_this_origin(app: FastAPI) -> None:
    """`script-src 'self'` is only satisfiable if the app actually serves them."""
    from fastapi.testclient import TestClient

    manifest = json.loads(web_assets.LOCK_PATH.read_text(encoding="utf-8"))
    with TestClient(app) as client:
        for entry in manifest.values():
            response = client.get(f"/static/{entry['path']}")
            assert response.status_code == 200, entry["path"]

        assert client.get("/static/css/iceberg.css").status_code == 200
        assert client.get("/static/js/tags.js").status_code == 200
        assert client.get("/static/img/icebergai-mark.svg").status_code == 200


def test_every_vendored_asset_matches_its_recorded_integrity() -> None:
    """CI verifies the committed files offline, without a network call.

    A hand-edited vendor file, a truncated download, or a lock that was not
    regenerated all produce the same symptom in a browser — the asset is blocked
    by SRI and the page silently loses its behaviour. This catches it here.
    """
    manifest = json.loads(web_assets.LOCK_PATH.read_text(encoding="utf-8"))

    for name, entry in sorted(manifest.items()):
        path = web_assets.STATIC_DIR / entry["path"]
        assert path.is_file(), f"{name}: {entry['path']} is missing"
        digest = hashlib.sha384(path.read_bytes()).digest()
        expected = "sha384-" + base64.b64encode(digest).decode("ascii")
        assert expected == entry["integrity"], (
            f"{name} does not match its lock entry; re-run web/vendor_assets.py"
        )


def test_every_declared_font_file_is_present() -> None:
    manifest = json.loads(web_assets.LOCK_PATH.read_text(encoding="utf-8"))
    missing = [
        filename
        for filename in manifest["fonts"]["files"]
        if not (web_assets.STATIC_DIR / "fonts" / filename).is_file()
    ]

    assert missing == [], f"declared but absent: {missing}"


def test_the_font_stylesheet_points_only_at_this_origin() -> None:
    """A Google Fonts URL would need `font-src` to name a third party, and would
    break the app in an air-gapped deployment."""
    css = (web_assets.STATIC_DIR / "css" / "vendor" / "fonts.css").read_text(encoding="utf-8")

    assert "fonts.gstatic.com" not in css
    assert "fonts.googleapis.com" not in css
    assert "/static/fonts/" in css


def test_the_alpine_bundle_is_the_csp_build() -> None:
    """The standard build uses `new Function()` and cannot run under this policy."""
    bundle = (web_assets.STATIC_DIR / "js" / "vendor" / "alpine.min.js").read_text(
        encoding="utf-8", errors="replace"
    )

    # The CSP build ships its own expression interpreter and never constructs a
    # function from a string; the standard build's evaluator is `new Function`.
    assert "new Function(" not in bundle


# ─── Design system ───────────────────────────────────────────────────────────


def test_the_stylesheet_carries_the_shared_iceberg_tokens() -> None:
    """Same palette as iceberg and IcebergCM — one visual language, three apps."""
    css = (web_assets.STATIC_DIR / "css" / "iceberg.css").read_text(encoding="utf-8")

    for token, value in CANONICAL_TOKENS.items():
        assert re.search(rf"{re.escape(token)}:\s*{re.escape(value)}", css), (
            f"{token} has drifted from the shared palette"
        )


def test_the_stylesheet_has_a_dark_variant() -> None:
    css = (web_assets.STATIC_DIR / "css" / "iceberg.css").read_text(encoding="utf-8")

    assert "@media (prefers-color-scheme: dark)" in css
    assert "color-scheme: dark" in css


def test_the_stylesheet_hard_codes_no_hex_colours_outside_the_rail() -> None:
    """Colours come from tokens so light↔dark switches for free.

    `#fff` on the dark rail is the deliberate exception: that chrome is dark in
    both themes, so its foreground is a constant rather than a token.
    """
    css = (web_assets.STATIC_DIR / "css" / "iceberg.css").read_text(encoding="utf-8")
    hexes = set(re.findall(r"#[0-9a-fA-F]{3,8}\b", css))

    assert hexes <= {"#fff"}, f"hard-coded colours found: {sorted(hexes)}"
