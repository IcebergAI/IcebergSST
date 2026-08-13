"""The web shell: authentication gating, role-shaped navigation, headers (#53).

These are the properties the shell has to hold no matter what any screen does —
that an anonymous visitor never sees data, that the rail offers only what the
signed-in role can actually reach, and that the response carries a policy strict
enough for a page which renders strings out of somebody else's Confluence.
"""

import re
import uuid
from collections.abc import Callable
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi.testclient import TestClient
from iceberg_api.web.assets import TEMPLATES_DIR
from iceberg_api.web.errors import HX_ERROR_REGION
from iceberg_api.web.security import DOCS_PATHS, build_csp, build_security_headers
from iceberg_core.config import CoreSettings
from iceberg_core.enums import UserRole
from iceberg_core.models import User

#: Every page a signed-in viewer may open. Analyst-only and admin-only screens
#: are checked separately, because for a lesser role they are a 403, not a page.
VIEWER_PAGES = ("/", "/findings", "/scans", "/sources", "/schedules", "/suppressions", "/rules")
ANALYST_PAGES = ("/clusters",)
ADMIN_PAGES = ("/engines", "/channels", "/users")


def test_an_anonymous_visitor_is_sent_to_the_login_page(client: TestClient) -> None:
    response = client.get("/findings", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/login?next=/findings"


def test_the_login_redirect_remembers_the_query_string(client: TestClient) -> None:
    """A bookmarked filter must survive the round trip through the IdP.

    Percent-encoded, or the target's own `?` ends the value: `next` would parse as
    `/findings?state=open` with `severity` arriving as a stray parameter on /login,
    and the visitor would land on a filter that is only half applied.
    """
    response = client.get("/findings?state=open&severity=critical", follow_redirects=False)

    location = response.headers["location"]
    assert location == "/login?next=/findings%3Fstate%3Dopen%26severity%3Dcritical"
    assert parse_qs(urlsplit(location).query)["next"] == ["/findings?state=open&severity=critical"]


def test_the_login_page_hands_the_whole_filter_to_the_identity_provider(
    client: TestClient,
) -> None:
    """The far end of the same round trip: /auth/login carries it intact."""
    response = client.get("/findings?state=open&severity=critical")

    href = re.search(r'href="(/api/v1/auth/login\?[^"]*)"', response.text)
    assert href is not None, response.text[:400]
    assert parse_qs(urlsplit(href.group(1)).query)["next"] == [
        "/findings?state=open&severity=critical"
    ]


def test_an_expired_session_returns_to_a_page_rather_than_a_post_only_path(
    client: TestClient,
) -> None:
    """Signing back in ends in a *GET*, and `POST .../triage` answers one with 405.

    The Referer is the page the mutation was fired from, which is where the
    analyst was — the common expiry path for every hx-post in the console.
    """
    finding_id = uuid.uuid4()

    response = client.post(
        f"/findings/{finding_id}/triage",
        headers={"HX-Request": "true", "Referer": f"http://testserver/findings/{finding_id}"},
        data={"state": "open"},
        follow_redirects=False,
    )

    assert response.headers["HX-Redirect"] == f"/login?next=/findings/{finding_id}"


def test_a_mutation_with_no_referer_falls_back_to_the_parent_page(client: TestClient) -> None:
    """Nothing else is knowable, and the parent is at least navigable."""
    source_id = uuid.uuid4()

    response = client.post(f"/sources/{source_id}/scan", follow_redirects=False)

    assert response.headers["location"] == f"/login?next=/sources/{source_id}"


def test_an_htmx_request_without_a_session_gets_a_redirect_header_not_a_body(
    client: TestClient,
) -> None:
    """A 303 would be followed by fetch and swap a login page into a table cell."""
    response = client.post(
        "/findings/00000000-0000-0000-0000-000000000000/triage",
        headers={"HX-Request": "true"},
        data={"state": "open"},
        follow_redirects=False,
    )

    assert response.status_code == 204
    assert response.headers["HX-Redirect"].startswith("/login")
    assert response.content == b""


@pytest.mark.parametrize("candidate", ["//evil.example", "/\\evil.example", "https://evil.example"])
def test_a_crafted_next_path_cannot_leave_this_origin(client: TestClient, candidate: str) -> None:
    """The login page round-trips `next`; it must never become an open redirect."""
    response = client.get(f"/login?next={candidate}")

    assert response.status_code == 200
    assert "evil.example" not in response.text


def test_the_login_page_offers_single_sign_on_and_no_password_field(
    client: TestClient,
) -> None:
    response = client.get("/login")

    assert response.status_code == 200
    assert "/api/v1/auth/login" in response.text
    assert 'type="password"' not in response.text


def test_a_signed_in_visitor_is_redirected_away_from_the_login_page(
    client: TestClient, make_user: Callable[..., User], login_as: Callable[[User], dict[str, str]]
) -> None:
    login_as(make_user(UserRole.VIEWER))

    response = client.get("/login", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/"


@pytest.mark.parametrize("path", VIEWER_PAGES)
def test_every_viewer_page_renders_for_a_viewer(
    client: TestClient,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
    path: str,
) -> None:
    login_as(make_user(UserRole.VIEWER))

    response = client.get(path)

    assert response.status_code == 200, response.text[:400]
    assert response.headers["content-type"].startswith("text/html")


@pytest.mark.parametrize("path", ANALYST_PAGES)
def test_the_analyst_screens_refuse_a_viewer(
    client: TestClient,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
    path: str,
) -> None:
    """The cluster view is the "same secret elsewhere" capability (ADR 0011) —
    scoped to the roles that remediate, and enforced here, not by the rail."""
    login_as(make_user(UserRole.VIEWER))

    response = client.get(path, follow_redirects=True)

    assert response.status_code == 403
    assert "Your role does not allow this" in response.text


@pytest.mark.parametrize("path", ANALYST_PAGES)
def test_every_analyst_screen_renders_for_an_analyst(
    client: TestClient,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
    path: str,
) -> None:
    login_as(make_user(UserRole.ANALYST))

    response = client.get(path, follow_redirects=True)

    assert response.status_code == 200, response.text[:400]
    assert response.headers["content-type"].startswith("text/html")


@pytest.mark.parametrize("path", ADMIN_PAGES)
def test_the_admin_screens_refuse_a_viewer(
    client: TestClient,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
    path: str,
) -> None:
    """Hiding the link is a courtesy; require_role is the control."""
    login_as(make_user(UserRole.VIEWER))

    response = client.get(path)

    assert response.status_code == 403
    assert "Your role does not allow this" in response.text


@pytest.mark.parametrize("path", ADMIN_PAGES)
def test_every_admin_screen_renders_for_an_admin(
    client: TestClient,
    make_user: Callable[..., User],
    login_as: Callable[[User], dict[str, str]],
    path: str,
) -> None:
    login_as(make_user(UserRole.ADMIN))

    response = client.get(path)

    assert response.status_code == 200, response.text[:400]


def test_the_rail_shows_administration_only_to_an_admin(
    client: TestClient, make_user: Callable[..., User], login_as: Callable[[User], dict[str, str]]
) -> None:
    """The nav reflects the user's role — the acceptance criterion for #53."""
    login_as(make_user(UserRole.ANALYST))
    analyst_view = client.get("/").text

    login_as(make_user(UserRole.ADMIN))
    admin_view = client.get("/").text

    assert 'href="/engines"' not in analyst_view
    assert 'href="/users"' not in analyst_view
    assert 'href="/findings"' in analyst_view
    assert 'href="/clusters"' in analyst_view

    assert 'href="/engines"' in admin_view
    assert 'href="/users"' in admin_view
    assert 'href="/channels"' in admin_view


def test_the_rail_hides_clusters_from_a_viewer(
    client: TestClient, make_user: Callable[..., User], login_as: Callable[[User], dict[str, str]]
) -> None:
    """Same rule as Administration: no link to a page that would only 403."""
    login_as(make_user(UserRole.VIEWER))

    body = client.get("/").text

    assert 'href="/clusters"' not in body
    assert 'href="/findings"' in body


def test_the_shell_names_the_signed_in_user_and_their_role(
    client: TestClient, make_user: Callable[..., User], login_as: Callable[[User], dict[str, str]]
) -> None:
    user = make_user(UserRole.ANALYST)
    login_as(user)

    body = client.get("/").text

    assert user.display_name in body
    assert "analyst" in body


def test_the_shell_carries_the_sessions_csrf_token_for_htmx(
    client: TestClient, make_user: Callable[..., User], login_as: Callable[[User], dict[str, str]]
) -> None:
    """Every hx- request inherits it from the shell, so no form can forget one."""
    headers = login_as(make_user(UserRole.ANALYST))

    body = client.get("/").text

    assert "hx-headers=" in body
    assert headers["X-CSRF-Token"] in body


def test_logout_clears_the_session_and_returns_to_the_login_page(
    client: TestClient, make_user: Callable[..., User], login_as: Callable[[User], dict[str, str]]
) -> None:
    headers = login_as(make_user(UserRole.VIEWER))

    response = client.post(
        "/logout",
        data={"csrf_token": headers["X-CSRF-Token"]},
        headers=headers,
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/login"
    assert "iceberg_session" in response.headers.get("set-cookie", "")


def test_logout_without_a_csrf_token_is_refused(
    client: TestClient, make_user: Callable[..., User], login_as: Callable[[User], dict[str, str]]
) -> None:
    login_as(make_user(UserRole.VIEWER))

    response = client.post("/logout", data={}, follow_redirects=False)

    assert response.status_code == 403


# ─── Failures on the HTMX surface ────────────────────────────────────────────


def test_the_shell_carries_a_region_for_a_retargeted_failure(
    client: TestClient, make_user: Callable[..., User], login_as: Callable[[User], dict[str, str]]
) -> None:
    login_as(make_user(UserRole.VIEWER))

    assert f'id="{HX_ERROR_REGION}"' in client.get("/").text


def test_a_failed_htmx_mutation_answers_with_a_fragment_htmx_will_swap(
    client: TestClient, make_user: Callable[..., User], login_as: Callable[[User], dict[str, str]]
) -> None:
    """htmx discards the body of a 4xx, so the error *page* is a silent no-op.

    Without this, an analyst clicking a control their role cannot use — or one
    aimed at a record somebody else just deleted — sees nothing happen at all.
    """
    headers = login_as(make_user(UserRole.VIEWER))

    response = client.post(
        f"/sources/{uuid.uuid4()}/scan", headers=headers | {"HX-Request": "true"}
    )

    assert response.status_code == 200
    assert response.headers["HX-Retarget"] == f"#{HX_ERROR_REGION}"
    assert response.headers["HX-Reswap"] == "innerHTML"
    assert "Your role does not allow this" in response.text
    # A fragment, not the page: it is swapped into a live document.
    assert "<html" not in response.text


def test_the_same_failure_reaches_a_plain_browser_as_a_page_with_its_status(
    client: TestClient, make_user: Callable[..., User], login_as: Callable[[User], dict[str, str]]
) -> None:
    """Only htmx trades the status away; a navigation still gets the real one."""
    headers = login_as(make_user(UserRole.VIEWER))

    response = client.post(f"/sources/{uuid.uuid4()}/scan", headers=headers)

    assert response.status_code == 403
    assert "<html" in response.text


# ─── Security headers ────────────────────────────────────────────────────────


def test_the_policy_forbids_inline_and_eval_script() -> None:
    """The whole reason the UI self-hosts Alpine's CSP build."""
    policy = build_csp(is_prod=False)

    assert "script-src 'self'" in policy
    assert "'unsafe-eval'" not in policy
    assert "script-src 'self' 'unsafe-inline'" not in policy
    assert "default-src 'self'" in policy
    assert "frame-ancestors 'none'" in policy
    assert "object-src 'none'" in policy


def test_style_src_keeps_unsafe_inline_only_for_style_attributes() -> None:
    """Documented carve-out: inline style= attributes cannot be nonced."""
    policy = build_csp(is_prod=False)

    assert "style-src 'self' 'unsafe-inline'" in policy


def test_production_adds_transport_hardening() -> None:
    dev = build_security_headers(CoreSettings(environment="dev"))
    prod = build_security_headers(CoreSettings(environment="prod"))

    assert "Strict-Transport-Security" not in dev
    assert prod["Strict-Transport-Security"].startswith("max-age=31536000")
    assert "upgrade-insecure-requests" in prod["Content-Security-Policy"]
    assert "upgrade-insecure-requests" not in dev["Content-Security-Policy"]


def test_every_response_carries_the_security_headers(client: TestClient) -> None:
    response = client.get("/login")

    assert "script-src 'self'" in response.headers["content-security-policy"]
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin"
    assert "camera=()" in response.headers["permissions-policy"]


def test_the_api_surface_is_covered_by_the_same_policy(client: TestClient) -> None:
    """A JSON route can still be navigated to; it gets the headers too."""
    response = client.get("/healthz")

    assert "script-src 'self'" in response.headers["content-security-policy"]


def test_a_console_page_is_never_stored_by_the_browser(
    client: TestClient, make_user: Callable[..., User], login_as: Callable[[User], dict[str, str]]
) -> None:
    """Findings and the one-time engine token must not survive a sign-out.

    Without a directive, heuristic caching and the bfcache make an authenticated
    page restorable with the back button on a shared machine.
    """
    login_as(make_user(UserRole.ADMIN))

    for path in ("/", "/findings", "/engines", "/login"):
        assert client.get(path).headers["cache-control"] == "no-store", path


def test_the_static_assets_stay_cacheable(client: TestClient) -> None:
    """Version-pinned, session-free, and re-fetched on every single page load."""
    response = client.get("/static/js/tags.js")

    assert response.status_code == 200
    assert "no-store" not in response.headers.get("cache-control", "")


@pytest.mark.parametrize("path", sorted(DOCS_PATHS))
def test_the_interactive_docs_are_exempt(client: TestClient, path: str) -> None:
    """Swagger UI loads from a CDN and bootstraps inline; a policy loose enough
    to run it would be no policy at all, so it is exempted by path instead."""
    response = client.get(path)

    assert "content-security-policy" not in response.headers


# ─── No inline script or style ───────────────────────────────────────────────


#: Jinja comments never reach the browser, and several of them here discuss the
#: very tags this file forbids. Strip them before scanning for markup.
_JINJA_COMMENT = re.compile(r"\{#.*?#\}", re.S)


def _markup(path: object) -> str:
    return _JINJA_COMMENT.sub("", path.read_text(encoding="utf-8"))  # type: ignore[attr-defined]


def test_no_template_contains_an_inline_script_or_style_block() -> None:
    """The invariant that makes `script-src 'self'` possible at all.

    Checked over the template source rather than a rendered page: a block added
    to a screen nobody wrote a test for would otherwise ship, and the CSP would
    silently stop it in production instead of here.
    """
    offenders: list[str] = []
    for template in sorted(TEMPLATES_DIR.rglob("*.html")):
        text = _markup(template)
        if "<style>" in text or "<style " in text:
            offenders.append(f"{template.name}: <style>")
        # A <script> with a src is fine; one with a body is not. The JSON islands
        # are `type="application/json"`, which the browser never executes, so the
        # CSP's script-src does not apply to them.
        for chunk in text.split("<script")[1:]:
            head = chunk.split(">", 1)[0]
            if "src=" not in head and "application/json" not in head:
                offenders.append(f"{template.name}: inline <script{head}>")

    assert offenders == [], f"inline script/style found: {offenders}"


def test_no_template_uses_an_inline_event_handler() -> None:
    """`onclick=` is inline script by another name, and the CSP blocks it."""
    offenders = [
        f"{template.name}: {attribute}"
        for template in sorted(TEMPLATES_DIR.rglob("*.html"))
        for attribute in ("onclick=", "onsubmit=", "onload=", "onchange=", "onerror=")
        if attribute in _markup(template)
    ]

    assert offenders == [], f"inline event handlers found in: {offenders}"
