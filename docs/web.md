# The web UI (M3)

The console is server-rendered Jinja with HTMX for partial updates and Alpine for
the interactions that genuinely need client state. There is no SPA, no build
step, and no third-party CDN.

Code lives in [`apps/api/src/iceberg_api/web/`](../apps/api/src/iceberg_api/web/);
the vendoring script is [`web/vendor_assets.py`](../web/vendor_assets.py).

## The one rule: the UI is a client of the API

Every web route resolves the RBAC dependency its API counterpart declares and
then **calls that route's handler as a function**:

```python
@router.get("/sources")
async def sources_page(request, viewer: CurrentViewer, user: WebViewer, db: SessionDep, ...):
    page = await api.list_sources(user=user, db=db, limit=DEFAULT_LIMIT, cursor=cursor)
    return render_page(request, "sources/list.html", viewer, {"sources": page.items, ...})
```

One query, one permission check, one set of response semantics, and one place a
behaviour change lands. `apps/api/tests/test_web_invariants.py` holds the line:
no module under `iceberg_api.web` may import the ORM or call `select`, `exec`,
`commit`, `refresh`, or `flush`.

Two consequences worth knowing:

- **Declare the gate.** Calling a handler directly does *not* run its
  `Depends(require_role(...))`. A web route that delegates to an admin-only
  handler must declare `WebAdmin` itself. The `Web*` aliases in
  `web/dependencies.py` wrap `rbac.require_role` — the same ranking, the same
  403, the same audit line — and differ only in redirecting an anonymous
  visitor instead of returning JSON.
- **Pass every argument.** A FastAPI handler's signature default is a
  `Query(...)` marker, not the value it stands for. Omitting `cursor=` hands
  `resolve_cursor` a `Query` object and the page 400s.

HTML endpoints are `include_in_schema=False`: the OpenAPI document is the API's
contract (`docs/api.md`), and HTML routes in it would describe a second one.

## Screens

| Path | Screen | Drives | Read by |
|---|---|---|---|
| `/` | Overview queue | the list endpoints below | viewer |
| `/findings`, `/findings/{id}` | Queue, detail, triage, remediation panel, owner and due date (#146) | `GET/PATCH /findings`, `/remediation/guidance/{rule_id}`, `/findings/{id}/remediations…` (ADR 0012) | viewer / analyst to triage or record |
| `/clusters`, `/clusters/{id}` | Exposure clusters: spread view, topology, export link | `GET /correlation/clusters…` (ADR 0011) | analyst |
| `/scans`, `/scans/{id}` | List, live status, cancel | `/scans`, `/scans/{id}/tasks`, `/scans/{id}/cancel` | viewer / analyst to cancel |
| `/sources`, `/sources/{id}` | List, create/edit (every connector the API supports), connectivity test where one exists | `/sources`, `/sources/{id}/test`, `/sources/{id}/scan` | viewer / admin to write |
| `/schedules` | Cron cadences | `/schedules` | viewer / admin to write |
| `/suppressions` | Create, list, delete | `/suppressions` | viewer / analyst to write |
| `/rules` | Detection surface in force | `GET /rules` | viewer |
| `/engines` | Fleet health, enrolment | `/engines`, `/engines/register` | admin |
| `/channels` | Notification channels | `/notifications/channels` | admin |
| `/ownership` | Teams, routing rules, response targets (#146) | `/owner-groups`, `/routing-rules`, `/response-targets` | admin |
| `/users` | Roles and accounts | `/users` | admin |

The rail's **Administration** group is rendered only for admins, because every
route behind it is admin-only. That is a courtesy; `rbac.require_role` is the
control, and a viewer who types `/engines` gets a 403 page.

**A `<select>` cannot post "field omitted".** The triage panel's `assignee` and
`owner` controls each stand for three states the API distinguishes — leave alone,
clear, or set — so an empty value means *unchanged*, `none` means null, and
anything else is an id. `owner` needs this more than `assignee` does: any value
supplied there pins the finding against routing (#146), so without an
"unchanged" option an analyst could not add a comment without also taking the
decision away from the rules.

The findings queue collapses `?owner_group_id=` and `?unowned=` into a single
`?owner=` dropdown for the same reason in reverse: the API keeps them separate
because an absent query parameter already means "do not filter" there, while a
dropdown has no such ambiguity and two controls that must not both be set is a
state a URL can carry and an operator can get wrong.

## HTMX conventions

**Pages and fragments are different routes.** A route renders a full page
(`render_page`, a template extending `base.html`) or a fragment
(`render_fragment`, a template in `templates/partials/`). Which one is the
route's decision, never sniffed from `HX-Request` — a fragment URL that returns
the same fragment to curl, to HTMX, and to the address bar is one you can debug.

The conventions a fragment follows:

- it lives in `partials/` and is named `_thing.html`-style (`source_form.html`);
- it owns **one root element with a stable id**, and mutations swap it whole
  (`hx-target="#source-form" hx-swap="outerHTML"`);
- a mutation answers with the fragment its change affected, so the browser never
  has to re-request to find out what happened;
- where a change is bigger than one region, the mutation answers `hx_redirect()`
  (`HX-Redirect`) and the browser navigates normally. Triage is the example:
  a state change moves the header chips and the Record card as well as the panel,
  so it redirects — while a *rejected* triage answers the panel, because nothing
  moved and navigating away would take the analyst off the explanation.

**CSRF is set once, on the shell.** `base.html` carries
`hx-headers='{"X-CSRF-Token": …}'` on `.app`, so every `hx-` request inherits it
and no form can forget one. Plain `<form method="post">` posts carry a
`csrf_token` hidden field instead; `csrf.presented_token` reads either.

**A rejected form answers 200 with the re-rendered fragment**, not the API's 4xx.
HTMX only swaps a 2xx by default, so a 422 would leave the analyst looking at an
unchanged form with no explanation. The failure is the first thing in the
fragment, and the API logged it.

**Live status polls itself.** The scan status fragment carries its own
`hx-trigger="every 3s"`, and the *terminal* version of that fragment does not —
so a scan that finishes stops the polling by the act of rendering, and the client
never has to know which statuses are terminal. Polling rather than SSE because a
scan's state changes seconds-to-minutes apart for a handful of watchers, and a
dropped request retries on the next tick instead of leaving a half-dead stream.

### Reference partial

[`templates/partials/source_form.html`](../apps/api/src/iceberg_api/web/templates/partials/source_form.html)
is the worked example: stable root id, a registered Alpine component, server
state through a JSON island, `hx-post` to a route that answers with this same
fragment on failure, and an `hx-indicator` so a slow save looks like one.

## Alpine, under a strict CSP

The policy is `script-src 'self'` with **no `'unsafe-inline'` and no
`'unsafe-eval'`** (`web/security.py`). A findings viewer renders page titles,
resource paths, and redacted snippets that came out of somebody else's
Confluence, which makes it exactly the page where a stored-XSS would be worth
the most. Three things make the policy possible:

1. **The `@alpinejs/csp` build**, self-hosted and SRI-pinned. It interprets
   directive expressions instead of compiling them with `new Function()`.
2. **Every component registered via `Alpine.data()`** in
   [`static/js/tags.js`](../apps/api/src/iceberg_api/web/static/js/tags.js),
   which is loaded **before** Alpine — Alpine dispatches `alpine:init` during its
   own deferred startup, and a listener registered after that never runs.
3. **No inline `<script>` or `<style>` anywhere.** Asserted by
   `test_web_shell.py`, along with a check for `onclick=`-style handlers.

What the CSP build can and cannot do:

- **can** evaluate directive attributes — `x-text="label"`, `@click="open = true"`,
  `:class="active ? 'on' : ''"`, `x-show="count > 0"`, method calls, ternaries;
- **cannot** parse an inline `x-data` object that defines methods or getters —
  behaviour lives in the registered factory;
- **cannot** decode `\uXXXX` escapes, and Jinja's `|tojson` escapes `< > & '`
  that way — so server data never travels in an `x-data` attribute.

**Server data reaches a component through a JSON island** inside its own root
element, read by `readIsland()`:

```html
<div id="source-form" x-data="sourceForm">
  <script type="application/json">{{ island | tojson }}</script>
  <input x-model="spaceDraft" @keydown.enter.prevent="addSpace()">
  <template x-for="key in spaces" :key="key">
    <span class="tag"><span x-text="key"></span><input type="hidden" name="spaces" :value="key"></span>
  </template>
</div>
```

`JSON.parse` decodes the escapes correctly, and a `type` the browser does not
recognise as executable is a data block, so `script-src` does not apply to it.
Components take **no arguments** — each finds its own island relative to
`this.$el`, which sidesteps argument parsing entirely.

Registered components: `confirmAction` (two-step destructive guard),
`copyable` (shown-once engine token), `disclosure` (inline create forms),
`sourceForm`, `triageForm`, `channelForm`, `cronField`.

HTMX is configured through a `<meta name="htmx-config">` tag with
`allowEval: false` — none of the eval-dependent features are used, and leaving
them on makes HTMX probe for eval and log a CSP violation on every page load.

## Asset pipeline

`web/vendor_assets.py` pins exact versions, downloads each asset into
`web/static/`, and writes `static/assets.lock.json` with a `sha384` integrity
that `base.html` emits as an `integrity=` attribute. Sources are **npm registry
tarballs**, not a CDN: a jsdelivr/unpkg URL is a third party in the supply chain
and is unreachable from a locked-down build network.

```
uv run python web/vendor_assets.py      # after bumping a pin
```

`test_web_invariants.py` verifies the committed files against the lock offline,
so CI catches a hand-edited vendor file without a network call.

**Fonts are self-hosted woff2** (Archivo, JetBrains Mono, Spectral). A Google
Fonts `<link>` would need `font-src` to name a third party and would break the
console in an air-gapped deployment.

**There is no CSS build step.** The design system is hand-authored plain CSS in
`static/css/iceberg.css`, the same choice IcebergCM made. Tailwind would add a
110 MB standalone binary, a build stage in the Docker image, and a CI
verification step in exchange for layout utilities that are forty lines of CSS
here — and every *component* would still be hand-authored, because that is how
the shared design system works. If Tailwind is wanted later it is additive:
`@import "tailwindcss"` plus an `@theme inline` block mapping its colour tokens
onto the CSS variables already defined.

## The design system

Shared with the Iceberg app family (`iceberg`, `IcebergCM`, `IcebergTTX`): cool
blue-grey neutrals, a **fixed** glacial-cyan accent (`oklch(0.66 0.118 226)` —
never user-configurable), Archivo for UI, JetBrains Mono for data and labels,
Spectral for prose. The token block at the top of `iceberg.css` is byte-identical
to its siblings, and `test_web_invariants.py` fails if one drifts.

### Provenance

This console did not invent its look, and none of it should be re-derived by
hand. Where each shared artifact came from, so a future change can go back to the
same source instead of guessing:

| Here | Canonical source |
|---|---|
| `static/css/iceberg.css` token block | `IcebergCM/src/icebergcm/web/static/app.css` — identical values, including the dark variant |
| `.rail`/`.workspace`/`.canvas` shell, `.btn`/`.tag`/`.field`/`.card` vocabulary | `iceberg/src/iceberg/static/css/iceberg.css` and IcebergCM's `app.css` |
| `static/js/vendor/alpine.min.js` | the `@alpinejs/csp` build **iceberg** pins — byte-identical to `iceberg/src/iceberg/static/js/vendor/alpine.min.js` and to the npm tarball for that version |
| `static/css/vendor/fonts.css` + `static/fonts/*.woff2` (26 files) | byte-identical to `iceberg/src/iceberg/static/` |
| `static/img/icebergai-mark*.svg` | `~/Projects/.github/profile/assets/` — the real brand marks, never a text or emoji placeholder |
| CSP-safe Alpine pattern (`tags.js` registry, load order, JSON islands) | `iceberg/src/iceberg/templates/base.html` + `auth/security_headers.py` |
| The vendoring script's shape | `iceberg/scripts/vendor_assets.py`, retargeted at npm tarballs |

The rules those artifacts have to satisfy — fixed accent, tokens over hex, no
accent picker, self-hosted fonts, the CSP-safe Alpine contract — are written down
in the `iceberg-frontend` skill (`~/.claude/skills/iceberg-frontend/`, with
`references/tokens.css`, `components.md`, and `csp-alpine.md`). Read it before
touching anything in this section; several of the constraints here exist because
one of the sibling apps already got them wrong once.

Two deliberate divergences from `iceberg` specifically, both explained above:
this console has **no Tailwind** (it follows IcebergCM), and it has an
**automatic dark variant** (iceberg is light-only).

Colours come from tokens (`var(--ink)`, `var(--line)`, `var(--accent)`), never
from hex literals — `#fff` on the dark rail is the single deliberate exception,
because that chrome is dark in both themes. Dark mode is the automatic
`prefers-color-scheme` variant over the same token names: no toggle, no cookie,
and no FOUC bootstrap script (which would have to be inline).

Shell: `.brandbar` → `.app` → dark `.rail` → light `.workspace` (`.topbar`
breadcrumb + `.canvas`/`.canvas-inner`). Unauthenticated pages use
`.auth-shell`/`.auth-card`. Anything interactive inside `.rail` needs
rail-scoped styling from the `--rail*` tokens — a `.btn` there paints a white box
on dark chrome.

## Screenshots

`docs/img/*.png` are captured by hand and embedded in the README. They are not
generated by CI and will drift as screens change — treat a stale one as a doc
bug, not a broken build.

Reproducing them needs two things this repository deliberately does not contain:
a database of fabricated findings, and a way to sign in. Authentication is OIDC
only (ADR 0005), so a local instance cannot be signed into without a provider,
and a development bypass — a login route that trusts a query string — is exactly
the kind of thing that survives into a production image. Both therefore live
outside the tree: a seeding script and a wrapper that imports the real
`create_app()` and adds a single `/dev-login` route. Nothing under `apps/` knows
either exists.

## Security properties this surface adds

- **Strict CSP** on every response except FastAPI's interactive docs, which load
  Swagger UI from a CDN and bootstrap it inline; a policy loose enough to run
  them would be no policy at all, so they are exempted by path.
- `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`,
  a deny-all `Permissions-Policy`, `Cross-Origin-Opener-Policy: same-origin`, and
  HSTS + `upgrade-insecure-requests` in production only.
- **CSRF on every mutating browser route**, asserted for the whole router by
  `test_every_mutating_web_route_is_csrf_protected`.
- **No credential is ever rendered.** The source form never receives one to echo,
  the channels screen shows `sealed`/`none` rather than a secret or its ref, and
  an engine token appears exactly once — in the response that minted it.
- **Nothing in the chrome is attacker-authored.** A save that fails redirects with
  its reason, and that reason is a **signed, two-minute token** rather than the
  text itself: rendered as plain text it was autoescaped, so never script, but a
  crafted `?error=` still put a stranger's words inside the console's own frame
  ("your account is locked, call this number"). Pages show nothing for anything
  they cannot verify (#197).
- **Autoescaping everywhere**, with `StrictUndefined` so a typo'd variable is a
  loud failure rather than a silently empty severity cell.
