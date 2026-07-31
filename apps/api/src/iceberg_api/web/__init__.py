"""The server-rendered web UI (M3 — epics #12 and #13).

The UI is a **client of the API, not a second implementation of it**. Every web
route resolves the same RBAC dependency the corresponding API route declares and
then calls that route's handler directly, so there is one query, one permission
check, one set of response semantics, and one place a behaviour change lands.
What lives here is presentation: Jinja templates, HTMX partial conventions, and
the CSP-safe Alpine registry.

``apps/api/tests/test_web_invariants.py`` holds that boundary in place — no
module under this package may import a SQLModel table or build a query.
"""
