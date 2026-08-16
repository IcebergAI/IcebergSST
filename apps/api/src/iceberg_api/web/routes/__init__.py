"""Browser routes, mounted at the application root.

The JSON API owns ``/api/v1``; these own everything else a person types into an
address bar. Each module is one screen group, and each route follows the same
two steps: resolve the RBAC dependency the API route declares, then call that
route's handler and render what it returned.
"""

from fastapi import APIRouter

from iceberg_api.web.routes import (
    admin,
    clusters,
    findings,
    ownership,
    scans,
    schedules,
    shell,
    sources,
    suppressions,
)

router = APIRouter(include_in_schema=False)

# Order matters only for readability; every path is distinct. `include_in_schema`
# is off for the whole tree: the OpenAPI document is the API's contract
# (docs/api.md), and HTML endpoints in it would describe a second one.
router.include_router(shell.router)
router.include_router(findings.router)
router.include_router(clusters.router)
router.include_router(scans.router)
router.include_router(sources.router)
router.include_router(schedules.router)
router.include_router(suppressions.router)
router.include_router(admin.router)
router.include_router(ownership.router)

__all__ = ["router"]
