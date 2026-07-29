"""Authentication and authorization for the human-facing API (ADR 0005).

Identity comes from an OIDC provider; there is no local password store. What this
package owns is the flow (:mod:`.oidc`, :mod:`.routes`), the session and CSRF
cookies (:mod:`.session`, :mod:`.csrf`), and the dependencies every protected
route declares (:mod:`.dependencies`).
"""
