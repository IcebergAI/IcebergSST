# Spike: Python 3.14 stack compatibility (issue #66)

**Date:** 2026-07-23 · **Verdict: GO — target Python 3.14; no blockers found.**

## What was validated

A scratch uv project exercised every core dependency beyond bare import:

| Dependency | Exercise | 3.13.12 result |
|---|---|---|
| fastapi 0.139.2 | app + `TestClient` request round-trip | OK |
| sqlmodel 0.0.39 | table model + in-memory SQLite CRUD | OK |
| dramatiq 2.2.0 | actor via `StubBroker`, enqueue + worker run | OK |
| alembic 1.18.5 | config + `command.init` script directory | OK |
| cryptography 50.0.0 | AES-GCM and Fernet encrypt/decrypt round-trips | OK |
| httpx 0.28.1 | client request via `MockTransport` | OK |
| prometheus-client 0.25.0 | counter + text exposition | OK |
| structlog 26.1.0 | JSON renderer output parses | OK |
| pypdf 6.15.0 | write PDF + `extract_text` | OK |

## 3.14 evidence

The sandbox used for this spike could not obtain a 3.14 interpreter (its egress policy blocks
GitHub release downloads, python.org, and the deadsnakes PPA), so the stack was executed on
**3.13.12** — the pre-approved fallback floor — and 3.14 support was verified from PyPI
metadata for **all 34 packages in the lock**:

- Every package is either pure-Python or ships **cp314 wheels** (`cffi`, `cryptography`,
  `greenlet`, `markupsafe`, `pydantic-core`).
- No package's `Requires-Python` excludes 3.14.

Live execution on 3.14 was delegated to the **CI matrix** (issue #19), which ran the full
lint/type/test suite on both 3.13 and 3.14 on every PR — so 3.14 was continuously proven, not
assumed.

## Decision

- **Target Python 3.14** (`ARCHITECTURE.md` runtime row unchanged — the 3.13 fallback was
  policy for *blockers*, and none were found).
- Workspace pins `requires-python = ">=3.13"` for now: 3.13 remains a supported floor so that
  restricted dev environments without a 3.14 build keep working. Raise the floor to `>=3.14`
  once the M0 containers epic lands a dev image with 3.14 baked in.
- CI treats **3.14 as primary** and 3.13 as the compatibility leg.

## Resolved — floor raised (issue #82, 2026-07-31)

The condition set above was met: #80 landed both role images on `python:3.14-slim`, and its CI
run was the first in this repo to actually execute the 3.14 leg end to end. So 3.14 is now the
runtime *and* a proven test target, and the fallback exists to protect an environment that no
longer has to be catered for.

- The workspace and all five members pin `requires-python = ">=3.14"`; ruff targets `py314`
  and mypy checks against `3.14`.
- The 3.13 CI leg is **dropped, not kept as a compatibility check**. With the floor at `>=3.14`
  a 3.13 leg cannot resolve the environment, so it could only ever fail — the floor and the
  matrix have to agree. CI now runs a single 3.14 job, the same interpreter the images ship.

The consequence, stated plainly: contributors and images on 3.13 are no longer supported.

## Reproducing

The spike project is not committed (scratch work). To re-run: `uv init`, add the dependencies
listed above, and exercise each as described — or simply rely on CI, which now covers the same
ground with the real packages.
