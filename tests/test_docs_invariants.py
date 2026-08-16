"""The documentation says what the project actually does (#150).

`scripts/check_docs.py` catches the mechanical rot — a moved file, a renamed
target, a setting that no longer exists. These are the claims it cannot check
from a regular expression, and each one is a promise the docs make on behalf of
somebody else:

* **CONTRIBUTING lists the gate CI runs.** A contributor who runs everything the
  guide names and still fails CI has been told the wrong thing, and the second
  time it happens they stop running any of it.
* **Every document is reachable.** A guide nobody links to is a guide nobody
  reads — and it is also the one that rots, because nothing points at it when the
  thing it describes changes.
* **Every ADR is indexed.** Same reasoning, and the index is how the decision
  record works as a record at all.
"""

import importlib.util
import re
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[1]
CI = ROOT / ".github/workflows/ci.yml"
CONTRIBUTING = ROOT / "CONTRIBUTING.md"
DOCS = ROOT / "docs"

#: `run: make check`, in the workflow.
_CI_MAKE = re.compile(r"run:\s*make ([a-z][a-z0-9-]*)")


def _load(name: str) -> ModuleType:
    """Import a `scripts/` module by path — see `test_release_invariants.py`."""
    path = ROOT / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


check_docs = _load("check_docs")


def _linked_from(document: Path) -> set[str]:
    """Repository-local link targets in one document, resolved to repo paths."""
    targets: set[str] = set()
    for raw in check_docs.LINK.findall(document.read_text(encoding="utf-8")):
        target = raw.strip().split(maxsplit=1)[0].strip("<>").split("#")[0]
        if not target or target.startswith(("http", "mailto:")):
            continue
        resolved = (document.parent / target).resolve()
        if resolved.is_relative_to(ROOT):
            targets.add(str(resolved.relative_to(ROOT)))
    return targets


# ─── The contributor gate is the CI gate ──────────────────────────────────────


def test_contributing_names_every_make_target_ci_runs() -> None:
    """A contributor who runs everything the guide names and still fails CI has
    been told the wrong thing — and the second time, they stop running any of it."""
    ci_targets = set(_CI_MAKE.findall(CI.read_text(encoding="utf-8")))
    assert ci_targets, "no `run: make …` steps found; the pattern is checking nothing"

    guide = CONTRIBUTING.read_text(encoding="utf-8")
    missing = sorted(name for name in ci_targets if f"make {name}" not in guide)

    assert missing == [], f"CI runs these and CONTRIBUTING does not mention them: {missing}"


def test_contributing_names_the_scripts_ci_runs_directly() -> None:
    """The rehearsal is a script rather than a bare `make` step in CI, so the
    pattern above cannot see it — and it is the longest-running local check a
    contributor might reasonably want to know about before pushing."""
    workflow = CI.read_text(encoding="utf-8")
    guide = CONTRIBUTING.read_text(encoding="utf-8")

    assert "./scripts/rehearse_release.sh" in workflow
    assert "make rehearse" in guide


# ─── Everything is reachable ──────────────────────────────────────────────────


def test_every_document_is_linked_from_somewhere() -> None:
    """A guide nobody links to is a guide nobody reads, and it is the one that
    rots — nothing points at it when the thing it describes changes."""
    documents = {
        str(path.relative_to(ROOT)) for path in check_docs.tracked_documents(ROOT) if path != ROOT
    }
    linked: set[str] = set()
    for path in check_docs.tracked_documents(ROOT):
        linked |= _linked_from(path)

    # The entry points nothing needs to link to: a reader arrives at them by
    # convention, and GitHub surfaces all four in its own UI.
    entry_points = {"README.md", "CONTRIBUTING.md", "SECURITY.md", "SUPPORT.md", "CLAUDE.md"}
    orphans = sorted(documents - linked - entry_points)

    assert orphans == [], f"nothing links to: {orphans}"


def test_every_adr_is_in_the_index() -> None:
    """The index is how a decision record works as a record."""
    index = (DOCS / "README.md").read_text(encoding="utf-8")
    records = sorted(path.name for path in (DOCS / "adr").glob("0*.md"))

    assert records, "no ADRs found; the glob is looking in the wrong place"
    missing = [name for name in records if name not in index]
    assert missing == [], f"not indexed in docs/README.md: {missing}"


def test_every_runbook_is_in_the_index() -> None:
    """A runbook is read under pressure, by somebody who did not write it. If it
    is not in the index it will not be found in time to matter."""
    index = (DOCS / "README.md").read_text(encoding="utf-8")
    runbooks = sorted(path.name for path in (DOCS / "runbooks").glob("*.md"))

    assert runbooks, "no runbooks found; the glob is looking in the wrong place"
    missing = [name for name in runbooks if name not in index]
    assert missing == [], f"not indexed in docs/README.md: {missing}"


# ─── The operator-facing promises ─────────────────────────────────────────────


def test_the_security_policy_points_at_the_supported_versions() -> None:
    """ "Is my version still getting security fixes?" is the question a disclosure
    policy has to answer, and the answer lives in the release policy."""
    policy = (ROOT / "SECURITY.md").read_text(encoding="utf-8")

    assert "releases.md" in policy


def test_the_recovery_runbook_is_the_one_ci_rehearses() -> None:
    """The backup/restore runbook claims a rehearsal. `scripts/rehearse_release.sh`
    is that rehearsal, so the two must name each other — a runbook that claims to
    be exercised by a script nobody can find is a claim, not evidence."""
    runbook = (DOCS / "runbooks/backup-restore.md").read_text(encoding="utf-8")
    script = (ROOT / "scripts/rehearse_release.sh").read_text(encoding="utf-8")

    assert "rehearse_release.sh" in runbook or "make rehearse" in runbook
    assert "backup-restore.md" in script
