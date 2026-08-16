"""Scanning a mounted SMB or NFS share (#145).

**The share arrives as a mount, not as a protocol client.** Both SMB and NFS have
mature, privileged, kernel-side implementations that every operator already knows
how to configure read-only, and re-implementing either in the engine would mean
shipping a second authentication stack, a second set of protocol bugs, and a
second place a credential lives. The engine gets a read-only bind mount and walks
it; the credential is the mount's, and never enters a lease (docs/connectors.md).

That choice is what makes this connector small enough to reason about, and the
whole module is then about the three ways a filesystem walk goes wrong:

* **It escapes.** A symlink, a `..`, or a spec written by an older engine can
  point outside the configured root. Every path is resolved and checked against
  the resolved root before it is opened — the check is on the *resolved* path
  because that is the only form that cannot lie.
* **It never ends.** Symlink loops, and directory trees deep enough to exhaust
  the stack. Symlinks are not followed by default; when they are, a visited-inode
  set stops the cycle.
* **It blocks.** A FIFO opened for reading blocks until somebody writes. Only
  regular files are read, and everything else is a recorded skip rather than a
  hung task.

Everything past that is the extraction pipeline the other connectors already use
(:mod:`iceberg_connectors.extraction`), which owns size caps, decompression
bombs, and parser isolation.
"""

import os
import stat
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path, PurePosixPath
from typing import Any

import structlog
from iceberg_core.enums import CoverageObjectKind, CoverageReason
from iceberg_core.fingerprint import CoarseLocator

from iceberg_connectors.extraction import ExtractionLimits, ExtractionOutcome, extract_text
from iceberg_connectors.protocol import (
    Checkpoint,
    ConnectorCapability,
    ConnectorError,
    ConnectorMetadata,
    FetchOutcome,
    TaskSpec,
)
from iceberg_connectors.sandbox import ExtractionSandbox
from iceberg_connectors.units import ContentOrigin, ContentUnit

logger = structlog.get_logger()

FILESHARE_CONNECTOR_TYPE = "fileshare"

#: This connector's own resume-protocol version, independent of the SDK's (#143).
#: Bump it when the meaning of a stored position changes — the engine discards a
#: checkpoint whose version it does not recognise and restarts the spec, which
#: costs a re-read, whereas misreading one costs coverage.
FILESHARE_CHECKPOINT_VERSION = "1"

#: Directory depth below a root. Past it the subtree is a recorded gap rather than
#: a silent stop: a share with a thousand nested levels is either a mistake or a
#: hostile mount, and neither should be scanned to exhaustion.
MAX_DEPTH = 64

#: Entries read from one directory. A directory this size is a data store rather
#: than a document folder, and enumerating it fully would hold the whole listing
#: in memory to sort it.
MAX_ENTRIES_PER_DIRECTORY = 50_000

#: Files a single fetch task will read. The remainder is reported as a scope gap,
#: so an operator sees "this root is bigger than one task" rather than a number
#: that quietly stopped counting.
MAX_FILES_PER_SPEC = 100_000


@dataclass(frozen=True, slots=True)
class ShareConfig:
    """The connection blob, validated once so the walk can trust it.

    ``mount_path`` is the read-only mount; ``roots`` are subtrees within it, and
    an empty list means the mount itself. Splitting a share into roots is what
    makes a scan parallelisable — one fetch task per root — and it is also how an
    operator says "scan finance, not the whole file server".
    """

    mount_path: str
    roots: tuple[str, ...] = ()
    include: tuple[str, ...] = ()
    exclude: tuple[str, ...] = ()
    follow_symlinks: bool = False
    max_file_bytes: int = ExtractionLimits().max_input_bytes

    @classmethod
    def from_connection(cls, connection: Mapping[str, Any]) -> ShareConfig:
        mount = str(connection.get("mount_path") or "").strip()
        if not mount:
            raise ConnectorError("fileshare source has no mount_path")
        limits = ExtractionLimits()
        return cls(
            mount_path=mount,
            roots=tuple(_clean(connection.get("roots"))),
            include=tuple(_clean(connection.get("include"))),
            exclude=tuple(_clean(connection.get("exclude"))),
            follow_symlinks=bool(connection.get("follow_symlinks", False)),
            max_file_bytes=int(connection.get("max_file_bytes") or limits.max_input_bytes),
        )


def _clean(value: object) -> list[str]:
    if not isinstance(value, list | tuple):
        return []
    return [str(item).strip() for item in value if str(item).strip()]


@dataclass(frozen=True, slots=True)
class _Entry:
    """One file the walk decided to look at."""

    #: Path relative to the mount, POSIX-style. This is the finding's identity, so
    #: it must not contain the mount point: remounting the same share somewhere
    #: else must not orphan every finding on it (ADR 0006).
    key: str
    path: Path
    size: int


class FileshareConnector:
    """Walk a mounted share and hand every readable file to detection.

    ``discover`` produces one spec per configured root; ``fetch`` walks one of
    them in a deterministic order, which is what lets a reclaimed task resume from
    a checkpoint without skipping or repeating (#143).
    """

    connector_type = FILESHARE_CONNECTOR_TYPE
    #: How this connector names its scopes, in the connection blob and in a spec's
    #: params. Read by the engine runner through ``getattr`` (`runner.py`).
    scope_key = "roots"
    scope_param = "root"
    body_kind = CoverageObjectKind.PATH

    metadata = ConnectorMetadata(
        connector_type=FILESHARE_CONNECTOR_TYPE,
        capabilities=frozenset(
            {
                ConnectorCapability.DISCOVERY,
                ConnectorCapability.GAP_REPORTING,
                ConnectorCapability.CHECKPOINTS,
                # No credential of its own: the mount carries it, so a share with
                # no lease credential is the ordinary case rather than an error.
                ConnectorCapability.ANONYMOUS_AUTH,
            }
        ),
    )

    def __init__(
        self,
        *,
        limits: ExtractionLimits | None = None,
        sandbox: ExtractionSandbox | None = None,
    ) -> None:
        self._limits = limits or ExtractionLimits()
        self._sandbox = sandbox

    # ─── Discovery ────────────────────────────────────────────────────────────

    def discover(
        self,
        connection: Mapping[str, Any],
        credential: str | None = None,
    ) -> Iterator[TaskSpec]:
        """One spec per configured root, or one for the mount itself.

        The roots are *not* enumerated from the filesystem when none is
        configured. Walking a file server to find its top-level directories and
        turning each into a task would make the scope of a scan depend on what
        somebody created last week — an operator asked for this mount, and that is
        what gets scanned.

        A configured root that does not exist is reported by the fetch task rather
        than skipped here, so a typo shows up as a gap on the manifest instead of
        as a scan that quietly covered less than it was asked to.
        """
        config = ShareConfig.from_connection(connection)
        mount = self._resolved_mount(config)

        for root in config.roots or ("",):
            # Resolved and contained *now*, because a root escaping the mount is a
            # configuration error worth failing discovery over rather than a gap
            # on one task's manifest.
            target = _contained(mount, mount / root) if root else mount
            if target is None:
                raise ConnectorError(f"configured root escapes the mount: {root!r}")
            yield TaskSpec(
                label=f"share {root or '/'}",
                params={"root": root, "mount_path": config.mount_path},
            )

    # ─── Fetch ────────────────────────────────────────────────────────────────

    def fetch(
        self,
        connection: Mapping[str, Any],
        spec: TaskSpec,
        credential: str | None,
        outcome: FetchOutcome,
    ) -> Iterator[ContentUnit]:
        """Walk one root, yielding a unit per readable file.

        Deterministic order — every directory's entries are sorted — which is what
        makes the checkpoint below mean anything: "everything up to this key has
        been yielded" is only true if the next attempt walks the same order.
        """
        config = ShareConfig.from_connection(connection)
        mount = self._resolved_mount(config)
        root_name = str(spec.params.get("root") or "")
        root = _contained(mount, mount / root_name) if root_name else mount
        if root is None:
            raise ConnectorError("fetch spec root escapes the mount")

        resume_after = _resume_key(outcome.resume_from)
        if not root.is_dir():
            # A configured root that is not there. A scope gap rather than a task
            # failure: the other roots of this share are still worth scanning, and
            # the manifest says this one was not covered.
            outcome.scope_gap_for(CoverageReason.MISSING_RESOURCE, {"root": root_name})
            return

        for entry in self._walk(root, mount, config, outcome):
            if resume_after is not None and entry.key <= resume_after:
                # Already delivered by the attempt that published the checkpoint.
                # Skipped silently rather than counted: it was covered, and
                # counting it again would double the manifest across a reclaim.
                continue
            unit = self._read(entry, config, outcome)
            if unit is not None:
                yield unit
            # Published *after* the unit is yielded, so the position always means
            # "everything up to and including this key has been handed over".
            outcome.checkpoint_at(FILESHARE_CHECKPOINT_VERSION, {"after": entry.key})

    # ─── The walk ─────────────────────────────────────────────────────────────

    def _walk(
        self,
        root: Path,
        mount: Path,
        config: ShareConfig,
        outcome: FetchOutcome,
    ) -> Iterator[_Entry]:
        """Depth-first, sorted, contained, and bounded.

        Sorted so a resumed attempt sees the same order. Contained so no symlink
        or `..` reaches outside the root. Bounded so a hostile or accidental tree
        cannot walk forever.
        """
        seen: set[tuple[int, int]] = set()
        stack: list[tuple[Path, int]] = [(root, 0)]
        files = 0

        while stack:
            directory, depth = stack.pop()
            if depth > MAX_DEPTH:
                outcome.skipped_for(
                    CoverageReason.UNSUPPORTED_TYPE,
                    CoverageObjectKind.PATH,
                    {"path": _key(mount, directory)},
                )
                continue
            try:
                entries = sorted(os.scandir(directory), key=lambda item: item.name)
            except PermissionError:
                outcome.failed_for(
                    CoverageReason.PERMISSION_DENIED,
                    CoverageObjectKind.PATH,
                    {"path": _key(mount, directory)},
                )
                continue
            except OSError:
                # A vanished directory, a stale NFS handle, an I/O error on the
                # share. One subtree, not the task: the rest of the root is still
                # worth reading, and the gap says this part was not.
                outcome.failed_for(
                    CoverageReason.CONNECTOR_ERROR,
                    CoverageObjectKind.PATH,
                    {"path": _key(mount, directory)},
                )
                continue

            if len(entries) > MAX_ENTRIES_PER_DIRECTORY:
                outcome.scope_gap_for(
                    CoverageReason.CONNECTOR_ERROR, {"path": _key(mount, directory)}
                )
                entries = entries[:MAX_ENTRIES_PER_DIRECTORY]

            # Reversed, because the stack pops last-in-first: pushing in reverse
            # makes the walk visit them in sorted order.
            for item in reversed(entries):
                child = Path(item.path)
                if item.is_symlink() and not config.follow_symlinks:
                    # Not an error and not a silent omission: a share full of
                    # symlinks should read as a share full of skips.
                    outcome.skipped_for(
                        CoverageReason.UNSUPPORTED_TYPE,
                        CoverageObjectKind.PATH,
                        {"path": _key(mount, child)},
                    )
                    continue
                resolved = _contained(root, child)
                if resolved is None:
                    # Points outside the root once resolved. The one case that is
                    # a *security* skip rather than a practical one.
                    logger.warning("fileshare_path_escaped_root", root=str(root))
                    outcome.skipped_for(
                        CoverageReason.UNSUPPORTED_TYPE,
                        CoverageObjectKind.PATH,
                        {"path": _key(mount, child)},
                    )
                    continue
                try:
                    info = resolved.stat()
                except OSError:
                    outcome.failed_for(
                        CoverageReason.MISSING_RESOURCE,
                        CoverageObjectKind.PATH,
                        {"path": _key(mount, child)},
                    )
                    continue

                if stat.S_ISDIR(info.st_mode):
                    identity = (info.st_dev, info.st_ino)
                    if identity in seen:
                        # A symlink loop, or a bind mount of an ancestor. Silent:
                        # the directory itself is already being covered.
                        continue
                    seen.add(identity)
                    stack.append((resolved, depth + 1))
                    continue

                if not stat.S_ISREG(info.st_mode):
                    # A FIFO, socket, or device node. Reading a FIFO blocks until
                    # somebody writes to it — a hung task, not a slow one.
                    outcome.skipped_for(
                        CoverageReason.UNSUPPORTED_TYPE,
                        CoverageObjectKind.PATH,
                        {"path": _key(mount, child)},
                    )
                    continue

                key = _key(mount, child)
                if not _selected(key, config):
                    # An operator's include/exclude decision. Recorded, because
                    # "why is that directory not in my results" needs an answer.
                    outcome.skipped_for(
                        CoverageReason.UNSUPPORTED_TYPE, CoverageObjectKind.PATH, {"path": key}
                    )
                    continue

                files += 1
                if files > MAX_FILES_PER_SPEC:
                    outcome.scope_gap_for(CoverageReason.CONNECTOR_ERROR, {"root": str(root)})
                    return
                yield _Entry(key=key, path=resolved, size=info.st_size)

    def _read(
        self,
        entry: _Entry,
        config: ShareConfig,
        outcome: FetchOutcome,
    ) -> ContentUnit | None:
        """One file, through the same extraction pipeline every connector uses."""
        if entry.size > config.max_file_bytes:
            # Before opening it. The cheapest check, and the one that makes "a
            # share with a 40 GB backup in it" a recorded gap rather than a worker
            # that reads 40 GB to find out.
            #
            # A *failure*, not a skip: the file was in scope and should have been
            # readable, so source-wide reconciliation must not treat findings
            # absent from it as remediated. An image is a policy skip; a file too
            # big to open is missing assurance (`ExtractionOutcome.is_incomplete`).
            outcome.failed_for(
                CoverageReason.SIZE_LIMIT, CoverageObjectKind.PATH, {"path": entry.key}
            )
            return None
        try:
            data = entry.path.read_bytes()
        except PermissionError:
            outcome.failed_for(
                CoverageReason.PERMISSION_DENIED, CoverageObjectKind.PATH, {"path": entry.key}
            )
            return None
        except OSError:
            outcome.failed_for(
                CoverageReason.CONNECTOR_ERROR, CoverageObjectKind.PATH, {"path": entry.key}
            )
            return None

        extracted = extract_text(
            data,
            PurePosixPath(entry.key).name,
            limits=self._limits,
            sandbox=self._sandbox,
        )
        if not extracted.outcome.is_text:
            _record_extraction(outcome, entry, extracted.outcome)
            return None

        outcome.scanned_for(CoverageObjectKind.PATH, {"path": entry.key})
        return ContentUnit(
            locator=CoarseLocator(
                connector_type=FILESHARE_CONNECTOR_TYPE,
                # Mount-relative, never absolute: remounting the same share at a
                # different path must not orphan every finding on it (ADR 0006).
                resource_id=entry.key,
            ),
            text=extracted.text,
            origin=ContentOrigin.BODY,
            display={
                "path": entry.key,
                "title": PurePosixPath(entry.key).name,
                "bytes": entry.size,
                "truncated": extracted.truncated,
            },
        )

    def _resolved_mount(self, config: ShareConfig) -> Path:
        try:
            mount = Path(config.mount_path).resolve(strict=True)
        except OSError as exc:
            # The share is not mounted, or the engine cannot see it. A task
            # failure rather than an empty scan: an unmounted share that reported
            # zero findings would read as "no secrets here".
            raise ConnectorError("fileshare mount is not readable") from exc
        if not mount.is_dir():
            raise ConnectorError("fileshare mount_path is not a directory")
        return mount


def _record_extraction(outcome: FetchOutcome, entry: _Entry, result: ExtractionOutcome) -> None:
    """Map one extraction outcome onto the manifest.

    The distinction that matters is :attr:`ExtractionOutcome.is_incomplete`: an
    image is a policy skip, while a PDF whose parser timed out is content that
    *should* have been readable — and source-wide reconciliation must not treat
    findings absent from it as remediated.
    """
    reference = {"path": entry.key}
    match result:
        case ExtractionOutcome.REJECTED_TOO_LARGE:
            outcome.failed_for(CoverageReason.SIZE_LIMIT, CoverageObjectKind.PATH, reference)
        case ExtractionOutcome.SKIPPED_BINARY:
            outcome.skipped_for(CoverageReason.BINARY_CONTENT, CoverageObjectKind.PATH, reference)
        case ExtractionOutcome.SKIPPED_EMPTY:
            outcome.skipped_for(CoverageReason.EMPTY_CONTENT, CoverageObjectKind.PATH, reference)
        case ExtractionOutcome.SKIPPED_UNSUPPORTED:
            outcome.skipped_for(CoverageReason.UNSUPPORTED_TYPE, CoverageObjectKind.PATH, reference)
        case ExtractionOutcome.FAILED_TIMEOUT:
            outcome.failed_for(CoverageReason.TIMEOUT, CoverageObjectKind.PATH, reference)
        case ExtractionOutcome.REJECTED_BOMB:
            outcome.failed_for(CoverageReason.SIZE_LIMIT, CoverageObjectKind.PATH, reference)
        case _:
            outcome.failed_for(CoverageReason.PARSE_ERROR, CoverageObjectKind.PATH, reference)


def _contained(root: Path, candidate: Path) -> Path | None:
    """``candidate`` resolved, or None if it is not inside ``root``.

    The check is on the *resolved* path, which is the only form that cannot lie: a
    symlink, a `..`, or a spec written by an older engine all disappear once the
    kernel has followed them. Both sides are resolved, because a root that is
    itself reached through a symlink would otherwise never contain anything.
    """
    try:
        resolved = candidate.resolve()
        base = root.resolve()
    except OSError:
        return None
    return resolved if resolved == base or resolved.is_relative_to(base) else None


def _key(mount: Path, path: Path) -> str:
    """A path's identity: POSIX, relative to the mount, no leading slash."""
    try:
        return PurePosixPath(path.resolve().relative_to(mount.resolve())).as_posix()
    except OSError, ValueError:  # pragma: no cover — guarded by `_contained`
        return PurePosixPath(path.name).as_posix()


def _selected(key: str, config: ShareConfig) -> bool:
    """Whether include/exclude let this path through.

    Exclude wins. An operator who has written both is saying "these, but not
    those", and the safe reading of an ambiguous rule set is the narrower one.
    """
    if any(fnmatch(key, pattern) for pattern in config.exclude):
        return False
    return not config.include or any(fnmatch(key, pattern) for pattern in config.include)


def _resume_key(checkpoint: Checkpoint | None) -> str | None:
    """The position a resumed fetch continues after, or None to start at the top."""
    if checkpoint is None or checkpoint.version != FILESHARE_CHECKPOINT_VERSION:
        return None
    after = checkpoint.position.get("after")
    return after if isinstance(after, str) and after else None
