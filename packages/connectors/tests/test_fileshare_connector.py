"""The mounted SMB/NFS share connector (#145).

The share is a directory tree on disk, so these tests build one. That is the
point: the connector's whole job is to walk a filesystem safely, and a fake that
stood in for the filesystem would stub out exactly the behaviour worth testing —
symlink resolution, permission bits, and file modes are the kernel's, not a
double's.

Organised around the three ways a walk goes wrong: it escapes, it never ends, or
it blocks.
"""

import os
import stat
from pathlib import Path
from typing import Any

import pytest
from iceberg_connectors.fileshare import FILESHARE_CONNECTOR_TYPE, FileshareConnector
from iceberg_connectors.fileshare.connector import (
    FILESHARE_CHECKPOINT_VERSION,
    MAX_DEPTH,
)
from iceberg_connectors.protocol import (
    Checkpoint,
    ConnectorCapability,
    ConnectorError,
    FetchOutcome,
    TaskSpec,
)
from iceberg_connectors.testing import (
    ConformanceCase,
    assert_checkpoint_resume,
    assert_connector_conformance,
)
from iceberg_core.enums import CoverageReason

REFERENCE_KEY = b"\x00" * 32

#: Real file content, used to prove nothing from the share reaches a spec label,
#: a coverage reference, or a checkpoint position.
SENTINEL = "aws_secret_access_key = AKIAIOSFODNN7EXAMPLE"


@pytest.fixture(name="share")
def share_fixture(tmp_path: Path) -> Path:
    """A small share: two departments, a mix of readable and not."""
    (tmp_path / "finance").mkdir()
    (tmp_path / "finance" / "budget.txt").write_text("aws_secret_access_key = redacted")
    (tmp_path / "finance" / "notes.md").write_text("nothing here")
    (tmp_path / "eng").mkdir()
    (tmp_path / "eng" / "deploy.sh").write_text("export TOKEN=abc")
    return tmp_path


def _connection(share: Path, **overrides: Any) -> dict[str, Any]:
    return {"mount_path": str(share), "protocol": "smb"} | overrides


def _fetch(
    connector: FileshareConnector,
    connection: dict[str, Any],
    root: str = "",
    *,
    resume_from: Checkpoint | None = None,
) -> tuple[list[Any], FetchOutcome]:
    outcome = FetchOutcome(reference_key=REFERENCE_KEY, resume_from=resume_from)
    spec = TaskSpec(label="share", params={"root": root})
    units = list(connector.fetch(connection, spec, None, outcome))
    return units, outcome


def _reasons(outcome: FetchOutcome) -> set[str]:
    return {gap["reason"] for gap in outcome.coverage.as_payload()["gaps"]}


# ─── Discovery ────────────────────────────────────────────────────────────────


def test_each_configured_root_becomes_one_fetch_task(share: Path) -> None:
    """One task per root is what parallelises a scan across engines."""
    connector = FileshareConnector()

    specs = list(connector.discover(_connection(share, roots=["finance", "eng"])))

    assert [spec.params["root"] for spec in specs] == ["finance", "eng"]


def test_a_share_with_no_roots_is_scanned_whole(share: Path) -> None:
    specs = list(FileshareConnector().discover(_connection(share)))

    assert [spec.params["root"] for spec in specs] == [""]


def test_the_top_level_directories_are_not_enumerated_into_roots(share: Path) -> None:
    """Turning whatever exists today into tasks would make the scope of a scan
    depend on what somebody created last week. An operator asked for this mount."""
    specs = list(FileshareConnector().discover(_connection(share)))

    assert len(specs) == 1


def test_discovery_is_reproducible(share: Path) -> None:
    """The conformance kit runs discovery twice and compares payloads."""
    connector = FileshareConnector()
    connection = _connection(share, roots=["finance", "eng"])

    first = [spec.as_payload() for spec in connector.discover(connection)]
    second = [spec.as_payload() for spec in connector.discover(connection)]

    assert first == second


def test_an_unmounted_share_fails_the_task_rather_than_reporting_nothing(
    tmp_path: Path,
) -> None:
    """An unmounted share that reported zero findings would read as "no secrets
    here" — the single most expensive thing this system can get wrong."""
    connector = FileshareConnector()

    with pytest.raises(ConnectorError, match="not readable"):
        list(connector.discover({"mount_path": str(tmp_path / "absent")}))


def test_a_root_that_escapes_the_mount_fails_discovery(share: Path) -> None:
    """A configuration error worth failing over, rather than a gap on one task."""
    with pytest.raises(ConnectorError, match="escapes"):
        list(FileshareConnector().discover(_connection(share, roots=["../.."])))


# ─── The ordinary walk ────────────────────────────────────────────────────────


def test_every_readable_file_becomes_a_unit(share: Path) -> None:
    units, outcome = _fetch(FileshareConnector(), _connection(share))

    assert sorted(unit.locator.resource_id for unit in units) == [
        "eng/deploy.sh",
        "finance/budget.txt",
        "finance/notes.md",
    ]
    assert outcome.units == 3


def test_identity_is_the_path_within_the_share_not_the_mount_point(
    tmp_path: Path, share: Path
) -> None:
    """Remounting the same share somewhere else must not orphan every finding on
    it: the mount point is a deployment detail, the path within the share is the
    file (ADR 0006)."""
    moved = tmp_path.parent / f"{tmp_path.name}-remounted"
    units_before, _ = _fetch(FileshareConnector(), _connection(share))
    os.rename(share, moved)

    units_after, _ = _fetch(FileshareConnector(), _connection(moved))

    assert sorted(unit.locator.resource_id for unit in units_before) == sorted(
        unit.locator.resource_id for unit in units_after
    )


def test_a_root_narrows_the_walk_to_one_subtree(share: Path) -> None:
    units, _outcome = _fetch(FileshareConnector(), _connection(share), root="finance")

    assert all(unit.locator.resource_id.startswith("finance/") for unit in units)


def test_a_missing_root_is_a_gap_not_a_silent_zero(share: Path) -> None:
    """A typo must show up on the manifest. The other roots of this share are
    still worth scanning."""
    _units, outcome = _fetch(FileshareConnector(), _connection(share), root="marketing")

    assert outcome.coverage.as_payload()["scope"]["gaps"] == 1
    assert CoverageReason.MISSING_RESOURCE.value in _reasons(outcome)


def test_the_walk_is_deterministic(share: Path) -> None:
    """The checkpoint below means "everything up to this key", which is only true
    if the next attempt walks the same order."""
    connector = FileshareConnector()

    first, _ = _fetch(connector, _connection(share))
    second, _ = _fetch(connector, _connection(share))

    assert [unit.locator.resource_id for unit in first] == [
        unit.locator.resource_id for unit in second
    ]


# ─── It escapes ───────────────────────────────────────────────────────────────


def test_a_symlink_out_of_the_share_is_not_followed(share: Path, tmp_path: Path) -> None:
    """The failure this exists to prevent: a scan quietly covering a system
    nobody authorised, because somebody left a symlink on a file server."""
    outside = tmp_path.parent / "outside-the-share"
    outside.mkdir(exist_ok=True)
    (outside / "private.txt").write_text("aws_secret_access_key = elsewhere")
    (share / "finance" / "link").symlink_to(outside)

    units, outcome = _fetch(FileshareConnector(), _connection(share))

    assert all("private" not in unit.locator.resource_id for unit in units)
    assert outcome.skipped >= 1


def test_a_symlink_out_of_the_share_is_refused_even_when_following_is_on(
    share: Path, tmp_path: Path
) -> None:
    """Containment is not the symlink policy — it is checked on the *resolved*
    path, which is the only form that cannot lie."""
    outside = tmp_path.parent / "outside-the-share-2"
    outside.mkdir(exist_ok=True)
    (outside / "private.txt").write_text("aws_secret_access_key = elsewhere")
    (share / "eng" / "link").symlink_to(outside)

    units, _outcome = _fetch(
        FileshareConnector(), _connection(share, follow_symlinks=True, roots=["eng"]), root="eng"
    )

    assert all("private" not in unit.locator.resource_id for unit in units)


def test_a_symlink_within_the_root_is_followed_when_asked(share: Path) -> None:
    """The feature the containment check must not break: a subtree that organises
    itself with symlinks is still scannable."""
    (share / "eng" / "nested").mkdir()
    (share / "eng" / "nested" / "config.env").write_text("TOKEN=abc")
    (share / "eng" / "alias").symlink_to(share / "eng" / "nested")

    units, _outcome = _fetch(
        FileshareConnector(), _connection(share, follow_symlinks=True), root="eng"
    )

    assert "eng/nested/config.env" in [unit.locator.resource_id for unit in units]


def test_a_symlink_loop_back_to_the_root_does_not_double_scan(share: Path) -> None:
    """The dedupe set registers directories as they are *discovered*, so the root
    — pushed onto the stack directly — needs registering too. Without it a loop
    back to the root re-walks it: every direct file yielded and counted twice,
    an inflated manifest that cannot be reconciled against the share."""
    (share / "eng" / "sub").mkdir()
    (share / "eng" / "sub" / "loop").symlink_to(share / "eng")

    units, outcome = _fetch(
        FileshareConnector(), _connection(share, follow_symlinks=True), root="eng"
    )

    assert [unit.locator.resource_id for unit in units] == ["eng/deploy.sh"]
    assert outcome.coverage.as_payload()["counts"]["scanned"] == 1


def test_a_symlink_to_another_root_is_not_followed(share: Path) -> None:
    """Containment is against the *root*, not the mount. Following a link into a
    sibling root would have two fetch tasks scan the same files — double-counted
    coverage, and a manifest that cannot be reconciled against the share."""
    (share / "eng" / "shared").symlink_to(share / "finance")

    units, _outcome = _fetch(
        FileshareConnector(), _connection(share, follow_symlinks=True), root="eng"
    )

    assert all(not unit.locator.resource_id.startswith("finance/") for unit in units)


def test_a_spec_naming_a_path_outside_the_mount_is_refused(share: Path) -> None:
    """A spec is persisted and leased back later; one written by an older engine,
    or edited, must not become a directory traversal."""
    outcome = FetchOutcome(reference_key=REFERENCE_KEY)
    spec = TaskSpec(label="escape", params={"root": "../../etc"})

    with pytest.raises(ConnectorError, match="escapes"):
        list(FileshareConnector().fetch(_connection(share), spec, None, outcome))


# ─── It never ends ────────────────────────────────────────────────────────────


def test_a_symlink_cycle_terminates(share: Path) -> None:
    """A directory that links to its own ancestor. Without the visited-inode set
    this walks until the task is killed."""
    (share / "finance" / "loop").symlink_to(share)

    units, _outcome = _fetch(FileshareConnector(), _connection(share, follow_symlinks=True))

    assert len(units) == 3


def test_a_tree_deeper_than_the_limit_stops_and_says_so(share: Path) -> None:
    """A share with a thousand nested levels is a mistake or a hostile mount.
    Either way it is a recorded gap rather than a silent stop."""
    deep = share / "deep"
    deep.mkdir()
    current = deep
    for index in range(MAX_DEPTH + 2):
        current = current / f"level{index}"
        current.mkdir()
    (current / "buried.txt").write_text("aws_secret_access_key = deep")

    units, outcome = _fetch(FileshareConnector(), _connection(share), root="deep")

    assert units == []
    assert outcome.skipped >= 1


# ─── It blocks, or refuses ────────────────────────────────────────────────────


def test_a_fifo_is_skipped_rather_than_opened(share: Path) -> None:
    """Reading a FIFO blocks until somebody writes to it. That is a hung task,
    not a slow one, and no timeout in this connector would catch it."""
    os.mkfifo(share / "eng" / "pipe")

    units, outcome = _fetch(FileshareConnector(), _connection(share), root="eng")

    assert [unit.locator.resource_id for unit in units] == ["eng/deploy.sh"]
    assert CoverageReason.UNSUPPORTED_TYPE.value in _reasons(outcome)


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores permission bits")
def test_an_unreadable_file_is_a_failure_not_a_skip(share: Path) -> None:
    """A file that *should* have been readable and was not means a source-wide
    reconciliation must not treat its absent findings as remediated."""
    secret = share / "eng" / "locked.txt"
    secret.write_text("aws_secret_access_key = locked")
    secret.chmod(0o000)

    try:
        _units, outcome = _fetch(FileshareConnector(), _connection(share), root="eng")
    finally:
        secret.chmod(0o644)

    assert outcome.failed == 1
    assert CoverageReason.PERMISSION_DENIED.value in _reasons(outcome)


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores permission bits")
def test_an_unreadable_directory_does_not_stop_the_rest_of_the_walk(share: Path) -> None:
    """One subtree, not the task: the rest of the root is still worth reading."""
    locked = share / "eng" / "restricted"
    locked.mkdir()
    (locked / "inside.txt").write_text("aws_secret_access_key = inside")
    locked.chmod(0o000)

    try:
        units, outcome = _fetch(FileshareConnector(), _connection(share), root="eng")
    finally:
        locked.chmod(0o755)

    assert [unit.locator.resource_id for unit in units] == ["eng/deploy.sh"]
    assert CoverageReason.PERMISSION_DENIED.value in _reasons(outcome)


# ─── Policy: what is in scope ─────────────────────────────────────────────────


def test_a_file_over_the_size_limit_is_a_gap_before_it_is_read(share: Path) -> None:
    """The cheapest check — a share with a 40 GB backup in it should not be a
    worker that reads 40 GB to find out.

    Recorded as a *failure* rather than a skip, because the file was in scope and
    should have been readable: reconciliation must not treat findings absent from
    it as remediated. An image is a policy skip; this is missing assurance."""
    (share / "eng" / "big.txt").write_bytes(b"x" * 4096)

    _units, outcome = _fetch(
        FileshareConnector(), _connection(share, max_file_bytes=1024), root="eng"
    )

    assert outcome.failed == 1
    assert CoverageReason.SIZE_LIMIT.value in _reasons(outcome)


def test_exclude_wins_over_include(share: Path) -> None:
    """An operator who wrote both is saying "these, but not those", and the safe
    reading of an ambiguous rule set is the narrower one."""
    units, _outcome = _fetch(
        FileshareConnector(),
        _connection(share, include=["finance/*"], exclude=["*/notes.md"]),
    )

    assert [unit.locator.resource_id for unit in units] == ["finance/budget.txt"]


def test_an_excluded_file_is_recorded_not_silently_dropped(share: Path) -> None:
    """ "Why is that directory not in my results" needs an answer."""
    _units, outcome = _fetch(
        FileshareConnector(), _connection(share, exclude=["eng/*"]), root="eng"
    )

    assert outcome.skipped == 1


def test_a_binary_file_is_skipped_as_binary(share: Path) -> None:
    (share / "eng" / "blob.txt").write_bytes(b"\x00\x01\x02\x03" * 64)

    _units, outcome = _fetch(FileshareConnector(), _connection(share), root="eng")

    assert CoverageReason.BINARY_CONTENT.value in _reasons(outcome)


def test_an_unsupported_format_is_a_policy_skip(share: Path) -> None:
    """An image is not an error, and must not fail the task — unlike a PDF whose
    parser timed out, which is content that should have been readable."""
    (share / "eng" / "photo.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 64)

    _units, outcome = _fetch(FileshareConnector(), _connection(share), root="eng")

    assert outcome.failed == 0
    assert outcome.skipped == 1


# ─── Resuming ─────────────────────────────────────────────────────────────────


def test_a_checkpoint_is_published_after_each_file(share: Path) -> None:
    """Published *after* the unit is yielded, so the position always means
    "everything up to and including this key has been handed over"."""
    connector = FileshareConnector()
    outcome = FetchOutcome(reference_key=REFERENCE_KEY)
    spec = TaskSpec(label="share", params={"root": ""})

    stream = connector.fetch(_connection(share), spec, None, outcome)
    first = next(stream)

    # Not published until the consumer asks for the next unit — the generator has
    # not run past the yield yet. Read into a local, so narrowing the attribute
    # to None does not follow it across the `next()` that changes it.
    before = outcome.checkpoint
    assert before is None
    next(stream)
    published = outcome.checkpoint
    assert published is not None
    assert published.position["after"] == first.locator.resource_id


def test_a_resumed_fetch_neither_repeats_nor_skips(share: Path) -> None:
    connector = FileshareConnector()
    everything, _ = _fetch(connector, _connection(share))
    after_first = Checkpoint(
        version=FILESHARE_CHECKPOINT_VERSION,
        position={"after": everything[0].locator.resource_id},
    )

    resumed, _outcome = _fetch(connector, _connection(share), resume_from=after_first)

    assert [unit.locator.resource_id for unit in resumed] == [
        unit.locator.resource_id for unit in everything[1:]
    ]


def test_work_already_covered_is_not_counted_twice_after_a_reclaim(share: Path) -> None:
    """Counting the skipped prefix again would double the manifest across a
    reclaim, and a coverage report that inflates is one nobody can reconcile."""
    connector = FileshareConnector()
    everything, _ = _fetch(connector, _connection(share))
    after_first = Checkpoint(
        version=FILESHARE_CHECKPOINT_VERSION,
        position={"after": everything[0].locator.resource_id},
    )

    _resumed, outcome = _fetch(connector, _connection(share), resume_from=after_first)

    assert outcome.units == len(everything) - 1
    assert outcome.skipped == 0


def test_a_checkpoint_from_another_protocol_version_restarts_the_spec(share: Path) -> None:
    """Discarding one costs a re-read; misreading one costs coverage."""
    stale = Checkpoint(version="0", position={"after": "finance/budget.txt"})

    units, _outcome = _fetch(FileshareConnector(), _connection(share), resume_from=stale)

    assert len(units) == 3


# ─── Contract ─────────────────────────────────────────────────────────────────


def test_the_connector_declares_what_it_can_do() -> None:
    metadata = FileshareConnector().metadata

    assert metadata.connector_type == FILESHARE_CONNECTOR_TYPE
    assert ConnectorCapability.CHECKPOINTS in metadata.capabilities
    # The mount carries the credential, so a lease without one is ordinary.
    assert ConnectorCapability.ANONYMOUS_AUTH in metadata.capabilities


def test_a_checkpoint_never_carries_content_or_a_credential(share: Path) -> None:
    """The conformance kit scans positions for both; asserted here as well
    because this connector's position is derived from file paths."""
    _units, outcome = _fetch(FileshareConnector(), _connection(share))

    assert outcome.checkpoint is not None
    assert set(outcome.checkpoint.position) == {"after"}


def test_a_unit_carries_the_path_for_suppressions_to_match_on(share: Path) -> None:
    """`path` is one of the glob-friendly display keys, and without it an analyst
    has nothing to write a `path_glob` suppression against (`units.py`)."""
    units, _outcome = _fetch(FileshareConnector(), _connection(share), root="finance")

    assert units[0].display["path"] == units[0].locator.resource_id


def test_a_file_mode_test_helper_is_not_lying(share: Path) -> None:
    """Sanity: the fixture really does contain a regular file, so the
    `S_ISREG` guard is being exercised rather than trivially satisfied."""
    assert stat.S_ISREG((share / "eng" / "deploy.sh").stat().st_mode)


def test_a_subdirectory_that_sorts_first_is_not_skipped_on_resume(share: Path) -> None:
    """The walk must hand files over in the order the resume comparison assumes.

    Yielding a directory's own files before descending put `a/x.txt` *after*
    `m.txt` in the stream while the comparison read it as earlier, so a reclaimed
    attempt resuming past `m.txt` skipped it — and the manifest called the scope
    clean, which is the worst way for this scanner to be wrong (#189).
    """
    root = share / "resume"
    (root / "a").mkdir(parents=True)
    (root / "a" / "x.txt").write_text(SENTINEL)
    (root / "b.txt").write_text("bee")
    (root / "m.txt").write_text("em")

    units, _outcome = _fetch(FileshareConnector(), _connection(share), root="resume")
    order = [unit.locator.resource_id for unit in units]

    assert order == ["resume/a/x.txt", "resume/b.txt", "resume/m.txt"]
    # Resuming from any point delivers exactly the remainder — nothing skipped,
    # nothing handed over twice.
    for index, cut in enumerate(order):
        resumed, _ = _fetch(
            FileshareConnector(),
            _connection(share),
            root="resume",
            resume_from=Checkpoint(version=FILESHARE_CHECKPOINT_VERSION, position={"after": cut}),
        )
        assert [unit.locator.resource_id for unit in resumed] == order[index + 1 :]


def test_a_subtree_resumes_before_a_sibling_file_that_extends_its_name(share: Path) -> None:
    """The names where comparing the joined keys is wrong rather than merely ugly.

    `/` (0x2F) sorts after `.` (0x2E), so `"trap/a.txt" < "trap/a/b.txt"` as
    plain strings while the walk yields `trap/a/b.txt` first — a directory's
    subtree comes before a sibling file whose name extends the directory's. A
    resume comparing whole keys would read `trap/a.txt` as already delivered and
    drop it, so the position is compared segment by segment.
    """
    trap = share / "trap"
    (trap / "a").mkdir(parents=True)
    (trap / "a" / "b.txt").write_text("bee")
    (trap / "a.txt").write_text("ay")

    units, _outcome = _fetch(FileshareConnector(), _connection(share), root="trap")
    order = [unit.locator.resource_id for unit in units]
    assert order == ["trap/a/b.txt", "trap/a.txt"]
    assert "trap/a.txt" < "trap/a/b.txt"  # the trap, as plain strings

    resumed, _ = _fetch(
        FileshareConnector(),
        _connection(share),
        root="trap",
        resume_from=Checkpoint(
            version=FILESHARE_CHECKPOINT_VERSION, position={"after": "trap/a/b.txt"}
        ),
    )

    assert [unit.locator.resource_id for unit in resumed] == ["trap/a.txt"]


def test_a_checkpoint_from_the_previous_walk_order_is_discarded(share: Path) -> None:
    """A position written by an engine that walked the old order names a place in
    an order this one does not walk. Discarding it re-reads the root; trusting it
    would skip whatever the two orders disagree about."""
    (share / "eng" / "later.txt").write_text("later")

    units, _outcome = _fetch(
        FileshareConnector(),
        _connection(share),
        root="eng",
        resume_from=Checkpoint(version="1", position={"after": "eng/deploy.sh"}),
    )

    # Restarted from the top rather than resumed: deploy.sh is delivered again.
    assert "eng/deploy.sh" in [unit.locator.resource_id for unit in units]


def test_the_connector_passes_the_shared_conformance_kit(share: Path) -> None:
    """The kit every connector must satisfy (`docs/connector-sdk.md`): reproducible
    discovery, distinct task identities, coverage dispositions that reconcile, and
    no content or credential anywhere in the public payload.

    The sentinel is real file content from the fixture, so a connector that leaked
    a snippet into a spec label or a coverage reference would fail here rather
    than in production.
    """
    (share / "finance" / "leak.txt").write_text(SENTINEL)

    payload = assert_connector_conformance(
        ConformanceCase(
            connector=FileshareConnector(),
            connection=_connection(share, roots=["finance", "eng"]),
            credential=None,
            reference_key=REFERENCE_KEY,
            expected_minimum_specs=2,
            expected_minimum_units=3,
            secret_sentinels=(SENTINEL,),
        )
    )

    metadata = payload["metadata"]
    assert isinstance(metadata, dict)
    assert metadata["connector_type"] == FILESHARE_CONNECTOR_TYPE


def test_the_connector_passes_the_shared_checkpoint_resume_kit(share: Path) -> None:
    """The kit's resume check, which this connector declared CHECKPOINTS without
    ever running (#189) — Confluence and Jira both call it.

    The fixture is deliberately nested and wide enough to be a real test: a spec
    needs three units before the kit will resume from partway through, and the
    defect it exists to catch only appears when a subdirectory sorts before a file
    beside it.
    """
    nested = share / "eng" / "alpha"
    nested.mkdir(parents=True, exist_ok=True)
    (nested / "one.txt").write_text("one")
    (nested / "two.txt").write_text("two")
    (share / "eng" / "zulu.txt").write_text("zulu")

    assert_checkpoint_resume(
        ConformanceCase(
            connector=FileshareConnector(),
            connection=_connection(share, roots=["eng"]),
            credential=None,
            reference_key=REFERENCE_KEY,
        )
    )


def test_an_oversized_directory_is_capped_before_it_is_materialised(
    share: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The cap has to bound the *read*, not the result. Sorting the whole listing
    and slicing afterwards spends the memory first, so a directory large enough to
    matter kills the worker instead of producing the bounded scope gap.

    Asserted by counting how many entries the walk actually pulls off the
    iterator: with the cap at two, it must stop at three — two plus the one that
    tells it there were more.
    """
    from iceberg_connectors.fileshare import connector as module

    crowded = share / "crowded"
    crowded.mkdir()
    for index in range(20):
        (crowded / f"file{index:02d}.txt").write_text("nothing")

    monkeypatch.setattr(module, "MAX_ENTRIES_PER_DIRECTORY", 2)
    pulled = 0
    real_scandir = os.scandir

    class Counting:
        """`os.scandir`'s context-manager + iterator contract, counting pulls."""

        def __init__(self, path: str) -> None:
            self._scanner = real_scandir(path)

        def __enter__(self) -> Counting:
            return self

        def __exit__(self, *exc: object) -> None:
            self._scanner.close()

        def __iter__(self) -> Counting:
            return self

        def __next__(self) -> os.DirEntry[str]:
            nonlocal pulled
            entry = next(self._scanner)
            pulled += 1
            return entry

    monkeypatch.setattr(os, "scandir", Counting)
    _units, outcome = _fetch(FileshareConnector(), _connection(share), root="crowded")

    assert pulled <= 3, f"read {pulled} entries with the cap at 2"
    assert outcome.coverage.as_payload()["scope"]["gaps"] == 1
