"""The SDK 1.1 checkpoint and cursor contract (#143).

Two optional behaviours, both carried on :class:`FetchOutcome` so no method
signature changes — a signature change would be an SDK major, and an engine image
may not mix connector majors.

The recurring theme is **what a checkpoint is allowed to mean**: it is a boundary
past which a fresh fetch may start, so anything that would let one be published
early, misread, or double-counted is a correctness bug rather than a nicety.
"""

from typing import Any

import pytest
from iceberg_connectors import (
    CONNECTOR_SDK_VERSION,
    Checkpoint,
    ConnectorCapability,
    FakeConnector,
    FakePage,
    FetchOutcome,
    SourceCursor,
    assert_checkpoint_resume,
    assert_incremental_contract,
)
from iceberg_connectors.fake import FAKE_CHECKPOINT_VERSION
from iceberg_connectors.testing import ConformanceCase

KEY = b"connector-conformance-reference-key"
SECRET = "AKIAIOSFODNN7EXAMPLE"


def _pages(count: int, *, first_revision: int = 1) -> list[FakePage]:
    return [FakePage(f"record-{n}", f"text {n}", revision=first_revision + n) for n in range(count)]


def _case(connector: FakeConnector, **overrides: Any) -> ConformanceCase:
    defaults: dict[str, Any] = {
        "connector": connector,
        "connection": {},
        "credential": None,
        "reference_key": KEY,
    }
    return ConformanceCase(**(defaults | overrides))


# ─── The SDK declares 1.1 ─────────────────────────────────────────────────────


def test_the_sdk_minor_moved_and_the_major_did_not() -> None:
    """A major would forbid mixing connectors in one engine image; 1.1 only adds."""
    major, minor = CONNECTOR_SDK_VERSION.split(".", 1)

    assert (major, minor) == ("1", "1")


def test_the_two_new_capabilities_are_off_unless_declared() -> None:
    plain = FakeConnector(spaces={"EXAMPLE": _pages(2)})

    assert ConnectorCapability.CHECKPOINTS not in plain.metadata.capabilities
    assert ConnectorCapability.INCREMENTAL not in plain.metadata.capabilities


def test_declaring_them_puts_them_in_the_public_manifest() -> None:
    connector = FakeConnector(spaces={"EXAMPLE": _pages(2)}, resumable=True, incremental=True)

    capabilities = connector.metadata.as_payload()["capabilities"]

    assert isinstance(capabilities, list)
    assert "checkpoints" in capabilities
    assert "incremental" in capabilities


def test_supplied_metadata_still_wins_over_the_flags() -> None:
    """The registry-rejection tests construct metadata explicitly; keep that path."""
    from iceberg_connectors import ConnectorMetadata

    connector = FakeConnector(resumable=True, metadata=ConnectorMetadata("not-fake"))

    assert connector.metadata.connector_type == "not-fake"
    assert ConnectorCapability.CHECKPOINTS not in connector.metadata.capabilities


# ─── Checkpoints: publishing ──────────────────────────────────────────────────


def test_the_published_checkpoint_covers_everything_before_the_unit_in_hand() -> None:
    """The pairing an engine flushing mid-fetch depends on.

    ``fetch`` is a generator, so the ``checkpoint_at`` call that follows a ``yield``
    does not run until the consumer asks for the next unit. A consumer holding unit
    *i* therefore sees the checkpoint covering units 0..i-1 — precisely the units
    whose findings it has accumulated. Flushing that pair together is exact: no
    re-read on resume, and nothing skipped.
    """
    connector = FakeConnector(spaces={"EXAMPLE": _pages(3)}, resumable=True)
    spec = next(iter(connector.discover({}, None)))
    outcome = FetchOutcome(reference_key=KEY)

    seen: list[tuple[str, Checkpoint | None]] = []
    for unit in connector.fetch({}, spec, None, outcome):
        seen.append((unit.locator.resource_id, outcome.checkpoint))

    assert [resource for resource, _ in seen] == ["record-0", "record-1", "record-2"]
    assert [point.position["after"] if point else None for _, point in seen] == [
        None,
        "record-0",
        "record-1",
    ]
    # And once the generator is exhausted, the last unit is covered too.
    assert outcome.checkpoint is not None
    assert outcome.checkpoint.position["after"] == "record-2"


def test_a_connector_that_does_not_declare_checkpoints_publishes_none() -> None:
    connector = FakeConnector(spaces={"EXAMPLE": _pages(3)})
    spec = next(iter(connector.discover({}, None)))
    outcome = FetchOutcome(reference_key=KEY)

    list(connector.fetch({}, spec, None, outcome))

    assert outcome.checkpoint is None


# ─── Checkpoints: resuming ────────────────────────────────────────────────────


def test_resuming_continues_after_the_boundary_without_repeating_it() -> None:
    connector = FakeConnector(spaces={"EXAMPLE": _pages(4)}, resumable=True)
    spec = next(iter(connector.discover({}, None)))
    outcome = FetchOutcome(
        reference_key=KEY,
        resume_from=Checkpoint(FAKE_CHECKPOINT_VERSION, {"after": "record-1"}),
    )

    resumed = [unit.locator.resource_id for unit in connector.fetch({}, spec, None, outcome)]

    assert resumed == ["record-2", "record-3"]


def test_a_resumed_fetch_does_not_recount_what_an_earlier_attempt_reported() -> None:
    """Coverage from both attempts is merged by the API, so a re-count doubles it."""
    connector = FakeConnector(spaces={"EXAMPLE": _pages(4)}, resumable=True)
    spec = next(iter(connector.discover({}, None)))
    outcome = FetchOutcome(
        reference_key=KEY,
        resume_from=Checkpoint(FAKE_CHECKPOINT_VERSION, {"after": "record-1"}),
    )

    list(connector.fetch({}, spec, None, outcome))

    assert outcome.as_coverage()["counts"]["discovered"] == 2


def test_a_checkpoint_from_an_unknown_protocol_version_restarts_from_the_top() -> None:
    """Restarting costs a re-read. Guessing at a position costs correctness."""
    connector = FakeConnector(spaces={"EXAMPLE": _pages(3)}, resumable=True)
    spec = next(iter(connector.discover({}, None)))
    outcome = FetchOutcome(
        reference_key=KEY,
        resume_from=Checkpoint("99", {"after": "record-1"}),
    )

    resumed = [unit.locator.resource_id for unit in connector.fetch({}, spec, None, outcome)]

    assert resumed == ["record-0", "record-1", "record-2"]


def test_a_resume_point_a_connector_never_declared_support_for_is_ignored() -> None:
    connector = FakeConnector(spaces={"EXAMPLE": _pages(3)})
    spec = next(iter(connector.discover({}, None)))
    outcome = FetchOutcome(
        reference_key=KEY,
        resume_from=Checkpoint(FAKE_CHECKPOINT_VERSION, {"after": "record-1"}),
    )

    resumed = [unit.locator.resource_id for unit in connector.fetch({}, spec, None, outcome)]

    assert resumed == ["record-0", "record-1", "record-2"]


@pytest.mark.parametrize(
    "payload",
    [
        None,
        {},
        "not a mapping",
        {"version": "1"},
        {"position": {}},
        {"version": "", "position": {}},
    ],
)
def test_an_unreadable_stored_checkpoint_is_none_rather_than_an_exception(
    payload: object,
) -> None:
    """A task must not fail over stored state it can simply ignore."""
    assert Checkpoint.from_payload(payload) is None  # type: ignore[arg-type]


def test_a_checkpoint_round_trips_through_the_wire_shape() -> None:
    point = Checkpoint("2", {"after": "record-7", "token": "abc"})

    assert Checkpoint.from_payload(point.as_payload()) == point


# ─── Cursors ──────────────────────────────────────────────────────────────────


def test_a_finished_scope_proposes_where_the_next_scan_starts() -> None:
    connector = FakeConnector(spaces={"EXAMPLE": _pages(3)}, incremental=True)
    spec = next(iter(connector.discover({}, None)))
    outcome = FetchOutcome(reference_key=KEY)

    list(connector.fetch({}, spec, None, outcome))

    assert outcome.cursor == SourceCursor("EXAMPLE", FAKE_CHECKPOINT_VERSION, {"revision": 3})


def test_discovery_skips_a_scope_whose_cursor_covers_everything_in_it() -> None:
    connector = FakeConnector(spaces={"EXAMPLE": _pages(3)}, incremental=True)

    narrowed = list(connector.discover({}, None, cursors={"EXAMPLE": {"revision": 3}}))

    assert narrowed == []


def test_discovery_still_covers_a_scope_with_something_newer_than_its_cursor() -> None:
    connector = FakeConnector(spaces={"EXAMPLE": _pages(3)}, incremental=True)

    narrowed = list(connector.discover({}, None, cursors={"EXAMPLE": {"revision": 1}}))

    assert [spec.params["space"] for spec in narrowed] == ["EXAMPLE"]
    assert narrowed[0].params["since_revision"] == 1


def test_a_scope_with_no_cursor_is_enumerated_in_full() -> None:
    """A source gains a space between scans; nothing says it has been read."""
    connector = FakeConnector(
        spaces={"OLD": _pages(2), "NEW": _pages(2)},
        incremental=True,
    )

    narrowed = list(connector.discover({}, None, cursors={"OLD": {"revision": 99}}))

    assert [spec.params["space"] for spec in narrowed] == ["NEW"]


def test_a_full_scan_ignores_cursors_entirely() -> None:
    connector = FakeConnector(spaces={"EXAMPLE": _pages(3)}, incremental=True)

    assert len(list(connector.discover({}, None))) == 1
    assert len(list(connector.discover({}, None, cursors=None))) == 1


def test_a_connector_without_the_capability_ignores_a_cursor_it_is_handed() -> None:
    """Fail safe: scanning everything is always correct, just not cheap."""
    connector = FakeConnector(spaces={"EXAMPLE": _pages(3)})

    narrowed = list(connector.discover({}, None, cursors={"EXAMPLE": {"revision": 99}}))

    assert len(narrowed) == 1


# ─── The conformance helpers ──────────────────────────────────────────────────


def test_the_resume_helper_passes_a_connector_that_resumes_honestly() -> None:
    connector = FakeConnector(spaces={"EXAMPLE": _pages(6)}, resumable=True)

    assert_checkpoint_resume(_case(connector))


def test_the_resume_helper_is_a_no_op_for_a_connector_without_the_capability() -> None:
    connector = FakeConnector(spaces={"EXAMPLE": _pages(6)})

    assert_checkpoint_resume(_case(connector))


def test_the_resume_helper_catches_a_connector_that_skips_on_resume() -> None:
    """The failure this helper exists for, and the one a green suite would hide."""

    class SkipsOnResume(FakeConnector):
        def _resume_after(self, outcome: FetchOutcome) -> str | None:
            after = super()._resume_after(outcome)
            if after is None:
                return None
            # Off by one in the direction that loses content.
            index = [page.resource_id for page in self.spaces["EXAMPLE"]].index(after)
            return self.spaces["EXAMPLE"][index + 1].resource_id

    connector = SkipsOnResume(spaces={"EXAMPLE": _pages(6)}, resumable=True)

    with pytest.raises(AssertionError, match="did not continue where it left off"):
        assert_checkpoint_resume(_case(connector))


def test_the_resume_helper_catches_a_connector_that_declares_but_never_publishes() -> None:
    class NeverPublishes(FakeConnector):
        def fetch(self, connection, spec, credential, outcome):  # type: ignore[no-untyped-def]
            saved, self.resumable = self.resumable, False
            try:
                yield from super().fetch(connection, spec, credential, outcome)
            finally:
                self.resumable = saved

    connector = NeverPublishes(spaces={"EXAMPLE": _pages(6)}, resumable=True)

    with pytest.raises(AssertionError, match="published none partway through"):
        assert_checkpoint_resume(_case(connector))


def test_the_incremental_helper_passes_a_connector_that_narrows_honestly() -> None:
    connector = FakeConnector(
        spaces={"ONE": _pages(2), "TWO": _pages(2)},
        incremental=True,
    )

    assert_incremental_contract(_case(connector), {"ONE": {"revision": 99}})


def test_the_incremental_helper_is_a_no_op_without_the_capability() -> None:
    connector = FakeConnector(spaces={"ONE": _pages(2)})

    assert_incremental_contract(_case(connector), {"ONE": {"revision": 99}})


def test_the_incremental_helper_refuses_a_scope_a_full_scan_would_not_produce() -> None:
    class Invents(FakeConnector):
        def discover(self, connection, credential, *, cursors=None):  # type: ignore[no-untyped-def]
            yield from super().discover(connection, credential, cursors=cursors)
            if cursors:
                from iceberg_connectors import TaskSpec

                yield TaskSpec(label="ghost", params={"space": "GHOST"})

    connector = Invents(spaces={"ONE": _pages(2)}, incremental=True)

    with pytest.raises(AssertionError, match="scopes a full scan would not"):
        assert_incremental_contract(_case(connector), {"ONE": {"revision": 1}})


def test_the_incremental_helper_refuses_a_sentinel_inside_a_cursor_narrowed_spec() -> None:
    class Leaks(FakeConnector):
        def discover(self, connection, credential, *, cursors=None):  # type: ignore[no-untyped-def]
            for spec in super().discover(connection, credential, cursors=cursors):
                spec.params["note"] = SECRET
                yield spec

    connector = Leaks(spaces={"ONE": _pages(2)}, incremental=True)

    with pytest.raises(AssertionError, match="sentinel crossed"):
        assert_incremental_contract(
            _case(connector, secret_sentinels=(SECRET,)),
            {"ONE": {"revision": 1}},
        )
