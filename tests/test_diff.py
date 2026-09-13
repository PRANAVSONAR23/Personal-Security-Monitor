from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from psm.core.diff import diff, scope_notes
from psm.core.models import Snapshot


def _snap(id_: int, capabilities: set[str]) -> Snapshot:
    return Snapshot(
        id=id_,
        device_id=1,
        kind="scan",
        capabilities=capabilities,
        tool_version="0.1.0",
    )


def test_identical_snapshots_produce_no_events():
    idx = {"file": {"file:a": "h1", "file:b": "h2"}}
    events = diff(_snap(1, {"file"}), idx, _snap(2, {"file"}), idx)
    assert events == []


def test_added_removed_changed():
    a = _snap(1, {"file"})
    b = _snap(2, {"file"})
    idx_a = {"file": {"file:kept": "h1", "file:gone": "h2", "file:changed": "h3"}}
    idx_b = {"file": {"file:kept": "h1", "file:new": "h4", "file:changed": "h5"}}

    events = diff(a, idx_a, b, idx_b)
    by_action = {e.action: e for e in events}
    assert set(by_action) == {"added", "removed", "changed"}
    assert by_action["added"].subject_key == "file:new"
    assert by_action["added"].before_hash is None
    assert by_action["added"].after_hash == "h4"
    assert by_action["removed"].subject_key == "file:gone"
    assert by_action["removed"].after_hash is None
    assert by_action["removed"].before_hash == "h2"
    assert by_action["changed"].subject_key == "file:changed"
    assert by_action["changed"].before_hash == "h3"
    assert by_action["changed"].after_hash == "h5"
    assert all(e.snap_from == 1 and e.snap_to == 2 for e in events)


def test_capability_only_in_one_snapshot_produces_no_events():
    a = _snap(1, {"file"})
    b = _snap(2, {"file", "persistence"})
    idx_a = {"file": {}}
    idx_b = {
        "file": {},
        "persistence": {"persist:windows:runkey:foo": "hp"},
    }
    events = diff(a, idx_a, b, idx_b)
    assert events == []
    notes = scope_notes(a, b)
    assert notes["only_in_after"] == ["persistence"]


def test_diff_across_categories():
    a = _snap(1, {"file", "persistence"})
    b = _snap(2, {"file", "persistence"})
    idx_a = {"file": {"file:x": "h1"}, "persistence": {}}
    idx_b = {"file": {"file:x": "h1"}, "persistence": {"persist:runkey:foo": "hp"}}
    events = diff(a, idx_a, b, idx_b)
    assert len(events) == 1
    assert events[0].category == "persistence"
    assert events[0].action == "added"


def test_diff_rejects_cross_device():
    a = _snap(1, {"file"})
    a.device_id = 1
    b = _snap(2, {"file"})
    b.device_id = 2
    try:
        diff(a, {}, b, {})
    except ValueError:
        return
    raise AssertionError("expected ValueError for cross-device diff")


_key_st = st.text(alphabet="abcdef", min_size=1, max_size=4).map(lambda s: f"file:{s}")
_hash_st = st.text(alphabet="0123456789abcdef", min_size=4, max_size=8)


@given(st.dictionaries(_key_st, _hash_st, max_size=10))
def test_diff_A_A_is_empty_property(items: dict[str, str]):
    a = _snap(1, {"file"})
    b = _snap(2, {"file"})
    idx = {"file": dict(items)}
    assert diff(a, idx, b, idx) == []


@given(
    st.dictionaries(_key_st, _hash_st, max_size=8),
    st.dictionaries(_key_st, _hash_st, max_size=8),
)
def test_diff_symmetry_of_add_remove(before: dict[str, str], after: dict[str, str]):
    a = _snap(1, {"file"})
    b = _snap(2, {"file"})
    fwd = diff(a, {"file": before}, b, {"file": after})
    rev = diff(a, {"file": after}, b, {"file": before})
    fwd_added = {e.subject_key for e in fwd if e.action == "added"}
    rev_removed = {e.subject_key for e in rev if e.action == "removed"}
    assert fwd_added == rev_removed
