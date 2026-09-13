from __future__ import annotations

from psm.core.models import Device, InventoryItem, Snapshot
from psm.store.db import current_schema_version, migrate
from psm.store.queries import (
    get_device_by_name,
    get_meta,
    insert_device,
    insert_snapshot,
    load_snapshot,
    load_snapshot_index,
    load_snapshot_items,
    set_meta,
)


def test_migration_applies_once(db):
    assert current_schema_version(db) >= 1
    applied = migrate(db)
    assert applied == 0


def test_meta_bootstrapped(db):
    assert int(get_meta(db, "schema_version") or "0") >= 1
    assert get_meta(db, "chain_head") == ""
    assert get_meta(db, "canonical_json_version") == "2"


def test_meta_upsert(db):
    set_meta(db, "chain_head", "deadbeef")
    assert get_meta(db, "chain_head") == "deadbeef"
    set_meta(db, "chain_head", "cafebabe")
    assert get_meta(db, "chain_head") == "cafebabe"


def test_device_roundtrip(db):
    d = Device(name="pc", platform="macos", identifier="localhost")
    insert_device(db, d)
    assert d.id is not None
    loaded = get_device_by_name(db, "pc")
    assert loaded is not None
    assert loaded.platform == "macos"
    assert loaded.identifier == "localhost"


def test_snapshot_with_items_roundtrip(db):
    d = Device(name="pc", platform="macos", identifier="localhost")
    insert_device(db, d)
    assert d.id is not None
    snap = Snapshot(
        device_id=d.id,
        kind="baseline",
        capabilities={"file", "persistence"},
        tool_version="0.1.0",
    )
    items = [
        InventoryItem(
            category="file",
            subject_key="file:c:\\tools\\a.exe",
            payload={"path": "C:\\Tools\\a.exe", "sha256": "aaa", "size": 100},
        ),
        InventoryItem(
            category="persistence",
            subject_key="persist:windows:runkey:foo",
            payload={"location": "runkey", "name": "Foo", "target": "C:\\x.exe"},
        ),
    ]
    insert_snapshot(db, snap, items)
    assert snap.id is not None

    loaded = load_snapshot(db, snap.id)
    assert loaded.capabilities == {"file", "persistence"}
    assert loaded.kind == "baseline"

    idx = load_snapshot_index(db, snap.id)
    assert set(idx.keys()) == {"file", "persistence"}
    assert "file:c:\\tools\\a.exe" in idx["file"]

    all_items = load_snapshot_items(db, snap.id)
    assert len(all_items) == 2


def test_items_dedup_across_snapshots(db):
    d = Device(name="pc", platform="macos", identifier="localhost")
    insert_device(db, d)
    assert d.id is not None
    payload = {"path": "C:\\Tools\\a.exe", "sha256": "aaa"}
    item = InventoryItem(category="file", subject_key="file:x", payload=payload)

    snap_a = Snapshot(device_id=d.id, kind="baseline", capabilities={"file"}, tool_version="0.1.0")
    snap_b = Snapshot(device_id=d.id, kind="scan", capabilities={"file"}, tool_version="0.1.0")
    insert_snapshot(db, snap_a, [item])
    insert_snapshot(db, snap_b, [item])

    n_items = db.execute("SELECT COUNT(*) AS c FROM items").fetchone()["c"]
    assert n_items == 1
    n_links = db.execute("SELECT COUNT(*) AS c FROM snapshot_items").fetchone()["c"]
    assert n_links == 2
