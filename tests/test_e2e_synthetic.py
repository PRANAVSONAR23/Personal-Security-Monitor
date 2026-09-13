"""Phase 0 exit check: insert two synthetic snapshots, diff, append events, verify chain."""

from __future__ import annotations

from psm.core.chain import append_events, verify_chain
from psm.core.diff import diff
from psm.core.models import Device, InventoryItem, Snapshot
from psm.store.db import transaction
from psm.store.queries import (
    insert_device,
    insert_snapshot,
    load_snapshot_index,
)


def test_synthetic_snapshot_diff(db):
    d = Device(name="pc", platform="macos", identifier="localhost")
    insert_device(db, d)
    assert d.id is not None

    baseline_items = [
        InventoryItem(
            category="file",
            subject_key="file:c:\\tools\\a.exe",
            payload={"path": "C:\\Tools\\a.exe", "sha256": "aaa", "size": 100},
        ),
        InventoryItem(
            category="persistence",
            subject_key="persist:windows:runkey:foo",
            payload={"location": "runkey", "name": "Foo", "target": "C:\\Tools\\a.exe"},
        ),
    ]
    baseline = Snapshot(
        device_id=d.id,
        kind="baseline",
        capabilities={"file", "persistence"},
        tool_version="0.1.0",
    )
    insert_snapshot(db, baseline, baseline_items)

    scan_items = [
        # a.exe changed content
        InventoryItem(
            category="file",
            subject_key="file:c:\\tools\\a.exe",
            payload={"path": "C:\\Tools\\a.exe", "sha256": "bbb", "size": 120},
        ),
        # new suspicious file
        InventoryItem(
            category="file",
            subject_key="file:c:\\users\\x\\appdata\\roaming\\bar.exe",
            payload={
                "path": "C:\\Users\\x\\AppData\\Roaming\\bar.exe",
                "sha256": "ccc",
                "size": 800,
                "signature_status": "unsigned",
            },
        ),
        # persistence entry preserved
        InventoryItem(
            category="persistence",
            subject_key="persist:windows:runkey:foo",
            payload={"location": "runkey", "name": "Foo", "target": "C:\\Tools\\a.exe"},
        ),
        # new persistence entry pointing at the new file
        InventoryItem(
            category="persistence",
            subject_key="persist:windows:runkey:bar",
            payload={
                "location": "runkey",
                "name": "Bar",
                "target": "C:\\Users\\x\\AppData\\Roaming\\bar.exe",
            },
        ),
    ]
    scan = Snapshot(
        device_id=d.id,
        kind="scan",
        capabilities={"file", "persistence"},
        tool_version="0.1.0",
    )
    insert_snapshot(db, scan, scan_items)

    idx_a = load_snapshot_index(db, baseline.id)  # type: ignore[arg-type]
    idx_b = load_snapshot_index(db, scan.id)  # type: ignore[arg-type]
    events = diff(baseline, idx_a, scan, idx_b)

    actions = sorted((e.category, e.action, e.subject_key) for e in events)
    assert actions == [
        ("file", "added", "file:c:\\users\\x\\appdata\\roaming\\bar.exe"),
        ("file", "changed", "file:c:\\tools\\a.exe"),
        ("persistence", "added", "persist:windows:runkey:bar"),
    ]

    with transaction(db):
        append_events(db, events)

    report = verify_chain(db)
    assert report.ok, report.error
    assert report.events_checked == 3
