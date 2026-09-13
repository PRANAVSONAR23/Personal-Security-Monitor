"""Phase 1 exit check (UC2-flavored).

Baseline the device, plant a new Run-key entry + a new unsigned exe in the file walk root,
scan, verify the two events show up. persistence/apps are patched so the test never touches
the real registry; the files walker is the real one.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from psm.collectors.windows.modules import apps, persistence
from psm.core.chain import verify_chain
from psm.core.models import Device
from psm.core.orchestrator import take_snapshot
from psm.store.queries import insert_device


@pytest.fixture()
def fake_registry(monkeypatch):
    state = {
        "persistence": [
            {
                "location": "runkey",
                "hive": "HKCU",
                "key": r"Software\Microsoft\Windows\CurrentVersion\Run",
                "name": "InitialApp",
                "value": "C:\\Tools\\InitialApp.exe",
                "target": "C:\\Tools\\InitialApp.exe",
                "args": [],
                "enabled": True,
            }
        ],
        "apps": [
            {
                "id": "{AAAA-1}",
                "hive": "HKLM",
                "name": "Existing App",
                "version": "1.0",
                "publisher": "Foo Corp",
                "path": None,
                "installed_at": "2026-01-01",
                "source": "msi",
            }
        ],
    }

    def fake_persistence_collect():
        return list(state["persistence"]), []

    def fake_apps_collect():
        return list(state["apps"]), []

    monkeypatch.setattr(persistence, "collect", fake_persistence_collect)
    monkeypatch.setattr(apps, "collect", fake_apps_collect)
    return state


def test_uc2_end_to_end(db, tmp_path: Path, fake_registry):
    walk = tmp_path / "walk"
    walk.mkdir()

    device = Device(name="pc", platform="windows", identifier="localhost")
    insert_device(db, device)
    assert device.id is not None

    # --- baseline ---
    baseline_result = take_snapshot(
        db, device, kind="baseline", file_walk_paths=(str(walk),)
    )
    assert baseline_result.events == []
    assert baseline_result.prior_snapshot_id is None

    # --- plant changes ---
    (walk / "bar.exe").write_bytes(b"MZ" + b"\x00" * 200)  # new file
    fake_registry["persistence"].append(
        {
            "location": "runkey",
            "hive": "HKCU",
            "key": r"Software\Microsoft\Windows\CurrentVersion\Run",
            "name": "Bar",
            "value": str(walk / "bar.exe"),
            "target": str(walk / "bar.exe"),
            "args": [],
            "enabled": True,
        }
    )
    fake_registry["apps"].append(
        {
            "id": "{BBBB-2}",
            "hive": "HKLM",
            "name": "Newly Installed App",
            "version": "2.5",
            "publisher": "Bar Corp",
            "path": None,
            "installed_at": "2026-07-05",
            "source": "exe",
        }
    )

    # --- scan ---
    scan_result = take_snapshot(
        db, device, kind="scan", file_walk_paths=(str(walk),)
    )
    assert scan_result.prior_snapshot_id == baseline_result.snapshot.id

    triples = sorted((e.category, e.action, e.subject_key) for e in scan_result.events)
    assert ("file", "added", f"file:{str(walk / 'bar.exe').lower()}") in triples
    assert ("application", "added", "pkg:{BBBB-2}") in triples
    assert any(
        cat == "persistence" and action == "added" and key.endswith("run\\bar")
        for cat, action, key in triples
    )

    # Chain still verifies after event insertion.
    report = verify_chain(db)
    assert report.ok, report.error
    assert report.events_checked == len(scan_result.events)


def test_baseline_writes_hash_cache(db, tmp_path: Path, fake_registry):
    walk = tmp_path / "walk"
    walk.mkdir()
    (walk / "a.bin").write_bytes(b"payload")

    device = Device(name="pc", platform="windows", identifier="localhost")
    insert_device(db, device)
    assert device.id is not None

    take_snapshot(db, device, kind="baseline", file_walk_paths=(str(walk),))
    rows = db.execute("SELECT * FROM file_hash_cache WHERE device_id = ?", (device.id,)).fetchall()
    assert len(rows) == 1
    assert rows[0]["sha256"]
