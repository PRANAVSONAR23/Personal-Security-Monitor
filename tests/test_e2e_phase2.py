"""Phase 2 exit check.

Plant an unsigned exe in a user-writable location + a Run-key entry pointing at it in
the same scan. Expect the persistence-plus-new-file correlate rule to fire (one alert),
the unsigned-binary rule to also fire (a second alert), and `psm explain` on the
persistence event to produce a Run-key-specific template.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from psm.collectors.windows.modules import apps, persistence
from psm.core.chain import verify_chain
from psm.core.models import Device
from psm.core.orchestrator import take_snapshot
from psm.report.explain import render as render_explain
from psm.store.queries import (
    insert_device,
    load_alerts,
    load_event,
    load_item_payload,
)


@pytest.fixture()
def empty_registry(monkeypatch):
    state = {"persistence": [], "apps": []}
    monkeypatch.setattr(persistence, "collect", lambda: (list(state["persistence"]), []))
    monkeypatch.setattr(apps, "collect", lambda: (list(state["apps"]), []))
    return state


def test_uc_phase2_end_to_end(db, tmp_path: Path, empty_registry):
    walk = tmp_path / "Users" / "test" / "AppData" / "Roaming"
    walk.mkdir(parents=True)

    device = Device(name="pc", platform="windows", identifier="localhost")
    insert_device(db, device)
    assert device.id is not None

    # --- baseline: nothing planted ---
    baseline = take_snapshot(
        db, device, kind="baseline", file_walk_paths=(str(walk),)
    )
    assert baseline.events == []
    assert baseline.alerts == []

    # --- plant the payload ---
    payload_path = walk / "bar.exe"
    payload_path.write_bytes(b"MZ" + b"\x00" * 200)  # extension → executable=True

    empty_registry["persistence"].append(
        {
            "location": "runkey",
            "hive": "HKCU",
            "key": r"Software\Microsoft\Windows\CurrentVersion\Run",
            "name": "Bar",
            "value": str(payload_path),
            "target": str(payload_path),
            "args": [],
            "enabled": True,
        }
    )

    # --- scan ---
    scan = take_snapshot(
        db, device, kind="scan", file_walk_paths=(str(walk),)
    )

    # Two categories added: persistence + file.
    triples = sorted((e.category, e.action) for e in scan.events)
    assert triples.count(("file", "added")) == 1
    assert triples.count(("persistence", "added")) == 1

    alert_rule_ids = {a.rule_id for a in scan.alerts}
    # We expect the correlate rule (path match) and the unsigned-binary rule (user path).
    assert "persistence-plus-new-file" in alert_rule_ids
    assert "unsigned-binary-user-path" in alert_rule_ids
    # HKCU persistence rule is severity=warning, not an alert → not in alerts list.
    assert "new-hkcu-persistence" not in alert_rule_ids

    # Contributing events are actually stored under both alert_events rows.
    contributing_ids: set[int] = set()
    for a in scan.alerts:
        for ev_id in a.detail.get("events", []):
            contributing_ids.add(ev_id)
        # The alert must reference at least one persisted event.
        for ev_id in a.detail.get("events", []):
            assert load_event(db, ev_id) is not None
    assert contributing_ids

    # Chain still verifies including the severity-upgraded events.
    report = verify_chain(db)
    assert report.ok
    assert report.events_checked == len(scan.events)

    # `psm explain` on the persistence event renders the runkey-specific template.
    persist_event = next(e for e in scan.events if e.category == "persistence")
    payload = load_item_payload(db, persist_event.after_hash or "") or {}
    text = render_explain(persist_event.category, persist_event.action, payload)
    assert "Run key" in text
    assert "Bar" in text  # the name slot filled

    # `psm alerts` sees them as open by default.
    open_alerts = load_alerts(db, status="open")
    assert len(open_alerts) == len(scan.alerts)


def test_hkcu_persistence_rule_bumps_severity_but_does_not_alert(
    db, tmp_path: Path, empty_registry
):
    walk = tmp_path / "walk"
    walk.mkdir()

    device = Device(name="pc", platform="windows", identifier="localhost")
    insert_device(db, device)
    assert device.id is not None

    take_snapshot(db, device, kind="baseline", file_walk_paths=(str(walk),))

    # Only a Run-key entry, no file → correlate rule cannot fire, but HKCU rule bumps to warning.
    empty_registry["persistence"].append(
        {
            "location": "runkey",
            "hive": "HKCU",
            "key": r"Software\Microsoft\Windows\CurrentVersion\Run",
            "name": "JustAKey",
            "value": "C:\\legitimate\\thing.exe",
            "target": "C:\\legitimate\\thing.exe",
            "args": [],
            "enabled": True,
        }
    )
    scan = take_snapshot(db, device, kind="scan", file_walk_paths=(str(walk),))

    assert scan.alerts == []
    persist_event = next(e for e in scan.events if e.category == "persistence")
    assert persist_event.severity == "warning"
