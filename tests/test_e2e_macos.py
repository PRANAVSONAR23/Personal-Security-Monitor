"""Phase 4 exit check.

From the controller's perspective, ingest a baseline shim envelope, then ingest a
second envelope where a new user LaunchAgent has appeared. The persistence event
must surface, the chain must still verify, and non-macOS entries must not leak
into the diff (capabilities respected).

Runs entirely on Windows — no SSH, no Mac needed — using MacosConfig.envelope_path
so the collector reads a file instead of piping the shim over SSH.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from psm.collectors.macos.collector import MacosConfig
from psm.core.chain import verify_chain
from psm.core.models import Device
from psm.core.orchestrator import take_snapshot
from psm.store.queries import insert_device

FIXTURES = Path(__file__).parent / "fixtures" / "macos"


@pytest.fixture()
def device(db):
    d = Device(name="mac", platform="macos", identifier="user@macbook.local")
    insert_device(db, d)
    return d


def test_uc_phase4_end_to_end(db, device):
    # Baseline: ingest the fixture envelope, no prior state → no events.
    base = take_snapshot(
        db, device, kind="baseline",
        macos_config=MacosConfig(envelope_path=FIXTURES / "baseline.json"),
    )
    assert base.events == []
    assert base.alerts == []
    assert "persistence" in base.snapshot.capabilities

    # Scan: ingest the scan envelope with a new LaunchAgent → persistence added event.
    scan = take_snapshot(
        db, device, kind="scan",
        macos_config=MacosConfig(envelope_path=FIXTURES / "scan_with_launchagent.json"),
    )

    persist_events = [e for e in scan.events if e.category == "persistence"]
    assert len(persist_events) == 1
    assert persist_events[0].subject_key == "persist:macos:launchagent:com.evil.persistence"
    assert persist_events[0].action == "added"

    # No unexpected removed/changed events from other modules:
    assert all(e.action == "added" for e in scan.events), scan.events

    # Chain verifies after ingest.
    report = verify_chain(db)
    assert report.ok
    assert report.events_checked == len(scan.events)
