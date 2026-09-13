"""Phase 6 exit checks: enrichment labels known-good files and suppresses alerts."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from psm.collectors.windows.modules import apps, persistence
from psm.core.models import Device
from psm.core.orchestrator import take_snapshot
from psm.enrich import known_good
from psm.enrich.labeler import build_labels
from psm.store.queries import insert_device

PAYLOAD_BYTES = b"MZ" + b"\x00" * 200
PAYLOAD_SHA256 = hashlib.sha256(PAYLOAD_BYTES).hexdigest()


@pytest.fixture()
def empty_registry(monkeypatch):
    monkeypatch.setattr(persistence, "collect", lambda: ([], []))
    monkeypatch.setattr(apps, "collect", lambda: ([], []))


def test_uc_phase6_known_good_suppresses_alerts(db, tmp_path: Path, empty_registry):
    walk = tmp_path / "Users" / "x" / "AppData" / "Roaming"
    walk.mkdir(parents=True)

    device = Device(name="pc", platform="windows", identifier="localhost")
    insert_device(db, device)

    # Baseline: empty walk dir.
    take_snapshot(db, device, kind="baseline", file_walk_paths=(str(walk),))

    # Mark the payload's sha256 as known-good BEFORE the scan.
    known_good.import_entries(
        db,
        [known_good.KnownGoodEntry(sha256=PAYLOAD_SHA256, source="unit-test",
                                   label="test signer")],
    )

    # Plant a file whose sha256 matches the known-good entry.
    (walk / "bar.exe").write_bytes(PAYLOAD_BYTES)

    scan = take_snapshot(
        db, device, kind="scan", file_walk_paths=(str(walk),),
        suppress_known_good=True,
    )

    # The event still surfaces (transparency), but the unsigned-binary alert is suppressed.
    file_events = [e for e in scan.events if e.category == "file"]
    assert len(file_events) == 1
    rule_ids = {a.rule_id for a in scan.alerts}
    assert "unsigned-binary-user-path" not in rule_ids

    # And build_labels tags it as known_good.
    labels = build_labels(db, scan.events)
    file_event = file_events[0]
    assert file_event.id is not None
    assert labels.get(file_event.id) == "known_good"


def test_known_good_not_toggled_still_alerts(db, tmp_path: Path, empty_registry):
    """Sanity: without --enrich known_good, alerts fire normally."""
    walk = tmp_path / "Users" / "x" / "AppData" / "Roaming"
    walk.mkdir(parents=True)
    device = Device(name="pc", platform="windows", identifier="localhost")
    insert_device(db, device)

    take_snapshot(db, device, kind="baseline", file_walk_paths=(str(walk),))
    known_good.import_entries(
        db, [known_good.KnownGoodEntry(sha256=PAYLOAD_SHA256, source="unit-test")]
    )
    (walk / "bar.exe").write_bytes(PAYLOAD_BYTES)

    scan = take_snapshot(
        db, device, kind="scan", file_walk_paths=(str(walk),),
        suppress_known_good=False,
    )
    rule_ids = {a.rule_id for a in scan.alerts}
    assert "unsigned-binary-user-path" in rule_ids


def test_capture_baseline_snapshots_hashes(db, tmp_path: Path, empty_registry):
    walk = tmp_path / "walk"
    walk.mkdir()
    (walk / "a.exe").write_bytes(b"A")

    device = Device(name="pc", platform="windows", identifier="localhost")
    insert_device(db, device)
    take_snapshot(db, device, kind="baseline", file_walk_paths=(str(walk),))

    n = known_good.capture_baseline(db, source="fresh-os")
    assert n >= 1
    a_sha = hashlib.sha256(b"A").hexdigest()
    assert known_good.lookup(db, a_sha) is not None
