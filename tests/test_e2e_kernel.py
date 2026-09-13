"""End-to-end coverage of the ported kernel, driven by a fake collector.

v1 exercised all of this through the Windows registry collector. That vehicle is
gone, but rules, alerts, severity, known-good suppression, the timeline and the
daily report are all ported code and must stay covered. The fake collector keeps
the tests about the kernel rather than about any one platform's quirks.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from psm.collectors.base import Collector, Normalizer, RawBundle
from psm.core.chain import verify_chain
from psm.core.models import Device, InventoryItem
from psm.core.orchestrator import register, take_snapshot
from psm.core.rules import load_rules_from_dir
from psm.enrich import known_good
from psm.report import daily as daily_report
from psm.report.timeline import export_jsonl, parse_last
from psm.store.queries import insert_device, load_alerts, load_timeline

RULES = Path(__file__).resolve().parents[1] / "src" / "psm" / "rules" / "builtin"


class _Fake(Collector):
    platform = "macos"
    ALL_MODULES = ("application", "persistence", "file", "browser")

    def __init__(self, payloads):
        self.payloads = payloads

    def satisfied_tiers(self, device):
        return {"base"}

    def capabilities(self, device):
        return set(self.ALL_MODULES)

    def collect(self, device, modules, timeout_s=300):
        b = RawBundle(device=device)
        for cat in self.ALL_MODULES:
            if cat in self.payloads:
                b.record(cat, self.payloads[cat])
        return b


class _Norm(Normalizer):
    def normalize(self, bundle):
        return [
            InventoryItem(
                category=c,
                subject_key=e["_key"],
                payload={k: v for k, v in e.items() if k != "_key"},
            )
            for c, entries in bundle.raw.items()
            for e in entries
        ]


@pytest.fixture()
def fake(monkeypatch):
    holder = {"payloads": {}}
    register("macos", lambda **kw: (_Fake(holder["payloads"]), _Norm()))
    return holder


def _device(db, name="mac"):
    d = Device(name=name, platform="macos", identifier="local")
    insert_device(db, d)
    return d


UNSIGNED_EXE = {
    "_key": "file:/Users/x/Library/bar",
    "path": "/Users/x/Library/bar",
    "sha256": "a" * 64,
    "executable": True,
    "signature_status": "unsigned",
}
LAUNCH_AGENT = {
    "_key": "persist:macos:launchagent:com.bar",
    "location": "launchagent",
    "name": "com.bar",
    "target": "/Users/x/Library/bar",
    "enabled": True,
}


def test_correlated_alert_persistence_plus_new_file(db, fake):
    """A new LaunchAgent pointing at a file created in the same scan is the
    flagship correlation rule."""
    d = _device(db)
    fake["payloads"] = {"file": [], "persistence": []}
    take_snapshot(db, d, kind="baseline")

    fake["payloads"] = {"file": [UNSIGNED_EXE], "persistence": [LAUNCH_AGENT]}
    result = take_snapshot(db, d, kind="scan", rules=load_rules_from_dir(RULES))

    rule_ids = {a.rule_id for a in result.alerts}
    assert "persistence-plus-new-file" in rule_ids
    assert verify_chain(db).ok


def test_correlate_join_survives_macos_path_casing(db, fake):
    """F6 in situ: the join runs through the device's own normalization, so a
    LaunchAgent target and the file path still match on case-insensitive APFS."""
    d = _device(db)
    fake["payloads"] = {"file": [], "persistence": []}
    take_snapshot(db, d, kind="baseline")

    shouty = dict(LAUNCH_AGENT, target="/Users/X/Library/BAR")
    fake["payloads"] = {"file": [UNSIGNED_EXE], "persistence": [shouty]}
    result = take_snapshot(db, d, kind="scan", rules=load_rules_from_dir(RULES))
    assert "persistence-plus-new-file" in {a.rule_id for a in result.alerts}


def test_severity_bump_without_alert(db, fake):
    """Non-alert rules raise severity but must not create alert rows."""
    d = _device(db)
    fake["payloads"] = {"application": []}
    take_snapshot(db, d, kind="baseline")

    fake["payloads"] = {"application": [{"_key": "pkg:com.new", "id": "com.new"}]}
    result = take_snapshot(db, d, kind="scan", rules=load_rules_from_dir(RULES))

    assert [e.severity for e in result.events] == ["notice"]
    assert result.alerts == []


def test_known_good_suppresses_alert_but_keeps_event(db, fake):
    d = _device(db)
    fake["payloads"] = {"file": []}
    take_snapshot(db, d, kind="baseline")

    known_good.import_entries(
        db, [known_good.KnownGoodEntry(sha256="a" * 64, source="test", label="allowed")]
    )
    fake["payloads"] = {"file": [UNSIGNED_EXE]}
    result = take_snapshot(
        db, d, kind="scan", rules=load_rules_from_dir(RULES), suppress_known_good=True
    )

    assert len(result.events) == 1, "the event still surfaces"
    assert result.alerts == [], "the alert is what gets suppressed"


def test_known_good_not_imported_still_alerts(db, fake):
    d = _device(db)
    fake["payloads"] = {"file": []}
    take_snapshot(db, d, kind="baseline")

    fake["payloads"] = {"file": [UNSIGNED_EXE]}
    result = take_snapshot(
        db, d, kind="scan", rules=load_rules_from_dir(RULES), suppress_known_good=True
    )
    assert "unsigned-binary-user-path" in {a.rule_id for a in result.alerts}


def test_browser_extension_all_urls_alerts(db, fake):
    d = _device(db)
    fake["payloads"] = {"browser": []}
    take_snapshot(db, d, kind="baseline")

    fake["payloads"] = {
        "browser": [
            {
                "_key": "ext:chrome:abc",
                "browser": "chrome",
                "id": "abc",
                "name": "Broad Ext",
                "permissions": ["tabs", "<all_urls>"],
            }
        ]
    }
    result = take_snapshot(db, d, kind="scan", rules=load_rules_from_dir(RULES))
    assert "new-browser-extension-all-urls" in {a.rule_id for a in result.alerts}


def test_timeline_and_jsonl_export_round_trip(db, fake, tmp_path: Path):
    d = _device(db)
    fake["payloads"] = {"application": []}
    take_snapshot(db, d, kind="baseline")
    fake["payloads"] = {"application": [{"_key": "pkg:com.new", "id": "com.new"}]}
    take_snapshot(db, d, kind="scan", rules=load_rules_from_dir(RULES))

    rows = load_timeline(db, device_id=d.id)
    assert len(rows) == 1
    assert rows[0]["source"] == "inventory"

    out = tmp_path / "events.jsonl"
    assert export_jsonl(rows, out) == 1
    record = json.loads(out.read_text().splitlines()[0])
    assert record["message"]
    assert record["datetime"]


def test_daily_report_renders(db, fake, tmp_path: Path):
    d = _device(db)
    fake["payloads"] = {"file": []}
    take_snapshot(db, d, kind="baseline")
    fake["payloads"] = {"file": [UNSIGNED_EXE]}
    take_snapshot(db, d, kind="scan", rules=load_rules_from_dir(RULES))

    rows = load_timeline(db)
    dest = daily_report.write(
        tmp_path, rows, load_alerts(db, status="open"), window=parse_last("24h")
    )
    assert dest.exists()
    assert "file" in dest.read_text()
