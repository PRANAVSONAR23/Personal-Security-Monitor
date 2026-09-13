"""Phase 5 exit check.

Between baseline and scan, a broad-permission extension appears in Chrome. The
`browser added` event surfaces, the `new-browser-extension-all-urls` rule fires,
and the daily report / timeline JSONL export produce the expected shape.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from psm.collectors.windows.collector import WindowsConfig
from psm.collectors.windows.modules import apps, browser, persistence
from psm.core.models import Device
from psm.core.orchestrator import take_snapshot
from psm.report import daily as daily_report
from psm.report.timeline import export_jsonl, iso_ago, parse_last
from psm.store.queries import (
    insert_device,
    load_alerts,
    load_timeline,
)

FIXTURES = Path(__file__).parent / "fixtures" / "windows"


@pytest.fixture()
def empty_registry(monkeypatch):
    monkeypatch.setattr(persistence, "collect", lambda: ([], []))
    monkeypatch.setattr(apps, "collect", lambda: ([], []))


def _windows_config(user_data_root: Path) -> WindowsConfig:
    """Restrict the Windows collector to the browser module and a fixture profile."""
    return WindowsConfig(
        browser=browser.BrowserConfig(chrome_user_data=(str(user_data_root),)),
    )


def test_uc_phase5_browser_extension_end_to_end(db, empty_registry):
    device = Device(name="pc", platform="windows", identifier="localhost")
    insert_device(db, device)

    # Baseline: only a legit extension present.
    take_snapshot(
        db, device, kind="baseline",
        modules={"browser"},
        windows_config=_windows_config(FIXTURES / "chrome_userdata"),
    )

    # Scan: broad-permission extension appears.
    scan = take_snapshot(
        db, device, kind="scan",
        modules={"browser"},
        windows_config=_windows_config(FIXTURES / "chrome_userdata_broad"),
    )

    # A single browser-added event for the new extension.
    browser_events = [e for e in scan.events if e.category == "browser"]
    assert len(browser_events) == 1
    assert browser_events[0].action == "added"
    assert browser_events[0].subject_key == (
        "ext:chrome:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    )

    # Alert fires from the built-in rule.
    rule_ids = {a.rule_id for a in scan.alerts}
    assert "new-browser-extension-all-urls" in rule_ids


def test_timeline_jsonl_export_round_trip(db, tmp_path: Path, empty_registry):
    device = Device(name="pc", platform="windows", identifier="localhost")
    insert_device(db, device)

    take_snapshot(
        db, device, kind="baseline", modules={"browser"},
        windows_config=_windows_config(FIXTURES / "chrome_userdata"),
    )
    take_snapshot(
        db, device, kind="scan", modules={"browser"},
        windows_config=_windows_config(FIXTURES / "chrome_userdata_broad"),
    )

    rows = load_timeline(db)
    assert rows

    out = tmp_path / "events.jsonl"
    n = export_jsonl(rows, out)
    assert n == len(rows)
    entries = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
    first = entries[0]
    assert "message" in first
    assert "timestamp" in first
    assert first["data_type"].startswith("psm:event:")


def test_daily_report_writes_markdown(db, tmp_path: Path, empty_registry):
    device = Device(name="pc", platform="windows", identifier="localhost")
    insert_device(db, device)

    take_snapshot(
        db, device, kind="baseline", modules={"browser"},
        windows_config=_windows_config(FIXTURES / "chrome_userdata"),
    )
    take_snapshot(
        db, device, kind="scan", modules={"browser"},
        windows_config=_windows_config(FIXTURES / "chrome_userdata_broad"),
    )

    since = iso_ago(parse_last("24h"))
    events = load_timeline(db, since_iso=since)
    alerts = load_alerts(db, status="open")
    dest = daily_report.write(tmp_path, events, alerts, window=parse_last("24h"))
    assert dest.exists()
    text = dest.read_text(encoding="utf-8")
    assert "psm daily report" in text
    assert "browser" in text  # the new event category shows up in the counts table
