"""Regression tests for the six defects found by running psm v1 on real hardware.

Each test fails against the v1 behaviour. They exist so the port cannot faithfully
reproduce the bugs it was supposed to fix. See PLAN.md Phase 0.
"""

from __future__ import annotations

import plistlib
import xml.parsers.expat
from pathlib import Path

import pytest

from psm.collectors.base import Collector, Normalizer, RawBundle
from psm.core.models import Device, InventoryItem
from psm.core.orchestrator import register, take_snapshot
from psm.normalize.paths import norm_path
from psm.store.queries import insert_device


class _FakeCollector(Collector):
    """Returns exactly the categories it is told to, so a 'module failed this run'
    scenario can be simulated without a real device."""

    platform = "macos"
    ALL_MODULES = ("application", "persistence", "permission", "file", "browser")

    def __init__(self, payloads: dict[str, list[dict]], failed: set[str] = frozenset()):
        self.payloads = payloads
        self.failed = failed

    def satisfied_tiers(self, device):
        return {"base"}

    def capabilities(self, device):
        return set(self.ALL_MODULES)

    def collect(self, device, modules, timeout_s=300):
        b = RawBundle(device=device)
        for cat in self.ALL_MODULES:
            if cat in self.failed:
                b.record_gap(cat, "simulated-failure")
            elif cat in self.payloads:
                b.record(cat, self.payloads[cat])
        return b


class _FakeNormalizer(Normalizer):
    def normalize(self, bundle: RawBundle) -> list[InventoryItem]:
        out = []
        for cat, entries in bundle.raw.items():
            for e in entries:
                out.append(InventoryItem(category=cat, subject_key=e["_key"], payload=e))
        return out


def _app(n: int) -> dict:
    return {"_key": f"pkg:com.example.app{n}", "id": f"com.example.app{n}", "name": f"App {n}"}


@pytest.fixture()
def fake_macos(monkeypatch):
    holder: dict = {}

    def factory(**kwargs):
        return _FakeCollector(holder["payloads"], holder.get("failed", set())), _FakeNormalizer()

    register("macos", factory)
    return holder


# ---------- F1 ----------


def test_f1_absent_module_does_not_emit_phantom_removals(db, fake_macos):
    """v1 declared capabilities from a constant instead of deriving them from what
    actually collected. Baselining with 64 apps and then scanning while the apps
    module was absent produced 64 phantom 'application removed' events — the exact
    failure capability negotiation exists to prevent. Reproduced on real data.
    """
    device = Device(name="mac", platform="macos", identifier="local")
    insert_device(db, device)

    fake_macos["payloads"] = {"application": [_app(i) for i in range(64)]}
    fake_macos["failed"] = set()
    base = take_snapshot(db, device, kind="baseline")
    assert base.snapshot.capabilities == {"application"}

    # Next run: the application module fails outright.
    fake_macos["payloads"] = {}
    fake_macos["failed"] = {"application"}
    scan = take_snapshot(db, device, kind="scan")

    assert scan.snapshot.capabilities == set(), "a failed module must not be claimed"
    removed = [e for e in scan.events if e.action == "removed"]
    assert removed == [], f"expected no phantom removals, got {len(removed)}"
    assert any(g.module == "application" for g in scan.snapshot.gaps)


def test_f1_empty_but_successful_module_is_still_collected(db, fake_macos):
    """'nothing there' and 'could not look' are different. A module that ran and
    legitimately found nothing must stay in capabilities, so a later appearance
    diffs as 'added'."""
    device = Device(name="mac2", platform="macos", identifier="local")
    insert_device(db, device)

    fake_macos["payloads"] = {"application": []}
    fake_macos["failed"] = set()
    base = take_snapshot(db, device, kind="baseline")
    assert base.snapshot.capabilities == {"application"}

    fake_macos["payloads"] = {"application": [_app(1)]}
    scan = take_snapshot(db, device, kind="scan")
    assert [e.action for e in scan.events] == ["added"]


def test_f1_real_removal_still_detected(db, fake_macos):
    """The fix must not suppress genuine removals."""
    device = Device(name="mac3", platform="macos", identifier="local")
    insert_device(db, device)

    fake_macos["payloads"] = {"application": [_app(1), _app(2)]}
    fake_macos["failed"] = set()
    take_snapshot(db, device, kind="baseline")

    fake_macos["payloads"] = {"application": [_app(1)]}
    scan = take_snapshot(db, device, kind="scan")
    assert [(e.action, e.subject_key) for e in scan.events] == [("removed", "pkg:com.example.app2")]


# ---------- F2 ----------


def _read_plist_dir(directory: Path) -> tuple[list[dict], list[str]]:
    """The per-item guard shape required by HLD §4: one bad file costs one item.

    v1 guarded at module level and caught only OSError / InvalidFileException, so a
    single system plist raising ExpatError zeroed all 471 launchd entries on a real
    Mac.
    """
    items: list[dict] = []
    errors: list[str] = []
    for path in sorted(directory.iterdir()):
        if not path.name.endswith(".plist"):
            continue
        try:
            with path.open("rb") as f:
                data = plistlib.load(f)
        except Exception as e:
            errors.append(f"{path.name}: {type(e).__name__}")
            continue
        items.append({"name": data.get("Label", path.stem)})
    return items, errors


def test_f2_one_malformed_plist_costs_one_item_not_the_module(tmp_path: Path):
    for i in range(5):
        with (tmp_path / f"good{i}.plist").open("wb") as f:
            plistlib.dump({"Label": f"com.example.good{i}"}, f)
    # Same shape as /System/Library/LaunchAgents/com.apple.familycircled.plist,
    # which raises xml.parsers.expat.ExpatError — NOT an OSError and NOT an
    # InvalidFileException, so v1's except clause missed it entirely.
    (tmp_path / "bad.plist").write_bytes(b"<?xml version='1.0' encoding='UTF-8'\n<plist></plist>")

    items, errors = _read_plist_dir(tmp_path)

    assert len(items) == 5, "the five valid plists must survive one bad sibling"
    assert len(errors) == 1
    assert "ExpatError" in errors[0]


def test_f2_expat_error_is_not_caught_by_v1_except_clause():
    """Pins the reason v1 failed, so nobody 'simplifies' the guard back."""
    assert not issubclass(xml.parsers.expat.ExpatError, OSError)
    assert not issubclass(xml.parsers.expat.ExpatError, plistlib.InvalidFileException)


# ---------- F6 ----------


def test_f6_android_paths_are_not_casefolded():
    assert norm_path("/sdcard/Download/A.apk", "android") != norm_path(
        "/sdcard/download/a.apk", "android"
    )


def test_f6_macos_paths_do_not_gain_windows_separators():
    assert norm_path("/Users/x/Library/LaunchAgents/a.plist", "macos").startswith("/users/")
