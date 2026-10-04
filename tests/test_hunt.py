"""Hunt analyzers and runner.

Analyzers are pure functions of an artifact plus the inventory payload, so these
need no device and no network.
"""

from __future__ import annotations

import pytest

import psm.collectors.registry  # noqa: F401  — registers collectors
from psm.core.models import Artifact, Device, InventoryItem, Snapshot
from psm.hunt import apk, runner
from psm.hunt.base import Analyzer
from psm.store.queries import insert_device, insert_snapshot, load_findings


def _artifact(**kw) -> Artifact:
    base = dict(device_id=1, kind="apk", subject_key="pkg:com.example", id=1)
    base.update(kw)
    return Artifact(**base)  # type: ignore[arg-type]


# ---------- flags ----------


def test_debuggable_is_flagged_high_confidence():
    f = apk.ApkFlagsAnalyzer().analyze(
        _artifact(), {"flags": ["HAS_CODE", "DEBUGGABLE"], "signing_version": 3}
    )
    assert [x.rule_id for x in f] == ["debuggable"]
    assert f[0].confidence == "high"
    assert f[0].verdict == "suspicious"


def test_test_only_is_flagged():
    f = apk.ApkFlagsAnalyzer().analyze(_artifact(), {"flags": ["TEST_ONLY"], "signing_version": 3})
    assert "test-only" in {x.rule_id for x in f}


def test_v1_signing_flagged_for_non_system_only():
    a = apk.ApkFlagsAnalyzer()
    assert "weak-signing-scheme" in {
        x.rule_id for x in a.analyze(_artifact(), {"flags": [], "signing_version": 1})
    }
    # A v1-signed system app is an OS artefact, not a user-facing risk.
    assert "weak-signing-scheme" not in {
        x.rule_id
        for x in a.analyze(_artifact(), {"flags": ["SYSTEM"], "signing_version": 1, "system": True})
    }


def test_clean_release_build_yields_nothing():
    assert (
        apk.ApkFlagsAnalyzer().analyze(
            _artifact(), {"flags": ["HAS_CODE", "ALLOW_BACKUP"], "signing_version": 3}
        )
        == []
    )


# ---------- source ----------


def test_sideload_is_flagged_but_unknown_is_not():
    a = apk.ApkSourceAnalyzer()
    assert [x.rule_id for x in a.analyze(_artifact(), {"source": "sideload"})] == ["sideloaded"]
    # `unknown` means the installer was unrecognised, not that anything is wrong.
    assert a.analyze(_artifact(), {"source": "unknown"}) == []
    assert a.analyze(_artifact(), {"source": "store"}) == []


# ---------- permissions ----------


def test_accessibility_service_is_high_confidence():
    f = apk.ApkPermissionsAnalyzer().analyze(
        _artifact(), {"granted_permissions": ["special:accessibility"]}
    )
    hit = next(x for x in f if x.rule_id == "accessibility-service")
    assert hit.confidence == "high"


def test_permission_combo_requires_every_member():
    a = apk.ApkPermissionsAnalyzer()
    # INTERNET is an install-time permission and is assumed, so READ_SMS alone
    # completes the sms-exfiltration pair.
    assert "sms-exfiltration" in {
        x.rule_id
        for x in a.analyze(_artifact(), {"granted_permissions": ["android.permission.READ_SMS"]})
    }
    assert "call-and-sms-control" not in {
        x.rule_id
        for x in a.analyze(_artifact(), {"granted_permissions": ["android.permission.READ_SMS"]})
    }


def test_system_apps_get_lower_confidence_on_combos():
    a = apk.ApkPermissionsAnalyzer()
    payload = {"granted_permissions": ["android.permission.RECORD_AUDIO"], "system": True}
    hit = next(x for x in a.analyze(_artifact(), payload) if x.rule_id == "audio-surveillance")
    assert hit.confidence == "low"


def test_no_granted_permissions_yields_nothing():
    assert apk.ApkPermissionsAnalyzer().analyze(_artifact(), {"granted_permissions": []}) == []


# ---------- runner ----------


class _Fake(Analyzer):
    id = "fake"
    version = "1"
    accepts = ("apk",)

    def analyze(self, artifact, payload):
        return [self.finding(artifact, rule_id="always", verdict="suspicious")]


def _seed(db, items):

    d = Device(name="phone", platform="android", identifier="x")
    insert_device(db, d)
    assert d.id is not None
    snap = Snapshot(
        device_id=d.id,
        kind="baseline",
        capabilities={"application", "permission"},
        tool_version="t",
    )
    insert_snapshot(db, snap, items)
    return d


def _app_item(pkg: str, **extra):

    payload = {"id": pkg, "name": pkg, "source": "store", "flags": [], **extra}
    return InventoryItem("application", f"pkg:{pkg}", payload)


def _perm_item(pkg: str, perm: str, granted: bool = True):

    return InventoryItem(
        "permission",
        f"perm:{pkg}:{perm}",
        {"pkg": pkg, "permission": perm, "granted": granted},
    )


def test_runner_attaches_granted_permissions_to_the_apk_payload(db):
    d = _seed(
        db,
        [
            _app_item("com.a"),
            _perm_item("com.a", "special:accessibility"),
            _perm_item("com.a", "android.permission.CAMERA", granted=False),
        ],
    )
    result = runner.run(db, d, analyzers=apk.ANALYZERS)
    rules = {f.rule_id for f in result.findings}
    assert "accessibility-service" in rules


def test_runner_is_idempotent_for_the_same_analyzer_version(db):
    d = _seed(db, [_app_item("com.a", flags=["DEBUGGABLE"])])
    runner.run(db, d, analyzers=(apk.ApkFlagsAnalyzer(),))
    runner.run(db, d, analyzers=(apk.ApkFlagsAnalyzer(),))
    rows = load_findings(db)
    assert len([r for r in rows if r["rule_id"] == "debuggable"]) == 1


def test_bumping_the_analyzer_version_records_a_new_finding(db):
    d = _seed(db, [_app_item("com.a", flags=["DEBUGGABLE"])])
    runner.run(db, d, analyzers=(apk.ApkFlagsAnalyzer(),))

    class V2(apk.ApkFlagsAnalyzer):
        version = "2"

    runner.run(db, d, analyzers=(V2(),))
    versions = {r["analyzer_version"] for r in load_findings(db) if r["rule_id"] == "debuggable"}
    assert versions == {"1", "2"}


def test_installable_file_becomes_an_apk_artifact(db):

    item = InventoryItem(
        "file",
        "file:/sdcard/Download/x.apk",
        {"path": "/sdcard/Download/x.apk", "sha256": "a" * 64, "size": 10, "installable": True},
    )
    d = _seed(db, [item])
    runner.run(db, d, analyzers=(_Fake(),))
    rows = load_findings(db)
    assert rows[0]["kind"] == "apk"
    assert rows[0]["sha256"] == "a" * 64


def test_plain_file_is_not_analyzed_by_apk_analyzers(db):

    item = InventoryItem(
        "file",
        "file:/sdcard/Download/a.pdf",
        {"path": "/sdcard/Download/a.pdf", "sha256": "b" * 64, "installable": False},
    )
    d = _seed(db, [item])
    result = runner.run(db, d, analyzers=apk.ANALYZERS)
    assert result.findings == []
    assert result.artifacts == 1


def test_hunt_without_a_snapshot_is_an_error(db):
    d = Device(name="phone", platform="android", identifier="x")
    insert_device(db, d)
    with pytest.raises(runner.HuntError):
        runner.run(db, d)


def test_promotion_threshold():
    """Only malicious, or high-confidence suspicious, reaches the chained log."""
    a = _artifact()
    flags = apk.ApkFlagsAnalyzer()
    high = flags.analyze(a, {"flags": ["DEBUGGABLE"], "signing_version": 3})[0]
    low = flags.analyze(a, {"flags": [], "signing_version": 1})[0]
    assert runner.promotable(high) is True
    assert runner.promotable(low) is False
