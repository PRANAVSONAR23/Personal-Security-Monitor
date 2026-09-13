"""Phase 3 exit check.

Between baseline and scan, plant a sideloaded APK and grant an accessibility service
to it. Expect both events to surface, the two Android alert rules to fire, and the
chain to still verify.

The ADB layer is replaced with an in-memory `fake_shell` that answers the shell
commands the collector issues. No adb.exe is touched.
"""

from __future__ import annotations

import pytest

from psm.collectors.android.collector import AndroidConfig
from psm.core.chain import verify_chain
from psm.core.models import Device
from psm.core.orchestrator import take_snapshot
from psm.store.queries import insert_device, load_alerts


class FakeShell:
    """Simple lookup table keyed by exact command string, with a fallback to (0, "", "")."""

    def __init__(self, table: dict[str, tuple[int, str, str]]) -> None:
        self.table = table

    def __call__(self, cmd: str) -> tuple[int, str, str]:
        return self.table.get(cmd, (0, "", ""))


BASELINE_PM_LIST = (
    "package:/system/app/GoogleContacts/GoogleContacts.apk="
    "com.google.android.contacts installer=com.android.vending versionCode:1000\n"
)


BASELINE_DUMPSYS_CONTACTS = """\
Packages:
  Package [com.google.android.contacts] (a1b2):
    appId=10100
    versionName=4.5.6
    firstInstallTime=2026-01-01 00:00:00
    lastUpdateTime=2026-01-01 00:00:00
    installerPackageName=com.android.vending
    User 0:
      runtime permissions:
        android.permission.READ_CONTACTS: granted=true, flags=[ USER_SET ]
"""


SIDELOAD_PM_LIST = (
    "package:/system/app/GoogleContacts/GoogleContacts.apk="
    "com.google.android.contacts installer=com.android.vending versionCode:1000\n"
    "package:/data/app/~~xx==/com.evil.sideload-1/base.apk="
    "com.evil.sideload installer=com.android.shell versionCode:1\n"
)


SIDELOAD_DUMPSYS = """\
Packages:
  Package [com.evil.sideload] (dead):
    appId=10555
    versionName=1.0.0
    firstInstallTime=2026-07-05 08:00:00
    lastUpdateTime=2026-07-05 08:00:00
    installerPackageName=com.android.shell
    User 0:
      runtime permissions:
        android.permission.CAMERA: granted=true, flags=[ USER_SET ]
"""


@pytest.fixture()
def device(db):
    d = Device(name="phone", platform="android", identifier="fakeserial")
    insert_device(db, d)
    return d


def test_uc_phase3_end_to_end(db, device):
    baseline_table = {
        "getprop ro.build.version.sdk": (0, "34\n", ""),
        "pm list packages -f -i --show-versioncode": (0, BASELINE_PM_LIST, ""),
        "dumpsys package com.google.android.contacts": (0, BASELINE_DUMPSYS_CONTACTS, ""),
        "settings get secure enabled_accessibility_services": (0, "null\n", ""),
        "dpm list-owners": (0, "No device policy owners.\n", ""),
    }
    base_result = take_snapshot(
        db,
        device,
        kind="baseline",
        android_config=AndroidConfig(shell_fn=FakeShell(baseline_table)),
    )
    assert base_result.events == []
    assert base_result.alerts == []

    # --- plant a sideloaded APK + accessibility grant ---
    scan_table = {
        "getprop ro.build.version.sdk": (0, "34\n", ""),
        "pm list packages -f -i --show-versioncode": (0, SIDELOAD_PM_LIST, ""),
        "dumpsys package com.google.android.contacts": (0, BASELINE_DUMPSYS_CONTACTS, ""),
        "dumpsys package com.evil.sideload": (0, SIDELOAD_DUMPSYS, ""),
        "settings get secure enabled_accessibility_services": (
            0,
            "com.evil.sideload/.EvilA11yService\n",
            "",
        ),
        "dpm list-owners": (0, "No device policy owners.\n", ""),
    }
    scan_result = take_snapshot(
        db,
        device,
        kind="scan",
        android_config=AndroidConfig(shell_fn=FakeShell(scan_table)),
    )

    subjects = {(e.category, e.subject_key) for e in scan_result.events}
    assert ("application", "pkg:com.evil.sideload") in subjects
    assert (
        "permission",
        "perm:com.evil.sideload:special:accessibility",
    ) in subjects
    assert (
        "permission",
        "perm:com.evil.sideload:android.permission.CAMERA",
    ) in subjects

    rule_ids = {a.rule_id for a in scan_result.alerts}
    assert "sideloaded-install" in rule_ids
    assert "new-accessibility-grant" in rule_ids

    # Chain still verifies after severity-upgraded events land.
    report = verify_chain(db)
    assert report.ok
    assert report.events_checked == len(scan_result.events)

    open_alerts = load_alerts(db, status="open")
    assert len(open_alerts) == len(scan_result.alerts)
