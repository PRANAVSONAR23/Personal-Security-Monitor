# ruff: noqa: E501 — dumpsys `User 0:` lines are long in the real format and the
# fixture is only useful verbatim.
"""Android end-to-end: plant a sideloaded APK and grant it an accessibility
service between baseline and scan, expect both events plus both alert rules.

The ADB layer is a lookup table keyed on command prefix — no adb binary, no
device. Command shapes match what the collector actually issues against a
POCO M2 Pro on SDK 31.
"""

from __future__ import annotations

import pytest

import psm.collectors.registry  # noqa: F401  — registers collectors
from psm.collectors.android.collector import AndroidConfig
from psm.core.chain import verify_chain
from psm.core.models import Device
from psm.core.orchestrator import take_snapshot
from psm.store.queries import insert_device, load_alerts

CONTACTS_BLOCK = """\
  Package [com.google.android.contacts] (a1b2):
    userId=10100
    codePath=/system/app/GoogleContacts
    versionCode=1000 minSdk=29 targetSdk=33
    versionName=4.5.6
    apkSigningVersion=3
    flags=[ SYSTEM HAS_CODE ]
    firstInstallTime=2026-01-01 00:00:00
    lastUpdateTime=2026-01-01 00:00:00
    installerPackageName=com.android.vending
    User 0: ceDataInode=1 installed=true hidden=false suspended=false distractionFlags=0 stopped=false notLaunched=false enabled=1 instant=false virtual=false
      runtime permissions:
        android.permission.READ_CONTACTS: granted=true, flags=[ USER_SET]
"""

EVIL_BLOCK = """\
  Package [com.evil.sideload] (c3d4):
    userId=10300
    codePath=/data/app/~~XXXX==/com.evil.sideload-YYYY==
    versionCode=1 minSdk=29 targetSdk=31
    versionName=0.0.1
    apkSigningVersion=1
    flags=[ HAS_CODE ]
    firstInstallTime=2026-06-01 10:00:00
    lastUpdateTime=2026-06-01 10:00:00
    installerPackageName=com.android.shell
    User 0: ceDataInode=2 installed=true hidden=false suspended=false distractionFlags=0 stopped=false notLaunched=false enabled=1 instant=false virtual=false
      runtime permissions:
        android.permission.READ_SMS: granted=true, flags=[ USER_SET]
"""


def _dump(*blocks: str) -> str:
    return "Packages:\n" + "".join(blocks) + "Hidden system packages:\n"


def _roster(*pkgs: str) -> str:
    return "".join(f"package:{p}\n" for p in pkgs)


class FakeShell:
    def __init__(self, dump: str, roster: str, accessibility: str = "null") -> None:
        self.dump = dump
        self.roster = roster
        self.accessibility = accessibility

    def __call__(self, cmd: str) -> tuple[int, str, str]:  # noqa: PLR0911 — command table
        if cmd.startswith("pm list packages"):
            return (0, self.roster, "")
        if cmd.startswith("dumpsys package packages"):
            return (0, self.dump, "")
        if cmd.startswith("settings get secure enabled_accessibility_services"):
            return (0, self.accessibility + "\n", "")
        if cmd.startswith("dpm list-owners"):
            return (0, "No owners set\n", "")
        if cmd.startswith("getprop"):
            return (0, "31\n", "")
        if cmd.startswith("find"):
            return (0, "", "")
        return (0, "", "")


@pytest.fixture()
def phone(db):
    d = Device(name="phone", platform="android", identifier="192.168.1.6:42137")
    insert_device(db, d)
    return d


def _snapshot(db, device, kind, shell):
    return take_snapshot(
        db,
        device,
        kind=kind,
        android_config=AndroidConfig(shell_fn=shell, storage_roots=()),
    )


def test_sideload_plus_accessibility_grant_end_to_end(db, phone):
    baseline_shell = FakeShell(_dump(CONTACTS_BLOCK), _roster("com.google.android.contacts"))
    base = _snapshot(db, phone, "baseline", baseline_shell)
    assert base.snapshot.capabilities == {"application", "permission"}

    scan_shell = FakeShell(
        _dump(CONTACTS_BLOCK, EVIL_BLOCK),
        _roster("com.google.android.contacts", "com.evil.sideload"),
        accessibility="com.evil.sideload/com.evil.sideload.Service",
    )
    scan = _snapshot(db, phone, "scan", scan_shell)

    subjects = {(e.category, e.subject_key) for e in scan.events}
    assert ("application", "pkg:com.evil.sideload") in subjects
    assert ("permission", "perm:com.evil.sideload:special:accessibility") in subjects

    fired = {a.rule_id for a in load_alerts(db)}
    assert "sideloaded-install" in fired
    assert "new-accessibility-grant" in fired
    assert verify_chain(db).ok


def test_store_install_does_not_fire_the_sideload_rule(db, phone):
    """`com.android.vending` is a store channel, not a sideload."""
    store_block = EVIL_BLOCK.replace("com.android.shell", "com.android.vending")
    _snapshot(
        db,
        phone,
        "baseline",
        FakeShell(_dump(CONTACTS_BLOCK), _roster("com.google.android.contacts")),
    )
    _snapshot(
        db,
        phone,
        "scan",
        FakeShell(
            _dump(CONTACTS_BLOCK, store_block),
            _roster("com.google.android.contacts", "com.evil.sideload"),
        ),
    )
    assert "sideloaded-install" not in {a.rule_id for a in load_alerts(db)}


def test_oem_installer_does_not_fire_the_sideload_rule(db, phone):
    """40 packages on the test device install via com.xiaomi.discover. Before the
    installer map covered OEM channels they classified as `unknown`, and the rule
    matched `unknown` — 40 alerts on the first scan."""
    oem_block = EVIL_BLOCK.replace("com.android.shell", "com.xiaomi.discover")
    _snapshot(
        db,
        phone,
        "baseline",
        FakeShell(_dump(CONTACTS_BLOCK), _roster("com.google.android.contacts")),
    )
    _snapshot(
        db,
        phone,
        "scan",
        FakeShell(
            _dump(CONTACTS_BLOCK, oem_block),
            _roster("com.google.android.contacts", "com.evil.sideload"),
        ),
    )
    assert "sideloaded-install" not in {a.rule_id for a in load_alerts(db)}


def test_failed_dumpsys_produces_no_phantom_removals(db, phone):
    """F1 on the Android path: a failed bulk dump must leave both categories out
    of the snapshot, not report every package as uninstalled."""
    _snapshot(
        db,
        phone,
        "baseline",
        FakeShell(_dump(CONTACTS_BLOCK), _roster("com.google.android.contacts")),
    )

    class Broken(FakeShell):
        def __call__(self, cmd: str) -> tuple[int, str, str]:
            if cmd.startswith("dumpsys package packages"):
                return (1, "", "protocol fault")
            return super().__call__(cmd)

    scan = _snapshot(
        db, phone, "scan", Broken(_dump(CONTACTS_BLOCK), _roster("com.google.android.contacts"))
    )
    assert scan.snapshot.capabilities == set()
    assert [e for e in scan.events if e.action == "removed"] == []
