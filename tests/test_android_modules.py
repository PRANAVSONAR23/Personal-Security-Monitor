"""Android parsers and modules.

The dumpsys fixture mirrors the exact format read off a POCO M2 Pro
(SDK 31 / MIUI 14) — indentation, the `User <n>:` split, the trailing
`Hidden system packages:` section — with synthetic package names.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from psm.collectors.android.modules import packages, storage
from psm.collectors.android.parsers import pm_list
from psm.collectors.android.parsers.dumpsys_packages import parse

FIXTURE = Path(__file__).parent / "fixtures" / "android_31" / "dumpsys_packages.txt"
DUMP = FIXTURE.read_text()


def _shell(responses: dict[str, tuple[int, str, str]]):
    def run(cmd: str) -> tuple[int, str, str]:
        for key, value in responses.items():
            if cmd.startswith(key):
                return value
        return (1, "", f"unexpected command: {cmd}")

    return run


# ---------- parser ----------


def test_parses_every_package_in_the_main_section():
    pkgs = parse(DUMP)
    assert [p.pkg for p in pkgs] == [
        "com.example.store",
        "com.example.oem",
        "com.example.preinstalled",
    ]


def test_hidden_system_packages_are_excluded():
    """The hidden section holds the shadowed original of each updated system app.
    Including it double-counts them and resurrects stale versions."""
    pkgs = parse(DUMP)
    preinstalled = [p for p in pkgs if p.pkg == "com.example.preinstalled"]
    assert len(preinstalled) == 1
    assert preinstalled[0].version_name == "3.3", "must be the live version, not the shadow"


def test_extracts_metadata():
    p = next(p for p in parse(DUMP) if p.pkg == "com.example.store")
    assert p.version_name == "26.38.6"
    assert p.version_code == 2638006
    assert p.user_id == 10074
    assert p.installer == "com.android.vending"
    assert p.signing_version == 3
    assert p.code_path == "/data/app/~~AAAA==/com.example.store-BBBB=="
    assert p.first_install_time == "2020-11-27 14:33:42"
    assert "HAS_CODE" in p.flags


def test_version_code_line_carries_extra_fields():
    """The line is "versionCode=N minSdk=X targetSdk=Y" — only N is the version."""
    p = next(p for p in parse(DUMP) if p.pkg == "com.example.oem")
    assert p.version_code == 1


def test_epoch_zero_install_time_is_none():
    """System apps report 1970-01-01, which is 'unknown', not a real date."""
    p = next(p for p in parse(DUMP) if p.pkg == "com.example.oem")
    assert p.first_install_time is None
    assert p.last_update_time is None


def test_runtime_permissions_come_from_the_requested_user_only():
    """User 0 and User 999 both have a CAMERA row with opposite grants; mixing
    them would report a phantom permission change."""
    p = next(p for p in parse(DUMP, user=0) if p.pkg == "com.example.store")
    cam = [r for r in p.runtime_permissions if r.permission.endswith("CAMERA")]
    assert len(cam) == 1
    assert cam[0].granted is True
    assert "USER_SET" in cam[0].flags

    p999 = next(p for p in parse(DUMP, user=999) if p.pkg == "com.example.store")
    cam999 = [r for r in p999.runtime_permissions if r.permission.endswith("CAMERA")]
    assert cam999[0].granted is False


def test_install_permissions_kept_separate_from_runtime():
    p = next(p for p in parse(DUMP) if p.pkg == "com.example.store")
    assert {r.permission for r in p.install_permissions} == {
        "android.permission.INTERNET",
        "android.permission.WAKE_LOCK",
    }
    assert all("INTERNET" not in r.permission for r in p.runtime_permissions)


def test_component_lists_do_not_leak_into_permissions():
    """`disabledComponents:` follows the permission block at the same depth."""
    p = next(p for p in parse(DUMP) if p.pkg == "com.example.store")
    assert all("SomeReceiver" not in r.permission for r in p.runtime_permissions)


def test_empty_input_yields_nothing_rather_than_raising():
    assert parse("") == []
    assert parse("Packages:\n") == []


# ---------- installer classification ----------


@pytest.mark.parametrize(
    ("installer", "expected"),
    [
        ("com.android.vending", "store"),
        ("com.xiaomi.discover", "oem"),
        ("com.facebook.system", "oem"),
        ("com.android.shell", "sideload"),
        (None, "preinstalled"),
    ],
)
def test_installer_classification(installer, expected):
    """OEM channels accounted for 40 packages on the test device; unmapped they
    fell into `unknown`, which the sideload rule used to alert on."""
    assert pm_list.classify_installer(installer) == expected


# ---------- packages module ----------


def test_module_emits_both_categories_from_one_call():
    calls: list[str] = []

    def shell(cmd: str) -> tuple[int, str, str]:
        calls.append(cmd)
        if cmd.startswith("pm list packages"):
            return (
                0,
                "package:com.example.store\npackage:com.example.oem\n"
                "package:com.example.preinstalled\n",
                "",
            )
        return (0, DUMP, "")

    apps, perms = packages.collect(shell, sensitive_only=False)
    assert apps.ok and perms.ok
    assert len(apps.entries) == 3
    assert any(c.startswith("dumpsys package packages") for c in calls)
    # One dumpsys call total, not one per package — v1 issued two per package.
    assert sum(c.startswith("dumpsys") for c in calls) == 1


def test_truncated_dump_is_rejected_even_with_exit_code_zero():
    """adb-over-TLS has returned a short dump with rc=0: one observed run gave
    295 of 373 packages and parsed cleanly. Storing that as complete would make
    every later scan report the missing 78 as newly installed."""

    def shell(cmd: str) -> tuple[int, str, str]:
        if cmd.startswith("pm list packages"):
            return (
                0,
                "package:com.example.store\npackage:com.example.oem\n"
                "package:com.example.preinstalled\npackage:com.example.missing\n",
                "",
            )
        return (0, DUMP, "")

    apps, perms = packages.collect(shell)
    assert apps.ok is False
    assert perms.ok is False
    assert any(g.reason == "dumpsys-truncated" for g in apps.gaps)
    assert "com.example.missing" in apps.gaps[-1].detail


def test_dumpsys_failure_fails_both_categories():
    shell = _shell({"pm list packages": (0, "", ""), "dumpsys": (1, "", "boom")})
    apps, perms = packages.collect(shell)
    assert not apps.ok and not perms.ok


def test_sensitive_filter_keeps_only_security_relevant_permissions():
    def shell(cmd: str) -> tuple[int, str, str]:
        if cmd.startswith("pm list packages"):
            return (
                0,
                "package:com.example.store\npackage:com.example.oem\n"
                "package:com.example.preinstalled\n",
                "",
            )
        return (0, DUMP, "")

    _, perms = packages.collect(shell, sensitive_only=True)
    names = {e["permission"] for e in perms.entries}
    assert "android.permission.CAMERA" in names
    assert "android.permission.INTERNET" not in names


# ---------- storage module ----------

STAT_OUT = (
    "36|1762000000|/sdcard/Download/payload.apk\n"
    "1024|1762000001|/sdcard/Download/a file with spaces.pdf\n"
    "999999999|1762000002|/sdcard/Download/huge.iso\n"
)
SHA_OUT = (
    "a" * 64
    + "  /sdcard/Download/payload.apk\n"
    + "b" * 64
    + "  /sdcard/Download/a file with spaces.pdf\n"
)


def test_storage_joins_metadata_with_digests():
    def two_pass(cmd: str) -> tuple[int, str, str]:
        return (0, STAT_OUT, "") if "stat -c" in cmd else (0, SHA_OUT, "")

    result = storage.collect(two_pass)
    by_path = {e["path"]: e for e in result.entries}
    assert by_path["/sdcard/Download/payload.apk"]["sha256"] == "a" * 64
    assert by_path["/sdcard/Download/a file with spaces.pdf"]["size"] == 1024
    assert result.ok


def test_storage_flags_installable_extensions():
    def two_pass(cmd: str) -> tuple[int, str, str]:
        return (0, STAT_OUT, "") if "stat -c" in cmd else (0, SHA_OUT, "")

    by_path = {e["path"]: e for e in storage.collect(two_pass).entries}
    assert by_path["/sdcard/Download/payload.apk"]["installable"] is True
    assert by_path["/sdcard/Download/a file with spaces.pdf"]["installable"] is False


def test_storage_records_oversize_file_rather_than_dropping_it():
    """A file past the digest size cap appears in stat but not sha256sum."""

    def two_pass(cmd: str) -> tuple[int, str, str]:
        return (0, STAT_OUT, "") if "stat -c" in cmd else (0, SHA_OUT, "")

    by_path = {e["path"]: e for e in storage.collect(two_pass).entries}
    huge = by_path["/sdcard/Download/huge.iso"]
    assert huge["sha256"] is None
    assert huge["skipped"] == "size-or-unreadable"


def test_storage_failure_is_not_an_empty_result():
    result = storage.collect(_shell({"find": (1, "", "permission denied")}))
    assert result.ok is False
    assert result.entries == []


# ---------- source classification ----------


@pytest.mark.parametrize(
    ("installer", "code_path", "flags", "expected"),
    [
        ("com.android.vending", "/data/app/~~x==/com.a-y==", (), "store"),
        ("com.xiaomi.discover", "/data/app/~~x==/com.a-y==", (), "oem"),
        ("com.android.shell", "/data/app/~~x==/com.a-y==", (), "sideload"),
        # The case that mattered: `adb install` records no installer. Classifying
        # on the installer alone labelled a sideloaded, debuggable app on the test
        # device "preinstalled" — the most benign label, for its riskiest package.
        (None, "/data/app/~~x==/com.a-y==", ("HAS_CODE", "DEBUGGABLE"), "sideload"),
        (None, "/system/app/Foo", ("SYSTEM", "HAS_CODE"), "preinstalled"),
        # A system app updated through Play is still part of the OS image.
        ("com.android.vending", "/system/app/Foo", ("SYSTEM",), "preinstalled"),
    ],
)
def test_source_classification_uses_path_and_flags(installer, code_path, flags, expected):
    assert pm_list.classify_source(installer, code_path, flags) == expected
