"""Golden-file parser tests for Android modules — SDK 33 and SDK 34 both parse."""

from __future__ import annotations

from pathlib import Path

from psm.collectors.android.parsers import dumpsys_package, pm_list

FIXTURES = Path(__file__).parent / "fixtures"


def test_pm_list_parses_installer_and_versioncode() -> None:
    entries = pm_list.parse((FIXTURES / "android_33" / "pm_list.txt").read_text(encoding="utf-8"))
    by_pkg = {e.pkg: e for e in entries}

    assert by_pkg["com.example.sideload"].installer == "com.android.shell"
    assert by_pkg["com.example.sideload"].version_code == 12
    assert by_pkg["com.example.sideload"].apk_path.endswith("base.apk")

    assert by_pkg["com.google.android.contacts"].installer == "com.android.vending"
    # The line without an installer= suffix must still parse:
    assert by_pkg["com.android.providers.settings"].installer is None
    assert by_pkg["com.android.providers.settings"].version_code == 34


def test_pm_list_classifier_labels_source() -> None:
    assert pm_list.classify_installer("com.android.vending") == "store"
    assert pm_list.classify_installer("com.android.shell") == "sideload"
    assert pm_list.classify_installer(None) == "preinstalled"
    assert pm_list.classify_installer("com.mystery.launcher") == "unknown"


def test_dumpsys_package_sideload_a13() -> None:
    text = (FIXTURES / "android_33" / "dumpsys_package_sideload.txt").read_text(encoding="utf-8")
    parsed = dumpsys_package.parse(text)
    assert parsed is not None
    assert parsed.pkg == "com.example.sideload"
    assert parsed.version_name == "0.1.2"
    assert parsed.app_id == 10234
    assert parsed.first_install_time == "2026-05-01T10:20:30Z"

    perms = {p.permission: p for p in parsed.runtime_permissions}
    assert perms["android.permission.CAMERA"].granted is True
    assert "USER_SET" in perms["android.permission.CAMERA"].flags
    assert perms["android.permission.RECORD_AUDIO"].granted is False


def test_dumpsys_package_store_a14() -> None:
    text = (FIXTURES / "android_34" / "dumpsys_package_store.txt").read_text(encoding="utf-8")
    parsed = dumpsys_package.parse(text)
    assert parsed is not None
    assert parsed.pkg == "org.thirdparty.foo"
    assert parsed.version_name == "3.0.7"

    perms = {p.permission: p for p in parsed.runtime_permissions}
    assert perms["android.permission.POST_NOTIFICATIONS"].granted is True
    assert perms["android.permission.RECORD_AUDIO"].granted is False


def test_dumpsys_package_returns_none_when_missing_header() -> None:
    assert dumpsys_package.parse("nothing to see") is None
