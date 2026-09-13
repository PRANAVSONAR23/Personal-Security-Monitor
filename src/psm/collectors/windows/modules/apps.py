"""Apps — installed programs via winreg Uninstall keys.

v1 covers HKLM + HKLM\\WOW6432Node + HKCU Uninstall trees. Appx (Store) apps are Phase 1.5
(PowerShell subprocess to Get-AppxPackage).
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import Any

from psm.core.models import CollectionGap

if sys.platform == "win32":
    import winreg
else:  # pragma: no cover
    winreg = None  # type: ignore[assignment]


@dataclass(slots=True)
class _UninstallLocation:
    hive_name: str
    hive_handle: int
    subkey: str


def _uninstall_locations() -> list[_UninstallLocation]:
    if winreg is None:
        return []
    return [
        _UninstallLocation("HKLM", winreg.HKEY_LOCAL_MACHINE,
                           r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
        _UninstallLocation("HKLM", winreg.HKEY_LOCAL_MACHINE,
                           r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        _UninstallLocation("HKCU", winreg.HKEY_CURRENT_USER,
                           r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]


def _get_value(key: Any, name: str) -> str | int | None:
    try:
        value, _ = winreg.QueryValueEx(key, name)  # type: ignore[union-attr]
    except OSError:
        return None
    if isinstance(value, str | int):
        return value
    return None


def _installed_at_iso(raw: str | int | None) -> str | None:
    if not raw:
        return None
    s = str(raw)
    if len(s) == 8 and s.isdigit():
        return f"{s[0:4]}-{s[4:6]}-{s[6:8]}"
    return None


def _enumerate_uninstall(loc: _UninstallLocation) -> list[dict[str, Any]]:
    assert winreg is not None
    entries: list[dict[str, Any]] = []
    access = winreg.KEY_READ | winreg.KEY_WOW64_64KEY
    try:
        parent = winreg.OpenKey(loc.hive_handle, loc.subkey, 0, access)
    except FileNotFoundError:
        return entries

    with parent:
        i = 0
        while True:
            try:
                child_name = winreg.EnumKey(parent, i)
            except OSError:
                break
            i += 1
            try:
                child = winreg.OpenKey(parent, child_name, 0, access)
            except OSError:
                continue
            with child:
                display_name = _get_value(child, "DisplayName")
                if not isinstance(display_name, str) or not display_name.strip():
                    continue
                system_component = _get_value(child, "SystemComponent")
                if system_component == 1:
                    continue
                if _get_value(child, "ParentKeyName") or _get_value(child, "ParentDisplayName"):
                    continue

                version = _get_value(child, "DisplayVersion")
                publisher = _get_value(child, "Publisher")
                install_location = _get_value(child, "InstallLocation")
                install_date = _installed_at_iso(_get_value(child, "InstallDate"))
                is_msi = _get_value(child, "WindowsInstaller") == 1

                entries.append(
                    {
                        "id": child_name,
                        "hive": loc.hive_name,
                        "name": display_name,
                        "version": str(version) if version is not None else None,
                        "publisher": publisher if isinstance(publisher, str) else None,
                        "path": install_location if isinstance(install_location, str) else None,
                        "installed_at": install_date,
                        "source": "msi" if is_msi else "exe",
                    }
                )
    return entries


def collect() -> tuple[list[dict[str, Any]], list[CollectionGap]]:
    if winreg is None:
        return [], [CollectionGap("apps", "unsupported-platform", "winreg unavailable")]

    entries: list[dict[str, Any]] = []
    gaps: list[CollectionGap] = []
    for loc in _uninstall_locations():
        try:
            entries.extend(_enumerate_uninstall(loc))
        except PermissionError:
            gaps.append(CollectionGap("apps", "access-denied", f"{loc.hive_name}\\{loc.subkey}"))
    return entries, gaps
