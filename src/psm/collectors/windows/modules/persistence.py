"""Persistence — Windows autoruns via winreg.

v1 covers Run/RunOnce keys under HKCU, HKLM, and HKLM\\WOW6432Node. Elevation extends the
HKLM readings; unelevated runs still yield HKCU. Services / scheduled tasks / WMI subs
are Phase 1.5 (osquery-backed).
"""

from __future__ import annotations

import shlex
import sys
from dataclasses import dataclass
from typing import Any

from psm.collectors.windows.elevation import is_elevated
from psm.core.models import CollectionGap

if sys.platform == "win32":
    import winreg
else:  # pragma: no cover - non-Windows: import guarded so tests import cleanly
    winreg = None  # type: ignore[assignment]


@dataclass(slots=True)
class _RunKeyLocation:
    hive_name: str  # display name used in the payload
    hive_handle: int  # winreg constant
    subkey: str


def _run_key_locations() -> list[_RunKeyLocation]:
    if winreg is None:
        return []
    return [
        _RunKeyLocation("HKCU", winreg.HKEY_CURRENT_USER,
                        r"Software\Microsoft\Windows\CurrentVersion\Run"),
        _RunKeyLocation("HKCU", winreg.HKEY_CURRENT_USER,
                        r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        _RunKeyLocation("HKLM", winreg.HKEY_LOCAL_MACHINE,
                        r"Software\Microsoft\Windows\CurrentVersion\Run"),
        _RunKeyLocation("HKLM", winreg.HKEY_LOCAL_MACHINE,
                        r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        _RunKeyLocation("HKLM", winreg.HKEY_LOCAL_MACHINE,
                        r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
        _RunKeyLocation("HKLM", winreg.HKEY_LOCAL_MACHINE,
                        r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"),
    ]


def _parse_command_line(value: str) -> tuple[str, list[str]]:
    """Split a Run-key value into (target, args). Handles both quoted and unquoted first tokens."""
    value = value.strip()
    if not value:
        return "", []
    try:
        parts = shlex.split(value, posix=False)
    except ValueError:
        return value, []
    if not parts:
        return value, []
    target = parts[0].strip('"')
    args = [p.strip('"') for p in parts[1:]]
    return target, args


def _enumerate_key(loc: _RunKeyLocation) -> list[dict[str, Any]]:
    assert winreg is not None
    entries: list[dict[str, Any]] = []
    access = winreg.KEY_READ | winreg.KEY_WOW64_64KEY
    try:
        with winreg.OpenKey(loc.hive_handle, loc.subkey, 0, access) as key:
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                except OSError:
                    break
                i += 1
                if not isinstance(value, str):
                    continue
                target, args = _parse_command_line(value)
                entries.append(
                    {
                        "location": "runkey",
                        "hive": loc.hive_name,
                        "key": loc.subkey,
                        "name": name,
                        "value": value,
                        "target": target,
                        "args": args,
                        "enabled": True,
                    }
                )
    except FileNotFoundError:
        pass  # key doesn't exist on this system; not a gap
    return entries


def collect() -> tuple[list[dict[str, Any]], list[CollectionGap]]:
    """Return (entries, gaps). Never raises; on Windows or otherwise."""
    if winreg is None:
        return [], [CollectionGap("persistence", "unsupported-platform", "winreg unavailable")]

    entries: list[dict[str, Any]] = []
    gaps: list[CollectionGap] = []
    elevated = is_elevated()

    for loc in _run_key_locations():
        if loc.hive_name == "HKLM" and not elevated:
            # Try anyway — HKLM Run is world-readable in practice — but note the gap so a
            # partial read is never silent.
            pass
        try:
            entries.extend(_enumerate_key(loc))
        except PermissionError:
            gaps.append(
                CollectionGap(
                    "persistence",
                    "not-elevated" if not elevated else "access-denied",
                    f"{loc.hive_name}\\{loc.subkey}",
                )
            )
    return entries, gaps
