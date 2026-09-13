"""Special access — accessibility services and device-admin owners.

Both are modeled as `permission` items with synthetic permission names so a single
rule can cover them:

    { pkg: com.foo, permission: "special:accessibility",  granted: true }
    { pkg: com.foo, permission: "special:device-admin",   granted: true }

Sources:
  - `settings get secure enabled_accessibility_services`
      value: `pkg1/component1:pkg2/component2` or "null"
  - `dpm list-owners` (falls back to `dumpsys device_policy` when the shell command
    is missing on the device).
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

from psm.collectors.android.modules.packages import ModuleResult
from psm.core.models import CollectionGap

ShellFn = Callable[[str], tuple[int, str, str]]

_ACCESSIBILITY_ENTRY = re.compile(r"^([^/]+)/[^:]+$")
_OWNER_PKG = re.compile(r"([\w\.]+)/[\w\.$]+")


def collect(shell: ShellFn) -> ModuleResult:
    result = ModuleResult()
    result.entries.extend(_collect_accessibility(shell, result.gaps))
    result.entries.extend(_collect_device_admins(shell, result.gaps))
    # Both sub-reads failing means we learned nothing about special access.
    result.ok = not (
        len(result.gaps) == 2 and all(g.module == "special_access" for g in result.gaps)
    )
    return result


def _collect_accessibility(shell: ShellFn, gaps: list[CollectionGap]) -> list[dict[str, Any]]:
    rc, stdout, stderr = shell("settings get secure enabled_accessibility_services")
    if rc != 0:
        gaps.append(CollectionGap("special_access", "settings-failed", stderr.strip()[:120]))
        return []
    raw = stdout.strip()
    if raw in ("null", "", "None"):
        return []
    entries: list[dict[str, Any]] = []
    for raw_token in raw.split(":"):
        token = raw_token.strip()
        if not token:
            continue
        m = _ACCESSIBILITY_ENTRY.match(token)
        if not m:
            continue
        entries.append(
            {
                "pkg": m.group(1),
                "permission": "special:accessibility",
                "granted": True,
                "flags": [],
            }
        )
    return entries


def _collect_device_admins(shell: ShellFn, gaps: list[CollectionGap]) -> list[dict[str, Any]]:
    rc, stdout, stderr = shell("dpm list-owners")
    if rc != 0:
        # Fallback: dumpsys device_policy — noisier, but covers older devices.
        rc, stdout, stderr = shell("dumpsys device_policy")
        if rc != 0:
            gaps.append(
                CollectionGap("special_access", "device-policy-failed", stderr.strip()[:120])
            )
            return []
    entries: list[dict[str, Any]] = []
    for pkg in _OWNER_PKG.findall(stdout):
        entries.append(
            {
                "pkg": pkg,
                "permission": "special:device-admin",
                "granted": True,
                "flags": [],
            }
        )
    return entries
