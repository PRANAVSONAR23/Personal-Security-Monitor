"""Parser for a single-package `dumpsys package <pkg>` blob.

Only the fields we actually use are extracted; the parser is deliberately narrow so
it survives cosmetic OEM re-formatting. Both Android 13 (SDK 33) and Android 14
(SDK 34) share the layout we care about — differences are in indentation and in the
permission grant syntax.

The rules we need:
  Packages:
    Package [com.example.foo] (…):
      versionName=1.2.3
      firstInstallTime=2026-06-01 12:34:56
      lastUpdateTime=…
      requested permissions:
        android.permission.CAMERA
      runtime permissions:
        android.permission.CAMERA: granted=true, flags=[ USER_SET|…]
        android.permission.CONTACTS: granted=false, flags=[ … ]

runtime permissions live under a per-user block on modern Android:

      User 0: …
        runtime permissions:
          android.permission.CAMERA: granted=true, flags=[…]

Older releases put the block flat under the Package. We handle both.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_PACKAGE_HEADER = re.compile(r"^\s*Package \[(?P<pkg>[^\]]+)\]")
_VERSION_NAME = re.compile(r"^\s*versionName=(?P<v>.+?)\s*$")
_FIRST_INSTALL = re.compile(r"^\s*firstInstallTime=(?P<t>.+?)\s*$")
_LAST_UPDATE = re.compile(r"^\s*lastUpdateTime=(?P<t>.+?)\s*$")
_APP_ID = re.compile(r"^\s*appId=(?P<uid>\d+)\s*$")
_RUNTIME_PERM = re.compile(
    r"^\s*(?P<perm>[\w\.]+):\s*granted=(?P<granted>true|false),\s*flags=\[\s*(?P<flags>[^\]]*)\]"
)
_REQUESTED_PERM_SECTION = re.compile(r"^\s*requested permissions:\s*$")
_RUNTIME_PERM_SECTION = re.compile(r"^\s*runtime permissions:\s*$")


@dataclass(slots=True)
class RuntimePermission:
    permission: str
    granted: bool
    flags: tuple[str, ...]


@dataclass(slots=True)
class DumpsysPackage:
    pkg: str
    version_name: str | None = None
    first_install_time: str | None = None
    last_update_time: str | None = None
    app_id: int | None = None
    runtime_permissions: list[RuntimePermission] = field(default_factory=list)


def parse(text: str) -> DumpsysPackage | None:
    """Parse one `dumpsys package <pkg>` blob. Returns None if no Package block found."""
    lines = text.splitlines()
    header_idx = _find_package_header(lines)
    if header_idx is None:
        return None
    m = _PACKAGE_HEADER.search(lines[header_idx])
    assert m is not None
    result = DumpsysPackage(pkg=m.group("pkg"))

    in_runtime = False
    for line in lines[header_idx + 1 :]:
        # Version / timestamps
        if (v := _VERSION_NAME.match(line)) and result.version_name is None:
            result.version_name = v.group("v")
            continue
        if (t := _FIRST_INSTALL.match(line)) and result.first_install_time is None:
            result.first_install_time = _canon_time(t.group("t"))
            continue
        if (t := _LAST_UPDATE.match(line)) and result.last_update_time is None:
            result.last_update_time = _canon_time(t.group("t"))
            continue
        if (u := _APP_ID.match(line)) and result.app_id is None:
            result.app_id = int(u.group("uid"))
            continue

        # Section markers
        if _RUNTIME_PERM_SECTION.match(line):
            in_runtime = True
            continue
        if _REQUESTED_PERM_SECTION.match(line):
            in_runtime = False
            continue

        if in_runtime:
            perm_match = _RUNTIME_PERM.match(line)
            if perm_match:
                flags_raw = perm_match.group("flags").strip()
                flags = tuple(f for f in re.split(r"[\s|]+", flags_raw) if f)
                result.runtime_permissions.append(
                    RuntimePermission(
                        permission=perm_match.group("perm"),
                        granted=perm_match.group("granted") == "true",
                        flags=flags,
                    )
                )

    return result


def _find_package_header(lines: list[str]) -> int | None:
    for i, line in enumerate(lines):
        if _PACKAGE_HEADER.search(line):
            return i
    return None


def _canon_time(raw: str) -> str:
    """Best-effort conversion of `YYYY-MM-DD HH:MM:SS` (device-local) to ISO-Z.

    Android reports local time without a zone. We preserve the string as-is with a
    trailing Z if it already looks ISO; otherwise we leave it untouched. Downstream
    diffs are hash-based, so as long as the same phone reports the same string
    across snapshots, the diff is stable.
    """
    raw = raw.strip()
    if not raw:
        return raw
    if " " in raw and "T" not in raw:
        return raw.replace(" ", "T", 1) + "Z"
    return raw
