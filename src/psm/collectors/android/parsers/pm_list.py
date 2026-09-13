"""Parser for `pm list packages -f -i --show-versioncode`.

Format (one package per line, since Android 8):

    package:/data/app/…/base.apk=com.example.foo  installer=com.android.vending  versionCode:12345

Older devices may omit the versionCode or installer suffix; both are optional here.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_LINE_RE = re.compile(
    r"^package:(?P<apk>\S+)=(?P<pkg>\S+?)(?:\s+installer=(?P<installer>\S+))?"
    r"(?:\s+versionCode:(?P<versioncode>\d+))?\s*$"
)


@dataclass(slots=True)
class PmListEntry:
    pkg: str
    apk_path: str
    installer: str | None
    version_code: int | None


def parse(text: str) -> list[PmListEntry]:
    entries: list[PmListEntry] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or not line.startswith("package:"):
            continue
        m = _LINE_RE.match(line)
        if not m:
            continue
        version_code = m.group("versioncode")
        entries.append(
            PmListEntry(
                pkg=m.group("pkg"),
                apk_path=m.group("apk"),
                installer=m.group("installer"),
                version_code=int(version_code) if version_code else None,
            )
        )
    return entries


# Well-known installer package IDs → source label used for rules and reporting.
_STORE_INSTALLERS = {
    "com.android.vending": "store",  # Google Play
    "com.amazon.venezia": "store",  # Amazon Appstore
    "com.sec.android.app.samsungapps": "store",  # Samsung Galaxy Store
    "com.huawei.appmarket": "store",
    "com.xiaomi.mipicks": "store",
    "com.oppo.market": "store",
    "com.heytap.market": "store",
    "com.google.android.packageinstaller": "sideload",
    "com.android.packageinstaller": "sideload",
    "com.android.shell": "sideload",  # `adb install` uses this
}


def classify_installer(installer: str | None) -> str:
    """Map installer package to a source label (store / sideload / preinstalled / unknown)."""
    if installer is None:
        return "preinstalled"
    return _STORE_INSTALLERS.get(installer, "unknown")
