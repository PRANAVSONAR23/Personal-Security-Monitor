"""Parser for the bulk `dumpsys package packages` dump.

One call returns every package with metadata and per-user runtime permissions.
Measured on a POCO M2 Pro over wireless ADB: the bulk dump is 1.9 MB and takes
5.7 s. A single `dumpsys package <pkg>` takes 2.3 s, so the per-package approach
costs ~14 minutes for 372 packages — v1 did two such calls per package.

Indentation is load-bearing and consistent (verified on SDK 31 / MIUI 14):

      Packages:
        Package [com.foo] (hash):          <- 2
          versionName=1.2
          install permissions:             <- 4
            android.permission.X: granted=true
          User 0: ceDataInode=... installed=true ...   <- 4
            runtime permissions:           <- 6
              android.permission.CAMERA: granted=false, flags=[ ... ]
      Hidden system packages:              <- shadowed originals of updated
                                              system apps; skipped, they would
                                              duplicate every updated package
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_SECTION = re.compile(r"^(?P<name>[A-Za-z][A-Za-z ]*):$")
_PACKAGE = re.compile(r"^ {2}Package \[(?P<pkg>[^\]]+)\]")
_USER = re.compile(r"^ {4}User (?P<uid>\d+):(?P<rest>.*)$")
_SUBSECTION = re.compile(r"^ {4,6}(?P<name>[a-z][a-z ]*):$")
_FIELD = re.compile(r"^ {4}(?P<key>[A-Za-z][A-Za-z0-9]*)=(?P<val>.*)$")
_PERM = re.compile(
    r"^ +(?P<perm>[A-Za-z][\w.]*(?:\.[\w]+)*): granted=(?P<granted>true|false)"
    r"(?:, flags=\[(?P<flags>[^\]]*)\])?"
)
_KV = re.compile(r"(\w+)=([^\s]+)")


@dataclass(slots=True)
class RuntimePermission:
    permission: str
    granted: bool
    flags: tuple[str, ...] = ()


@dataclass(slots=True)
class DumpsysPackage:
    pkg: str
    user_id: int | None = None
    version_name: str | None = None
    version_code: int | None = None
    first_install_time: str | None = None
    last_update_time: str | None = None
    installer: str | None = None
    code_path: str | None = None
    signing_version: int | None = None
    flags: tuple[str, ...] = ()
    installed: bool = True
    enabled: bool = True
    runtime_permissions: list[RuntimePermission] = field(default_factory=list)
    install_permissions: list[RuntimePermission] = field(default_factory=list)


def parse(  # noqa: PLR0912, PLR0915 — state machine; branches are the grammar
    text: str, *, user: int = 0
) -> list[DumpsysPackage]:
    """Parse the main `Packages:` section. Permissions are taken from `user`."""
    out: list[DumpsysPackage] = []
    current: DumpsysPackage | None = None
    in_packages = False
    perm_target: list[RuntimePermission] | None = None
    current_user: int | None = None

    for line in text.splitlines():
        if not line.strip():
            continue

        section = _SECTION.match(line)
        if section:
            # "Hidden system packages:" holds the shadowed originals of updated
            # system apps — including them double-counts every such package.
            in_packages = section.group("name") == "Packages"
            if not in_packages and current is not None:
                out.append(current)
                current = None
            continue
        if not in_packages:
            continue

        pkg = _PACKAGE.match(line)
        if pkg:
            if current is not None:
                out.append(current)
            current = DumpsysPackage(pkg=pkg.group("pkg"))
            perm_target = None
            current_user = None
            continue
        if current is None:
            continue

        usr = _USER.match(line)
        if usr:
            current_user = int(usr.group("uid"))
            perm_target = None
            if current_user == user:
                kv = dict(_KV.findall(usr.group("rest")))
                current.installed = kv.get("installed") != "false"
                current.enabled = kv.get("enabled", "0") in ("0", "1")
            continue

        sub = _SUBSECTION.match(line)
        if sub:
            name = sub.group("name")
            if name == "install permissions":
                perm_target = current.install_permissions
            elif name == "runtime permissions" and current_user == user:
                perm_target = current.runtime_permissions
            else:
                perm_target = None
            continue

        if perm_target is not None:
            perm = _PERM.match(line)
            if perm:
                flags = perm.group("flags") or ""
                perm_target.append(
                    RuntimePermission(
                        permission=perm.group("perm"),
                        granted=perm.group("granted") == "true",
                        flags=tuple(f for f in re.split(r"[|\s]+", flags.strip()) if f),
                    )
                )
                continue
            perm_target = None

        _absorb_field(current, line)

    if current is not None:
        out.append(current)
    return out


def _absorb_field(p: DumpsysPackage, line: str) -> None:
    m = _FIELD.match(line)
    if not m:
        return
    key, val = m.group("key"), m.group("val").strip()
    if key == "userId":
        p.user_id = int(val) if val.isdigit() else None
    elif key == "versionName":
        p.version_name = val or None
    elif key == "firstInstallTime":
        p.first_install_time = _iso(val)
    elif key == "lastUpdateTime":
        p.last_update_time = _iso(val)
    elif key == "installerPackageName":
        p.installer = val or None
    elif key == "codePath":
        p.code_path = val or None
    elif key == "apkSigningVersion":
        p.signing_version = int(val) if val.isdigit() else None
    elif key == "versionCode":
        # "versionCode=2638006 minSdk=29 targetSdk=36"
        head = val.split(None, 1)[0]
        p.version_code = int(head) if head.isdigit() else None
    elif key == "flags":
        p.flags = tuple(val.strip("[] ").split())


def _iso(raw: str) -> str | None:
    """dumpsys prints local time as 'YYYY-MM-DD HH:MM:SS' with no zone.

    Kept verbatim with a space separator rather than stamped with a 'Z' it has
    not earned — claiming UTC for an unknown-zone local timestamp would be a lie
    that silently shifts every install time by the device's offset.
    """
    raw = raw.strip()
    if not raw or raw.startswith("1970-01-01"):
        return None
    return raw
