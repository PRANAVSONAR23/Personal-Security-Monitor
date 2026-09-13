"""Persistence — launchd jobs plus Background Task Management login items.

Locations are scoped so reports can separate "Apple shipped this" from "something
installed this into my user account", which is where the real signal is.

`sfltool dumpbtm` needs root, so login items are an `admin`-tier read. Without it
the module still returns every launchd job and records a gap for the BTM half —
partial collection is normal, silent omission is not.
"""

from __future__ import annotations

import plistlib
import re
from pathlib import Path
from typing import Any

from psm.collectors.base import ModuleResult
from psm.collectors.subprocess_util import ProcTimeout, run

_ITEM_HEADER = re.compile(r"^#\d+:$")

# (path, location label, scope)
LAUNCH_DIRS: tuple[tuple[str, str, str], ...] = (
    ("/System/Library/LaunchAgents", "launchagent", "system"),
    ("/System/Library/LaunchDaemons", "launchdaemon", "system"),
    ("/Library/LaunchAgents", "launchagent", "admin"),
    ("/Library/LaunchDaemons", "launchdaemon", "admin"),
)


def collect(*, include_system: bool = True, with_login_items: bool = True) -> ModuleResult:
    result = ModuleResult()
    dirs = [
        (Path(p), loc, scope)
        for p, loc, scope in LAUNCH_DIRS
        if include_system or scope != "system"
    ]
    dirs.append((Path.home() / "Library" / "LaunchAgents", "launchagent", "user"))

    looked = False
    for directory, location, scope in dirs:
        if not directory.exists():
            continue
        try:
            children = sorted(directory.iterdir())
        except OSError as e:
            result.gap("persistence", "listdir-failed", f"{directory}: {e}")
            continue
        looked = True
        for path in children:
            if not path.name.endswith(".plist"):
                continue
            # F2: guard the smallest unit that can fail. A single malformed system
            # plist raising ExpatError zeroed all 471 entries in v1, because the
            # guard sat at module level and caught only OSError.
            try:
                result.entries.append(_read_job(path, location, scope))
            except Exception as e:
                result.gap("persistence", "plist-unreadable", f"{path}: {type(e).__name__}: {e}")

    if not looked:
        return result.fail("persistence", "no-launchd-dirs-readable")

    if with_login_items:
        items, gap = _login_items()
        result.entries.extend(items)
        if gap is not None:
            result.gap("persistence", *gap)
    return result


def _read_job(path: Path, location: str, scope: str) -> dict[str, Any]:
    with path.open("rb") as f:
        plist = plistlib.load(f)

    label = str(plist.get("Label") or path.stem)
    program = plist.get("Program")
    args_raw = plist.get("ProgramArguments") or []
    target = str(program) if program is not None else ""
    args: list[str] = []
    if isinstance(args_raw, list) and args_raw:
        if program is None:
            target = str(args_raw[0])
            args = [str(a) for a in args_raw[1:]]
        else:
            args = [str(a) for a in args_raw]

    return {
        "location": location,
        "scope": scope,
        "name": label,
        "path": str(path),
        "target": target,
        "args": args,
        "run_at_load": bool(plist.get("RunAtLoad", False)),
        "keep_alive": bool(plist.get("KeepAlive", False)),
        "enabled": not bool(plist.get("Disabled", False)),
        "start_interval": plist.get("StartInterval")
        if isinstance(plist.get("StartInterval"), int)
        else None,
        "watch_paths": [str(p) for p in (plist.get("WatchPaths") or [])]
        if isinstance(plist.get("WatchPaths"), list)
        else [],
    }


def _login_items() -> tuple[list[dict[str, Any]], tuple[str, str] | None]:
    """Login items via `sfltool dumpbtm`. Requires root (the `admin` tier)."""
    try:
        proc = run(["/usr/bin/sfltool", "dumpbtm"], timeout_s=30)
    except (ProcTimeout, OSError) as e:
        return [], ("btm-unavailable", str(e))
    if proc.returncode != 0:
        return [], (
            "btm-needs-admin",
            "sfltool dumpbtm requires root; login items not collected",
        )
    return _parse_btm(proc.stdout.decode("utf-8", errors="replace")), None


def _parse_btm(text: str) -> list[dict[str, Any]]:
    """Parse the item blocks `sfltool dumpbtm` prints.

    Structure, as of macOS 26:

        ========================
         Records for UID 501 : <uuid>
        ========================
         Items:
         #1:
                         UUID: E9924669-...
                         Name: Docker
                  Disposition: [disabled, allowed, not notified] (0x2)
          Embedded Item Identifiers:
            #1: 16.com.docker.vmnetd

    An item header is a line that is exactly `#<n>:` with nothing after the
    colon. The nested lists under `Embedded Item Identifiers` and
    `Assoc. Bundle IDs` also use `#<n>:` but always carry a value on the same
    line, so that is the discriminator. The format is undocumented and has
    changed between releases, so only long-stable fields are read.
    """
    entries: list[dict[str, Any]] = []
    current: dict[str, str] = {}
    uid: str | None = None
    in_nested = False

    def flush() -> None:
        if not current:
            return
        name = _clean(current.get("Name")) or _clean(current.get("Identifier"))
        if not name:
            return
        disposition = current.get("Disposition", "")
        entries.append(
            {
                "location": "loginitem",
                "scope": "user",
                "name": name,
                "uuid": _clean(current.get("UUID")),
                "identifier": _clean(current.get("Identifier")),
                "path": _clean(current.get("URL")) or "",
                "target": _clean(current.get("Executable Path"))
                or _clean(current.get("URL"))
                or "",
                "args": [],
                "developer": _clean(current.get("Developer Name")),
                "team_id": _clean(current.get("Team Identifier")),
                "item_type": _clean(current.get("Type")),
                "uid": uid,
                "enabled": "disabled" not in disposition.lower(),
            }
        )

    for raw in text.splitlines():
        stripped = raw.strip()
        if stripped.startswith("Records for UID"):
            flush()
            current = {}
            in_nested = False
            uid = stripped.removeprefix("Records for UID").strip().split(":")[0].strip()
            continue
        if _ITEM_HEADER.match(stripped):
            flush()
            current = {}
            in_nested = False
            continue
        if stripped.endswith(":") and not _ITEM_HEADER.match(stripped):
            # A sub-list header such as "Embedded Item Identifiers:".
            in_nested = True
            continue
        if in_nested or ":" not in stripped:
            continue
        key, _, value = stripped.partition(":")
        current[key.strip()] = value.strip()

    flush()
    return entries


def _clean(value: str | None) -> str | None:
    """`sfltool` prints the literal string "(null)" for absent values."""
    if value is None:
        return None
    v = value.strip()
    return None if v in ("", "(null)") else v
