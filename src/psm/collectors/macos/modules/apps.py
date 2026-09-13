"""Applications — bundle walk over the standard app roots.

Every bundle is read behind its own guard: a single unreadable or malformed
Info.plist costs that one app, never the module (HLD §4 / F2).
"""

from __future__ import annotations

import plistlib
from pathlib import Path
from typing import Any

from psm.collectors.base import ModuleResult
from psm.collectors.macos import signing

SYSTEM_ROOTS = ("/System/Applications", "/System/Applications/Utilities")
USER_ROOTS = ("/Applications", "/Applications/Utilities")


def _roots() -> list[tuple[Path, str]]:
    home = Path.home()
    roots: list[tuple[Path, str]] = [(Path(r), "system") for r in SYSTEM_ROOTS]
    roots.extend((Path(r), "local") for r in USER_ROOTS)
    roots.append((home / "Applications", "user"))
    return roots


def collect(*, check_signatures: bool = True) -> ModuleResult:
    result = ModuleResult()
    seen: set[str] = set()
    looked_at_anything = False

    for root, scope in _roots():
        if not root.exists():
            continue
        try:
            children = sorted(root.iterdir())
        except OSError as e:
            result.gap("apps", "listdir-failed", f"{root}: {e}")
            continue
        looked_at_anything = True
        for app in children:
            if not app.name.endswith(".app"):
                continue
            try:
                entry = _read_bundle(app, scope, check_signatures=check_signatures)
            except Exception as e:
                result.gap("apps", "bundle-unreadable", f"{app}: {type(e).__name__}: {e}")
                continue
            if entry["id"] in seen:
                continue
            seen.add(entry["id"])
            result.entries.append(entry)

    if not looked_at_anything:
        return result.fail("apps", "no-app-roots-readable")
    return result


def _read_bundle(app: Path, scope: str, *, check_signatures: bool) -> dict[str, Any]:
    info = app / "Contents" / "Info.plist"
    plist: dict[str, Any] = {}
    if info.exists():
        with info.open("rb") as f:
            plist = plistlib.load(f)

    bundle_id = str(plist.get("CFBundleIdentifier") or app.name)
    display = plist.get("CFBundleName") or plist.get("CFBundleDisplayName") or app.stem
    version = plist.get("CFBundleShortVersionString") or plist.get("CFBundleVersion")

    entry: dict[str, Any] = {
        "id": bundle_id,
        "name": str(display),
        "version": str(version) if version is not None else None,
        "path": str(app),
        "scope": scope,
        "source": _classify(app, scope),
        "min_system": str(plist.get("LSMinimumSystemVersion"))
        if plist.get("LSMinimumSystemVersion")
        else None,
    }
    if check_signatures:
        entry.update(signing.check(app).as_payload())
    else:
        entry["signature_status"] = "unknown"
    return entry


def _classify(app: Path, scope: str) -> str:
    if scope == "system":
        return "system"
    if (app / "Contents" / "_MASReceipt").exists():
        return "appstore"
    # Homebrew casks install a symlink in /Applications pointing into the Caskroom.
    try:
        if app.is_symlink() and "Caskroom" in str(app.resolve()):
            return "brew"
    except OSError:
        pass
    return "unknown"
