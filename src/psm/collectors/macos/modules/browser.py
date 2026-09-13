"""Browser extensions — Chromium family, Firefox, Safari.

F3: modern Chromium stores `extensions.settings` in **Secure Preferences**, not
`Preferences`. v1 read only `Preferences`, found 0 of the 21 extensions actually
installed on this machine, and recorded no gap — so the report said "no
extensions" when it meant "looked in the wrong file". Both files are read here,
and a profile whose extension store cannot be read anywhere records a gap.
"""

from __future__ import annotations

import json
import plistlib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from psm.collectors.base import ModuleResult

# label -> path under ~/Library/Application Support
CHROMIUM_BROWSERS: dict[str, str] = {
    "chrome": "Google/Chrome",
    "edge": "Microsoft Edge",
    "brave": "BraveSoftware/Brave-Browser",
    "chromium": "Chromium",
    "arc": "Arc",
    "vivaldi": "Vivaldi",
    "opera": "com.operasoftware.Opera",
}

# Secure Preferences first: it is where modern Chromium actually keeps them.
PREF_FILES = ("Secure Preferences", "Preferences")

BROAD_HOSTS = frozenset({"<all_urls>", "*://*/*", "https://*/*", "http://*/*"})

_CHROME_EPOCH_OFFSET = 11644473600  # Chromium counts microseconds from 1601-01-01


def collect() -> ModuleResult:
    result = ModuleResult()
    home = Path.home()
    support = home / "Library" / "Application Support"

    found_any_store = False
    for label, rel in CHROMIUM_BROWSERS.items():
        user_data = support / rel
        if not user_data.exists():
            continue
        if _chromium(label, user_data, result):
            found_any_store = True

    if _firefox(support / "Firefox" / "Profiles", result):
        found_any_store = True
    if _safari(home / "Library" / "Safari" / "Extensions", result):
        found_any_store = True

    # No browser at all on the machine is a legitimate empty result. A browser
    # present whose store we could not read is a gap, recorded above.
    result.ok = True
    _ = found_any_store
    return result


def _chromium(label: str, user_data: Path, result: ModuleResult) -> bool:
    try:
        profiles = sorted(p for p in user_data.iterdir() if p.is_dir())
    except OSError as e:
        result.gap("browser", "profile-listdir-failed", f"{user_data}: {e}")
        return False

    read_any = False
    for profile in profiles:
        settings: dict[str, Any] | None = None
        errors: list[str] = []
        for fname in PREF_FILES:
            path = profile / fname
            if not path.is_file():
                continue
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError, UnicodeDecodeError) as e:
                errors.append(f"{fname}: {type(e).__name__}")
                continue
            candidate = (data.get("extensions") or {}).get("settings") or {}
            if isinstance(candidate, dict) and candidate:
                settings = candidate
                break
        if settings is None:
            if errors:
                result.gap(
                    "browser",
                    "extension-store-unreadable",
                    f"{label}/{profile.name}: {', '.join(errors)}",
                )
            continue

        read_any = True
        for ext_id, ext in settings.items():
            try:
                entry = _chromium_entry(label, profile.name, ext_id, ext)
            except Exception as e:
                result.gap(
                    "browser", "extension-unparseable", f"{label}/{ext_id}: {type(e).__name__}: {e}"
                )
                continue
            if entry is not None:
                result.entries.append(entry)
    return read_any


def _chromium_entry(browser: str, profile: str, ext_id: str, ext: Any) -> dict[str, Any] | None:
    if not isinstance(ext, dict):
        return None
    manifest = ext.get("manifest")
    # `theme` is often an empty dict, which is falsy — test for presence, not truth.
    if not isinstance(manifest, dict) or "theme" in manifest:
        return None

    perms: list[str] = []
    hosts: list[str] = []
    for key in ("permissions", "optional_permissions"):
        for p in manifest.get(key) or []:
            if isinstance(p, str):
                (hosts if "://" in p or p == "<all_urls>" else perms).append(p)
    for key in ("host_permissions", "optional_host_permissions"):
        for p in manifest.get(key) or []:
            if isinstance(p, str):
                hosts.append(p)

    return {
        "browser": browser,
        "profile": profile,
        "id": ext_id,
        "name": str(manifest.get("name") or ext_id),
        "version": str(manifest.get("version")) if manifest.get("version") else None,
        "permissions": sorted(set(perms)),
        "host_permissions": sorted(set(hosts)),
        "broad_host_access": bool(BROAD_HOSTS & set(hosts)),
        "manifest_version": manifest.get("manifest_version")
        if isinstance(manifest.get("manifest_version"), int)
        else None,
        "from_webstore": bool(ext.get("from_webstore", False)),
        "install_time": _chrome_time(ext.get("install_time") or ext.get("first_install_time")),
        "enabled": ext.get("state", 1) == 1,
    }


def _chrome_time(raw: Any) -> str | None:
    if raw is None:
        return None
    try:
        micros = int(raw)
    except (TypeError, ValueError):
        return None
    seconds = micros / 1_000_000 - _CHROME_EPOCH_OFFSET
    if seconds <= 0:
        return None
    return datetime.fromtimestamp(seconds, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _firefox(profiles_root: Path, result: ModuleResult) -> bool:
    if not profiles_root.exists():
        return False
    read_any = False
    for profile in sorted(profiles_root.iterdir()):
        addons = profile / "extensions.json"
        if not addons.is_file():
            continue
        try:
            data = json.loads(addons.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, UnicodeDecodeError) as e:
            result.gap("browser", "extensions-json-unreadable", f"{addons}: {e}")
            continue
        read_any = True
        for addon in data.get("addons") or []:
            if not isinstance(addon, dict):
                continue
            perms: list[str] = []
            hosts: list[str] = []
            for key in ("userPermissions", "optionalPermissions"):
                block = addon.get(key)
                if isinstance(block, dict):
                    perms.extend(str(p) for p in block.get("permissions") or [])
                    hosts.extend(str(o) for o in block.get("origins") or [])
            result.entries.append(
                {
                    "browser": "firefox",
                    "profile": profile.name,
                    "id": str(addon.get("id") or ""),
                    "name": str((addon.get("defaultLocale") or {}).get("name") or addon.get("id")),
                    "version": str(addon.get("version")) if addon.get("version") else None,
                    "permissions": sorted(set(perms)),
                    "host_permissions": sorted(set(hosts)),
                    "broad_host_access": bool(BROAD_HOSTS & set(hosts)),
                    "install_time": _millis(addon.get("installDate")),
                    "enabled": bool(addon.get("active", True) and not addon.get("userDisabled")),
                }
            )
    return read_any


def _millis(raw: Any) -> str | None:
    if raw is None:
        return None
    try:
        return datetime.fromtimestamp(int(raw) / 1000, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (TypeError, ValueError, OSError):
        return None


def _safari(ext_dir: Path, result: ModuleResult) -> bool:
    if not ext_dir.exists():
        return False
    read_any = False
    for path in sorted(ext_dir.iterdir()):
        if not path.name.endswith(".appex"):
            continue
        info = path / "Contents" / "Info.plist"
        if not info.exists():
            continue
        try:
            with info.open("rb") as f:
                plist = plistlib.load(f)
        except Exception as e:
            result.gap("browser", "safari-plist-unreadable", f"{info}: {type(e).__name__}: {e}")
            continue
        read_any = True
        result.entries.append(
            {
                "browser": "safari",
                "profile": "default",
                "id": str(plist.get("CFBundleIdentifier") or path.name),
                "name": str(plist.get("CFBundleName") or path.stem),
                "version": str(plist.get("CFBundleShortVersionString") or "") or None,
                "permissions": [],
                "host_permissions": [],
                "broad_host_access": False,  # Safari sandbox exposes no manifest listing
                "install_time": None,
                "enabled": True,
            }
        )
    return read_any
