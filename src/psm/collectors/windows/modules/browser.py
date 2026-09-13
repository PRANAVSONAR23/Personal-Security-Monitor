r"""Browser extensions — Chrome, Edge, Firefox on Windows.

Chrome/Edge: read `<UserData>\<Profile>\Preferences` JSON, walk the `extensions.settings`
dict; each entry's `manifest` block carries name, version, and permissions.

Firefox: `<Profile>\extensions.json` has an `addons` array with `manifest`, `name`, `version`,
and `defaultLocale`. Permissions live under `defaultLocale.userDisabled == False` addons.

All reads are copy-then-parse to avoid touching a live browser's file. Preferences is a
plain JSON file, not a SQLite DB, so no WAL surprises.
"""

from __future__ import annotations

import configparser
import datetime as _dt
import json
import os
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from psm.core.models import CollectionGap


@dataclass(slots=True)
class BrowserConfig:
    """Optional overrides for testing. Empty tuple = use defaults."""

    chrome_user_data: tuple[str, ...] = ()
    edge_user_data: tuple[str, ...] = ()
    firefox_profiles_ini: tuple[str, ...] = ()


def _default_chrome_user_data() -> tuple[str, ...]:
    local = os.environ.get("LOCALAPPDATA")
    if not local:
        return ()
    return (str(Path(local) / "Google" / "Chrome" / "User Data"),)


def _default_edge_user_data() -> tuple[str, ...]:
    local = os.environ.get("LOCALAPPDATA")
    if not local:
        return ()
    return (str(Path(local) / "Microsoft" / "Edge" / "User Data"),)


def _default_firefox_profiles() -> tuple[str, ...]:
    roaming = os.environ.get("APPDATA")
    if not roaming:
        return ()
    return (str(Path(roaming) / "Mozilla" / "Firefox" / "profiles.ini"),)


def collect(
    config: BrowserConfig | None = None,
) -> tuple[list[dict[str, Any]], list[CollectionGap]]:
    cfg = config or BrowserConfig()
    entries: list[dict[str, Any]] = []
    gaps: list[CollectionGap] = []

    chrome_roots = cfg.chrome_user_data or _default_chrome_user_data()
    edge_roots = cfg.edge_user_data or _default_edge_user_data()
    firefox_roots = cfg.firefox_profiles_ini or _default_firefox_profiles()

    entries.extend(_collect_chromium("chrome", chrome_roots, gaps))
    entries.extend(_collect_chromium("edge", edge_roots, gaps))
    entries.extend(_collect_firefox(firefox_roots, gaps))
    return entries, gaps


def _collect_chromium(
    browser: str, user_data_dirs: Iterable[str], gaps: list[CollectionGap]
) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for user_data in user_data_dirs:
        root = Path(user_data)
        if not root.exists():
            continue
        for prefs_path in _iter_chromium_prefs(root):
            try:
                data = json.loads(prefs_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as e:
                gaps.append(
                    CollectionGap(
                        "browser",
                        "preferences-unreadable",
                        f"{prefs_path}: {e}",
                    )
                )
                continue
            entries.extend(_chromium_extensions(browser, prefs_path.parent.name, data))
    return entries


def _iter_chromium_prefs(user_data: Path) -> list[Path]:
    """Chromium keeps one Preferences file per profile under <UserData>\\<ProfileDir>."""
    out: list[Path] = []
    try:
        children = list(user_data.iterdir())
    except OSError:
        return out
    for child in children:
        prefs = child / "Preferences"
        if prefs.is_file():
            out.append(prefs)
    return out


def _chromium_extensions(browser: str, profile: str, prefs: Any) -> list[dict[str, Any]]:
    if not isinstance(prefs, dict):
        return []
    settings = _dig(prefs, "extensions", "settings")
    if not isinstance(settings, dict):
        return []
    out: list[dict[str, Any]] = []
    for ext_id, ext in settings.items():
        if not isinstance(ext, dict):
            continue
        manifest = ext.get("manifest") or {}
        if not isinstance(manifest, dict):
            continue
        # Skip theme, component, and default-installed extensions — noise for our purposes.
        if manifest.get("theme"):
            continue
        location = ext.get("location")
        if location in (5, 10):  # 5=EXTERNAL_COMPONENT, 10=EXTERNAL_POLICY_DOWNLOAD → non-user
            continue
        name = manifest.get("name") or ext_id
        version = manifest.get("version")
        permissions = _chromium_permissions(manifest)
        out.append(
            {
                "browser": browser,
                "profile": profile,
                "id": ext_id,
                "name": str(name),
                "version": str(version) if version is not None else None,
                "permissions": permissions,
                "install_time": _chromium_install_time(ext),
                "enabled": bool(ext.get("state", 1) == 1),
            }
        )
    return out


def _chromium_permissions(manifest: dict[str, Any]) -> list[str]:
    perms: list[str] = []
    for key in ("permissions", "optional_permissions"):
        raw = manifest.get(key)
        if isinstance(raw, list):
            perms.extend(str(p) for p in raw if isinstance(p, str))
    hosts = manifest.get("host_permissions")
    if isinstance(hosts, list):
        perms.extend(str(h) for h in hosts if isinstance(h, str))
    # De-dupe while preserving order.
    seen: set[str] = set()
    ordered: list[str] = []
    for p in perms:
        if p not in seen:
            seen.add(p)
            ordered.append(p)
    return ordered


def _chromium_install_time(ext: dict[str, Any]) -> str | None:
    """Chromium stores install time as Windows FILETIME microseconds since 1601."""
    raw = ext.get("install_time") or ext.get("last_update_time_start")
    if raw is None:
        return None
    try:
        micros = int(raw)
    except (TypeError, ValueError):
        return None
    # Windows FILETIME epoch is 1601-01-01. Convert to Unix seconds.
    unix_seconds = micros / 1_000_000 - 11644473600
    if unix_seconds < 0:
        return None
    return _dt.datetime.fromtimestamp(unix_seconds, tz=_dt.UTC).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def _collect_firefox(
    profiles_ini_paths: Iterable[str], gaps: list[CollectionGap]
) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for ini_path in profiles_ini_paths:
        ini = Path(ini_path)
        if not ini.exists():
            continue
        for profile_dir in _iter_firefox_profiles(ini):
            addons_json = profile_dir / "extensions.json"
            if not addons_json.exists():
                continue
            try:
                data = json.loads(addons_json.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as e:
                gaps.append(
                    CollectionGap(
                        "browser", "extensions-json-unreadable", f"{addons_json}: {e}"
                    )
                )
                continue
            addons = data.get("addons") if isinstance(data, dict) else None
            if not isinstance(addons, list):
                continue
            for addon in addons:
                if not isinstance(addon, dict):
                    continue
                entries.append(_firefox_addon(profile_dir.name, addon))
    return entries


def _iter_firefox_profiles(profiles_ini: Path) -> list[Path]:
    """Parse the classic INI to find profile paths. Falls back to sibling `Profiles/` dirs."""
    profiles: list[Path] = []
    parser = configparser.ConfigParser()
    try:
        parser.read(profiles_ini, encoding="utf-8")
    except (OSError, configparser.Error):
        return profiles
    base = profiles_ini.parent
    for section in parser.sections():
        if not section.startswith("Profile"):
            continue
        path = parser.get(section, "Path", fallback=None)
        if not path:
            continue
        is_relative = parser.get(section, "IsRelative", fallback="1") == "1"
        candidate = (base / path) if is_relative else Path(path)
        if candidate.exists():
            profiles.append(candidate)
    return profiles


def _firefox_addon(profile: str, addon: dict[str, Any]) -> dict[str, Any]:
    perms: list[str] = []
    for key in ("userPermissions", "optionalPermissions"):
        block = addon.get(key)
        if isinstance(block, dict):
            for k in ("permissions", "origins"):
                lst = block.get(k)
                if isinstance(lst, list):
                    perms.extend(str(p) for p in lst if isinstance(p, str))
    ext_id = addon.get("id") or addon.get("addonId") or ""
    return {
        "browser": "firefox",
        "profile": profile,
        "id": str(ext_id),
        "name": str(addon.get("defaultLocale", {}).get("name") or addon.get("name") or ext_id),
        "version": str(addon.get("version")) if addon.get("version") is not None else None,
        "permissions": perms,
        "install_time": _firefox_install_time(addon),
        "enabled": bool(addon.get("active", True) and not addon.get("userDisabled", False)),
    }


def _firefox_install_time(addon: dict[str, Any]) -> str | None:
    raw = addon.get("installDate")
    if raw is None:
        return None
    try:
        millis = int(raw)
    except (TypeError, ValueError):
        return None
    return _dt.datetime.fromtimestamp(millis / 1000, tz=_dt.UTC).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def _dig(root: Any, *path: str) -> Any:
    cur: Any = root
    for key in path:
        if not isinstance(cur, dict) or key not in cur:
            return None
        cur = cur[key]
    return cur
