#!/usr/bin/env python3
"""psm macOS collector shim — stdlib-only, single file.

Runs on the Mac (either directly or piped over SSH from the Windows controller).
Emits ONE JSON envelope on stdout; every diagnostic goes to stderr so `ssh
user@host 'python3 -' < psm_mac_collector.py` produces a clean parseable stream.

Envelope (see collector.schema.json for the authoritative version):
    {
      "psm_collector": "macos",
      "version": "1.0",
      "host": "<uname -n>",
      "taken_at": "2026-07-06T12:34:56Z",
      "modules": { "apps": [...], "persistence": [...], ... },
      "gaps": [ {"module": "permissions", "reason": "fda-missing", "detail": "..."} ]
    }

Modules v1: apps, persistence, files, permissions (TCC), processes, network.
codesign and browser are Phase 5.

CLI:
    python3 psm_mac_collector.py --modules apps,persistence,permissions [--file-walk PATH:PATH]
                                 [--max-file-mb 200]

Failure model: every module is guarded — one exception becomes a `gap` entry, the
envelope still emits successfully. Non-zero exit is reserved for argument errors.
"""

from __future__ import annotations

import argparse
import contextlib
import datetime as _dt
import hashlib
import json
import os
import plistlib
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import traceback
from pathlib import Path
from typing import Any

SHIM_VERSION = "1.0"
DEFAULT_TIMEOUT_S = 60


def _iso_now() -> str:
    return _dt.datetime.now(_dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _stderr(msg: str) -> None:
    print(f"psm-mac-shim: {msg}", file=sys.stderr, flush=True)


def _run(argv: list[str], *, timeout_s: int = DEFAULT_TIMEOUT_S) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            timeout=timeout_s,
            check=False,
        )
    except FileNotFoundError as e:
        return (-1, "", str(e))
    except subprocess.TimeoutExpired as e:
        return (-1, "", f"timeout after {timeout_s}s: {e}")
    return (
        proc.returncode,
        proc.stdout.decode("utf-8", errors="replace"),
        proc.stderr.decode("utf-8", errors="replace"),
    )


# ---------- apps ----------

_APP_ROOTS = ("/Applications", "/System/Applications")


def collect_apps(gaps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    home = Path.home()
    roots = [*_APP_ROOTS, str(home / "Applications")]
    for root in roots:
        root_path = Path(root)
        if not root_path.exists():
            continue
        try:
            children = list(root_path.iterdir())
        except OSError as e:
            gaps.append({"module": "apps", "reason": "listdir-failed", "detail": f"{root}: {e}"})
            continue
        for app in children:
            if not app.name.endswith(".app"):
                continue
            info = _read_bundle_info(app)
            if info is None:
                continue
            entries.append(info)
    return entries


def _read_bundle_info(app: Path) -> dict[str, Any] | None:
    info_plist = app / "Contents" / "Info.plist"
    if not info_plist.exists():
        return {
            "id": app.name,
            "name": app.stem,
            "path": str(app),
            "source": "unknown",
        }
    try:
        with info_plist.open("rb") as f:
            plist = plistlib.load(f)
    except (OSError, plistlib.InvalidFileException):
        return {
            "id": app.name,
            "name": app.stem,
            "path": str(app),
            "source": "unknown",
        }
    bundle_id = plist.get("CFBundleIdentifier") or app.name
    display = plist.get("CFBundleName") or plist.get("CFBundleDisplayName") or app.stem
    version = plist.get("CFBundleShortVersionString") or plist.get("CFBundleVersion")
    source = _classify_app_source(app)
    return {
        "id": str(bundle_id),
        "name": str(display),
        "version": str(version) if version is not None else None,
        "path": str(app),
        "source": source,
    }


def _classify_app_source(app: Path) -> str:
    if (app / "Contents" / "_MASReceipt").exists():
        return "appstore"
    if str(app).startswith("/System/"):
        return "system"
    return "unknown"


# ---------- persistence ----------

_LAUNCH_DIRS = (
    ("/Library/LaunchAgents", "launchagent"),
    ("/Library/LaunchDaemons", "launchdaemon"),
    ("/System/Library/LaunchAgents", "launchagent"),
    ("/System/Library/LaunchDaemons", "launchdaemon"),
)


def collect_persistence(gaps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    home = Path.home()
    dirs = [
        *_LAUNCH_DIRS,
        (str(home / "Library" / "LaunchAgents"), "launchagent"),
    ]
    for path, location in dirs:
        p = Path(path)
        if not p.exists():
            continue
        try:
            children = list(p.iterdir())
        except OSError as e:
            gaps.append({"module": "persistence", "reason": "listdir-failed",
                         "detail": f"{path}: {e}"})
            continue
        for plist_path in children:
            if not plist_path.name.endswith(".plist"):
                continue
            item = _read_launchd_plist(plist_path, location)
            if item is not None:
                entries.append(item)
    return entries


def _read_launchd_plist(plist_path: Path, location: str) -> dict[str, Any] | None:
    try:
        with plist_path.open("rb") as f:
            plist = plistlib.load(f)
    except (OSError, plistlib.InvalidFileException) as e:
        return {
            "location": location,
            "name": plist_path.stem,
            "path": str(plist_path),
            "target": "",
            "args": [],
            "enabled": None,
            "error": str(e),
        }
    label = plist.get("Label") or plist_path.stem
    program = plist.get("Program")
    program_args = plist.get("ProgramArguments") or []
    target = program
    args: list[str] = []
    if isinstance(program_args, list) and program_args:
        if target is None:
            target = str(program_args[0])
            args = [str(a) for a in program_args[1:]]
        else:
            args = [str(a) for a in program_args]
    disabled = bool(plist.get("Disabled", False))
    return {
        "location": location,
        "name": str(label),
        "path": str(plist_path),
        "target": str(target) if target is not None else "",
        "args": args,
        "run_at_load": bool(plist.get("RunAtLoad", False)),
        "enabled": not disabled,
    }


# ---------- permissions (TCC) ----------

_TCC_PATHS = (
    ("/Library/Application Support/com.apple.TCC/TCC.db", "system"),
)


def collect_permissions(gaps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    home = Path.home()
    sources = [
        *_TCC_PATHS,
        (str(home / "Library" / "Application Support" / "com.apple.TCC" / "TCC.db"), "user"),
    ]
    for db_path, scope in sources:
        src = Path(db_path)
        if not src.exists():
            gaps.append({"module": "permissions", "reason": "tcc-missing",
                         "detail": f"{db_path}: not present"})
            continue
        try:
            entries.extend(_read_tcc_copy(src, scope))
        except sqlite3.DatabaseError as e:
            gaps.append({"module": "permissions", "reason": "fda-missing",
                         "detail": f"{db_path}: {e}"})
        except OSError as e:
            gaps.append({"module": "permissions", "reason": "tcc-unreadable",
                         "detail": f"{db_path}: {e}"})
    return entries


def _read_tcc_copy(src: Path, scope: str) -> list[dict[str, Any]]:
    """Copy the TCC.db then open read-only — the live DB is opened WAL by tccd."""
    entries: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="psm-tcc-") as tmp:
        tmp_dir = Path(tmp)
        dst = tmp_dir / "TCC.db"
        shutil.copy2(src, dst)
        # WAL sibling may exist; copy if present so a checkpoint isn't required.
        for suffix in ("-wal", "-shm"):
            side = Path(str(src) + suffix)
            if side.exists():
                with contextlib.suppress(OSError):
                    shutil.copy2(side, str(dst) + suffix)
        conn = sqlite3.connect(f"file:{dst}?mode=ro", uri=True)
        try:
            cur = conn.execute(
                "SELECT service, client, auth_value FROM access "
                "WHERE auth_value IS NOT NULL"
            )
            for service, client, auth_value in cur:
                entries.append(
                    {
                        "pkg": str(client),
                        "permission": str(service),
                        "granted": bool(auth_value),
                        "scope": scope,
                    }
                )
        finally:
            conn.close()
    return entries


# ---------- files ----------

_EXECUTABLE_EXTS = frozenset({"", ".command", ".sh", ".py", ".pl", ".rb"})


def collect_files(
    roots: list[str], max_file_mb: int, gaps: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    if not roots:
        return []
    entries: list[dict[str, Any]] = []
    max_bytes = max_file_mb * 1024 * 1024
    for root in roots:
        root_expanded = os.path.expanduser(os.path.expandvars(root))
        if not os.path.isdir(root_expanded):
            gaps.append(
                {"module": "files", "reason": "root-missing", "detail": root_expanded}
            )
            continue
        for dirpath, _, filenames in os.walk(root_expanded):
            for name in filenames:
                full = os.path.join(dirpath, name)
                try:
                    st = os.stat(full)
                except OSError:
                    continue
                if st.st_size > max_bytes:
                    entries.append(
                        {
                            "path": full,
                            "size": st.st_size,
                            "mtime": _dt.datetime.fromtimestamp(
                                st.st_mtime, tz=_dt.UTC
                            ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                            "sha256": None,
                            "skipped": "size",
                            "executable": _is_executable(name, st.st_mode),
                            "signature_status": "unknown",
                        }
                    )
                    continue
                digest = hashlib.sha256()
                try:
                    with open(full, "rb") as f:
                        for chunk in iter(lambda: f.read(65536), b""):
                            digest.update(chunk)
                except OSError:
                    continue
                entries.append(
                    {
                        "path": full,
                        "size": st.st_size,
                        "mtime": _dt.datetime.fromtimestamp(
                            st.st_mtime, tz=_dt.UTC
                        ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "sha256": digest.hexdigest(),
                        "executable": _is_executable(name, st.st_mode),
                        "signature_status": "unknown",
                    }
                )
    return entries


def _is_executable(name: str, mode: int) -> bool:
    ext = os.path.splitext(name)[1].lower()
    if ext in _EXECUTABLE_EXTS:
        return True
    return bool(mode & 0o111)


# ---------- processes ----------

def collect_processes(gaps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rc, out, err = _run(["/bin/ps", "axo", "pid,ppid,uid,lstart,comm"])
    if rc != 0:
        gaps.append({"module": "processes", "reason": "ps-failed", "detail": err.strip()[:200]})
        return []
    entries: list[dict[str, Any]] = []
    lines = out.splitlines()
    for line in lines[1:]:  # skip header
        parts = line.split(None, 8)
        if len(parts) < 6:
            continue
        pid, ppid, uid = parts[0], parts[1], parts[2]
        # lstart is 5 whitespace-separated fields: 'Sun Jul  6 12:34:56 2026'
        lstart_end = 3 + 5
        if len(parts) < lstart_end + 1:
            continue
        started = " ".join(parts[3:lstart_end])
        comm = parts[lstart_end]
        entries.append({
            "pid": int(pid),
            "ppid": int(ppid),
            "uid": int(uid),
            "started": started,
            "command": comm,
        })
    return entries


# ---------- network (lsof listening sockets) ----------

def collect_network(gaps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rc, out, err = _run(["/usr/sbin/lsof", "-i", "-nP", "-sTCP:LISTEN"])
    if rc != 0:
        gaps.append({"module": "network", "reason": "lsof-failed", "detail": err.strip()[:200]})
        return []
    entries: list[dict[str, Any]] = []
    for raw in out.splitlines()[1:]:  # skip header
        parts = raw.split()
        if len(parts) < 9:
            continue
        command, pid, _user, _fd, _type, _dev, _size, node, name = (
            parts[0], parts[1], parts[2], parts[3], parts[4], parts[5], parts[6], parts[7], parts[8]
        )
        proto = node.lower() if node.lower() in ("tcp", "udp") else "tcp"
        addr, sep, port = name.rpartition(":")
        if not sep:
            continue
        entries.append({
            "proto": proto,
            "addr": addr,
            "port": _to_port(port),
            "process": command,
            "pid_seen": int(pid),
        })
    return entries


def _to_port(raw: str) -> int:
    try:
        return int(raw.split("->", maxsplit=1)[0])
    except (ValueError, IndexError):
        return -1


# ---------- browser ----------

def collect_browser(gaps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    home = Path.home()
    entries.extend(_chromium_extensions("chrome",
        home / "Library" / "Application Support" / "Google" / "Chrome", gaps))
    entries.extend(_chromium_extensions("edge",
        home / "Library" / "Application Support" / "Microsoft Edge", gaps))
    entries.extend(_firefox_extensions(home / "Library" / "Application Support"
                                       / "Firefox" / "Profiles", gaps))
    entries.extend(_safari_extensions(home / "Library" / "Safari" / "Extensions", gaps))
    return entries


def _chromium_extensions(
    browser: str, user_data: Path, gaps: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    if not user_data.exists():
        return []
    out: list[dict[str, Any]] = []
    for profile in user_data.iterdir():
        prefs = profile / "Preferences"
        if not prefs.is_file():
            continue
        try:
            data = json.loads(prefs.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            gaps.append({"module": "browser", "reason": "preferences-unreadable",
                         "detail": f"{prefs}: {e}"})
            continue
        settings = ((data.get("extensions") or {}).get("settings") or {})
        if not isinstance(settings, dict):
            continue
        for ext_id, ext in settings.items():
            if not isinstance(ext, dict):
                continue
            manifest = ext.get("manifest") or {}
            if not isinstance(manifest, dict) or manifest.get("theme"):
                continue
            perms: list[str] = []
            for key in ("permissions", "optional_permissions", "host_permissions"):
                lst = manifest.get(key)
                if isinstance(lst, list):
                    perms.extend(str(p) for p in lst if isinstance(p, str))
            out.append({
                "browser": browser,
                "profile": profile.name,
                "id": ext_id,
                "name": str(manifest.get("name") or ext_id),
                "version": str(manifest.get("version"))
                    if manifest.get("version") is not None else None,
                "permissions": perms,
                "install_time": _chromium_install_time(ext),
                "enabled": bool(ext.get("state", 1) == 1),
            })
    return out


def _chromium_install_time(ext: dict[str, Any]) -> str | None:
    raw = ext.get("install_time") or ext.get("last_update_time_start")
    if raw is None:
        return None
    try:
        micros = int(raw)
    except (TypeError, ValueError):
        return None
    unix_seconds = micros / 1_000_000 - 11644473600
    if unix_seconds < 0:
        return None
    return _dt.datetime.fromtimestamp(unix_seconds, tz=_dt.UTC).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def _firefox_extensions(
    profiles_root: Path, gaps: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    if not profiles_root.exists():
        return []
    out: list[dict[str, Any]] = []
    for profile in profiles_root.iterdir():
        addons = profile / "extensions.json"
        if not addons.is_file():
            continue
        try:
            data = json.loads(addons.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            gaps.append({"module": "browser", "reason": "extensions-json-unreadable",
                         "detail": f"{addons}: {e}"})
            continue
        for addon in (data.get("addons") or []):
            if not isinstance(addon, dict):
                continue
            perms: list[str] = []
            for key in ("userPermissions", "optionalPermissions"):
                block = addon.get(key)
                if isinstance(block, dict):
                    for k in ("permissions", "origins"):
                        lst = block.get(k)
                        if isinstance(lst, list):
                            perms.extend(str(p) for p in lst if isinstance(p, str))
            ext_id = addon.get("id") or ""
            out.append({
                "browser": "firefox",
                "profile": profile.name,
                "id": str(ext_id),
                "name": str(addon.get("defaultLocale", {}).get("name") or ext_id),
                "version": str(addon.get("version")) if addon.get("version") else None,
                "permissions": perms,
                "install_time": _millis_iso(addon.get("installDate")),
                "enabled": bool(addon.get("active", True) and not addon.get("userDisabled")),
            })
    return out


def _safari_extensions(
    ext_dir: Path, gaps: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    if not ext_dir.exists():
        return []
    out: list[dict[str, Any]] = []
    for path in ext_dir.iterdir():
        if not path.name.endswith(".appex"):
            continue
        info_plist = path / "Contents" / "Info.plist"
        if not info_plist.exists():
            continue
        try:
            with info_plist.open("rb") as f:
                plist = plistlib.load(f)
        except (OSError, plistlib.InvalidFileException) as e:
            gaps.append({"module": "browser", "reason": "safari-plist-unreadable",
                         "detail": f"{info_plist}: {e}"})
            continue
        out.append({
            "browser": "safari",
            "profile": "default",
            "id": str(plist.get("CFBundleIdentifier") or path.name),
            "name": str(plist.get("CFBundleName") or path.stem),
            "version": str(plist.get("CFBundleShortVersionString")) if
                plist.get("CFBundleShortVersionString") else None,
            "permissions": [],  # Safari sandbox — no manifest-style listing
            "install_time": None,
            "enabled": True,
        })
    return out


def _millis_iso(raw: Any) -> str | None:
    if raw is None:
        return None
    try:
        millis = int(raw)
    except (TypeError, ValueError):
        return None
    return _dt.datetime.fromtimestamp(millis / 1000, tz=_dt.UTC).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


# ---------- driver ----------

ALL_MODULES: tuple[str, ...] = (
    "apps",
    "persistence",
    "permissions",
    "files",
    "processes",
    "network",
    "browser",
)


def main() -> int:
    ap = argparse.ArgumentParser(description="psm macOS collector shim")
    ap.add_argument("--modules", default=",".join(ALL_MODULES),
                    help="comma-separated module list")
    ap.add_argument("--file-walk", default="",
                    help="colon-separated file-walk roots")
    ap.add_argument("--max-file-mb", type=int, default=200)
    args = ap.parse_args()

    modules = [m.strip() for m in args.modules.split(",") if m.strip()]
    unknown = [m for m in modules if m not in ALL_MODULES]
    if unknown:
        _stderr(f"unknown module(s): {unknown}")
        return 2

    file_roots = [r for r in args.file_walk.split(":") if r] if args.file_walk else []

    gaps: list[dict[str, Any]] = []
    result: dict[str, Any] = {
        "psm_collector": "macos",
        "version": SHIM_VERSION,
        "host": socket.gethostname(),
        "taken_at": _iso_now(),
        "modules": {},
        "gaps": gaps,
    }

    if "apps" in modules:
        result["modules"]["apps"] = _guarded("apps", collect_apps, gaps)
    if "persistence" in modules:
        result["modules"]["persistence"] = _guarded("persistence", collect_persistence, gaps)
    if "permissions" in modules:
        result["modules"]["permissions"] = _guarded("permissions", collect_permissions, gaps)
    if "files" in modules:
        result["modules"]["files"] = _guarded_files(file_roots, args.max_file_mb, gaps)
    if "processes" in modules:
        result["modules"]["processes"] = _guarded("processes", collect_processes, gaps)
    if "network" in modules:
        result["modules"]["network"] = _guarded("network", collect_network, gaps)
    if "browser" in modules:
        result["modules"]["browser"] = _guarded("browser", collect_browser, gaps)

    json.dump(result, sys.stdout, separators=(",", ":"), sort_keys=True)
    sys.stdout.write("\n")
    return 0


def _guarded(
    module: str,
    fn: Any,
    gaps: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    try:
        return fn(gaps)
    except Exception as e:
        _stderr(f"{module} failed: {e}")
        _stderr(traceback.format_exc())
        gaps.append({"module": module, "reason": "exception", "detail": str(e)[:200]})
        return []


def _guarded_files(
    roots: list[str], max_file_mb: int, gaps: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    try:
        return collect_files(roots, max_file_mb, gaps)
    except Exception as e:
        _stderr(f"files failed: {e}")
        gaps.append({"module": "files", "reason": "exception", "detail": str(e)[:200]})
        return []


if __name__ == "__main__":
    sys.exit(main())
