"""Shared storage — hash walk of the user-visible directories.

Hashing happens on the device with toybox `sha256sum`, so file content never
crosses the wire; only digests and metadata do. Two calls per run: one for
digests, one for size/mtime. Both use `find -exec ... +`, which batches rather
than spawning per file.

Defaults cover where downloaded and sideloaded content lands. DCIM is excluded
by default — on the test device it is 899 camera files that change constantly and
tell you nothing about device integrity.

Non-root scope: /sdcard only. App-private storage needs the `rooted` tier.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from psm.collectors.base import ModuleResult

ShellFn = Callable[[str], tuple[int, str, str]]

DEFAULT_ROOTS: tuple[str, ...] = (
    "/sdcard/Download",
    "/sdcard/Documents",
)
DEFAULT_MAX_FILE_MB = 200

# Extensions that can execute or install on Android.
INSTALLABLE_EXTS = (".apk", ".apex", ".dex", ".jar", ".so", ".sh", ".aab", ".xapk")


@dataclass(slots=True)
class _Meta:
    size: int
    mtime: int


def collect(
    shell: ShellFn,
    *,
    roots: tuple[str, ...] = DEFAULT_ROOTS,
    max_file_mb: int = DEFAULT_MAX_FILE_MB,
) -> ModuleResult:
    result = ModuleResult()
    if not roots:
        return result

    quoted = " ".join(_q(r) for r in roots)
    looked = False

    meta = _fetch_meta(shell, quoted, result)
    if meta is None:
        return result.fail("storage", "stat-failed", "could not list shared storage")

    digests = _fetch_digests(shell, quoted, max_file_mb, result)
    if digests is None:
        return result.fail("storage", "sha256-failed", "could not hash shared storage")

    looked = True
    for path, m in sorted(meta.items()):
        name = path.rsplit("/", 1)[-1]
        sha = digests.get(path)
        entry: dict[str, Any] = {
            "path": path,
            "size": m.size,
            "mtime": _iso(m.mtime),
            "sha256": sha,
            "installable": name.lower().endswith(INSTALLABLE_EXTS),
        }
        if sha is None:
            # Present in the stat pass but not the digest pass: over the size cap,
            # or unreadable. Recorded rather than dropped.
            entry["skipped"] = "size-or-unreadable"
        result.entries.append(entry)

    if not looked:
        result.ok = False
    return result


def _fetch_meta(shell: ShellFn, quoted: str, result: ModuleResult) -> dict[str, _Meta] | None:
    rc, out, err = shell(f"find {quoted} -type f -exec stat -c '%s|%Y|%n' {{}} + 2>/dev/null")
    if rc != 0 and not out.strip():
        result.gap("storage", "stat-failed", (err or "").strip()[:120])
        return None
    meta: dict[str, _Meta] = {}
    for line in out.splitlines():
        parts = line.rstrip("\r").split("|", 2)
        if len(parts) != 3 or not parts[0].isdigit() or not parts[1].isdigit():
            continue
        meta[parts[2]] = _Meta(size=int(parts[0]), mtime=int(parts[1]))
    return meta


def _fetch_digests(
    shell: ShellFn, quoted: str, max_file_mb: int, result: ModuleResult
) -> dict[str, str] | None:
    rc, out, err = shell(
        f"find {quoted} -type f -size -{max_file_mb}M -exec sha256sum {{}} + 2>/dev/null"
    )
    if rc != 0 and not out.strip():
        result.gap("storage", "sha256-failed", (err or "").strip()[:120])
        return None
    digests: dict[str, str] = {}
    for line in out.splitlines():
        # "<64 hex>  <path>" — the path is last and may contain spaces.
        sha, sep, path = line.rstrip("\r").partition("  ")
        if sep and len(sha) == 64:
            digests[path.strip()] = sha
    return digests


def _iso(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _q(path: str) -> str:
    return "'" + path.replace("'", "'\\''") + "'"
