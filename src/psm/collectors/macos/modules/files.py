"""Files — hash walk with a (size, mtime_ns, inode) skip cache.

Pure input→output: the caller supplies the prior cache and receives the updated
one. The collector never touches the database.

Executability is decided by the mode bits plus a small script-extension list.
v1's shim treated the empty extension as executable, so every extensionless file
counted — which, combined with a rule that alerted on `signature_status:
unknown`, made an alert out of essentially every new file.
"""

from __future__ import annotations

import hashlib
import os
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from psm.collectors.base import FileCache, ModuleResult
from psm.collectors.macos import signing
from psm.normalize.paths import norm_path

DEFAULT_MAX_FILE_MB = 200

SCRIPT_EXTS = frozenset(
    {".sh", ".command", ".py", ".pl", ".rb", ".scpt", ".applescript", ".js", ".zsh", ".bash"}
)
MACHO_EXTS = frozenset({".dylib", ".so", ".bundle", ".kext"})


@dataclass(slots=True)
class WalkResult(ModuleResult):
    cache: FileCache = field(default_factory=dict)


def _iso(ns: int) -> str:
    return datetime.fromtimestamp(ns / 1_000_000_000, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _is_executable(path: Path, mode: int) -> bool:
    ext = path.suffix.lower()
    if ext in SCRIPT_EXTS or ext in MACHO_EXTS:
        return True
    return bool(mode & 0o111)


def _hash(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def collect(
    roots: Iterable[str | Path],
    *,
    prior_cache: FileCache | None = None,
    max_file_mb: int = DEFAULT_MAX_FILE_MB,
    check_signatures: bool = True,
) -> WalkResult:
    result = WalkResult()
    prior = prior_cache or {}
    max_bytes = max_file_mb * 1024 * 1024
    walked_any = False

    for raw_root in roots:
        root = Path(os.path.expandvars(str(raw_root))).expanduser()
        if not root.exists():
            result.gap("files", "path-missing", str(root))
            continue
        if not root.is_dir():
            result.gap("files", "not-a-directory", str(root))
            continue
        walked_any = True
        _walk(root, result, prior, max_bytes, check_signatures)

    if not walked_any:
        result.ok = False
    return result


def _walk(
    root: Path,
    result: WalkResult,
    prior: FileCache,
    max_bytes: int,
    check_signatures: bool,
) -> None:
    for dirpath, _, filenames in os.walk(root, onerror=lambda _: None, followlinks=False):
        for fname in filenames:
            full = Path(dirpath) / fname
            # F2: one unstattable or unreadable file costs one entry, not the walk.
            try:
                _one_file(full, result, prior, max_bytes, check_signatures)
            except Exception as e:
                result.gap("files", "file-failed", f"{full}: {type(e).__name__}: {e}")


def _one_file(
    full: Path,
    result: WalkResult,
    prior: FileCache,
    max_bytes: int,
    check_signatures: bool,
) -> None:
    st = full.lstat()
    if not os.path.stat.S_ISREG(st.st_mode):  # type: ignore[attr-defined]
        return

    path_norm = norm_path(str(full), "macos")
    size, mtime_ns, inode = st.st_size, st.st_mtime_ns, st.st_ino
    executable = _is_executable(full, st.st_mode)

    entry: dict[str, Any] = {
        "path": str(full),
        "size": size,
        "mtime": _iso(mtime_ns),
        "executable": executable,
        "mode": oct(st.st_mode & 0o7777),
    }

    if size > max_bytes:
        entry.update({"sha256": None, "skipped": "size", "signature_status": "unknown"})
        result.entries.append(entry)
        return

    cached = prior.get(path_norm)
    unchanged = cached is not None and cached[:3] == (size, mtime_ns, inode)
    sha = cached[3] if unchanged and cached else _hash(full)
    result.cache[path_norm] = (size, mtime_ns, inode, sha)
    entry["sha256"] = sha

    # codesign costs ~6ms and only means anything for executables.
    if executable and check_signatures:
        entry.update(signing.check(full).as_payload())
    else:
        entry["signature_status"] = "not-applicable" if not executable else "unknown"

    result.entries.append(entry)
