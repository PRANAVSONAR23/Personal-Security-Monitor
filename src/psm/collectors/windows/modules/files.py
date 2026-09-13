"""Files — hash walk with (size, mtime_ns, file_id) skip cache.

The cache is a per-device dict keyed by norm_path → (size, mtime_ns, file_id, sha256).
The caller loads/saves it — this module is pure input→output.
"""

from __future__ import annotations

import hashlib
import os
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from psm.core.models import CollectionGap
from psm.normalize.paths import norm_path

DEFAULT_MAX_FILE_MB = 200
CacheEntry = tuple[int, int, int, str]  # (size, mtime_ns, file_id, sha256)
CacheMap = dict[str, CacheEntry]

# Extensions that Windows will execute directly. .lnk is intentionally excluded — resolving
# shortcuts requires shell COM, and the target itself will be tracked via its own path.
_EXECUTABLE_EXTS = frozenset({
    ".exe", ".dll", ".msi", ".msp", ".bat", ".cmd", ".ps1", ".ps1xml",
    ".scr", ".com", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
    ".jar", ".cpl", ".sys", ".ocx",
})


def _is_executable(path: str) -> bool:
    dot = path.rfind(".")
    if dot < 0:
        return False
    return path[dot:].casefold() in _EXECUTABLE_EXTS


@dataclass(slots=True)
class WalkResult:
    entries: list[dict[str, Any]]
    gaps: list[CollectionGap]
    cache: CacheMap  # updated cache to persist


def _iso_from_ns(ns: int) -> str:
    return datetime.fromtimestamp(ns / 1_000_000_000, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _hash_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _walk_one(
    root: Path,
    *,
    max_file_bytes: int,
    prior_cache: CacheMap,
    new_cache: CacheMap,
    entries: list[dict[str, Any]],
    gaps: list[CollectionGap],
) -> None:
    for dirpath, _, filenames in os.walk(root, onerror=lambda _: None):
        for fname in filenames:
            full = Path(dirpath) / fname
            try:
                st = full.stat()
            except (OSError, ValueError):
                continue
            if not (st.st_mode & 0o170000) & 0o100000:  # regular files only
                continue

            path_norm = norm_path(str(full), "windows")
            size = st.st_size
            mtime_ns = st.st_mtime_ns
            file_id = st.st_ino

            if size > max_file_bytes:
                new_cache.pop(path_norm, None)
                entries.append(
                    {
                        "path": str(full),
                        "sha256": None,
                        "size": size,
                        "mtime": _iso_from_ns(mtime_ns),
                        "executable": _is_executable(str(full)),
                        "signature_status": "unknown",
                        "skipped": "size",
                    }
                )
                continue

            cached = prior_cache.get(path_norm)
            if cached is not None and cached[:3] == (size, mtime_ns, file_id):
                sha = cached[3]
            else:
                try:
                    sha = _hash_file(full)
                except (OSError, PermissionError) as e:
                    gaps.append(CollectionGap("files", "hash-failed", f"{full}: {e}"))
                    continue

            new_cache[path_norm] = (size, mtime_ns, file_id, sha)
            entries.append(
                {
                    "path": str(full),
                    "sha256": sha,
                    "size": size,
                    "mtime": _iso_from_ns(mtime_ns),
                    "executable": _is_executable(str(full)),
                    "signature_status": "unknown",
                }
            )


def collect(
    roots: Iterable[str | Path],
    *,
    prior_cache: CacheMap | None = None,
    max_file_mb: int = DEFAULT_MAX_FILE_MB,
) -> WalkResult:
    prior_cache = prior_cache or {}
    new_cache: CacheMap = {}
    entries: list[dict[str, Any]] = []
    gaps: list[CollectionGap] = []
    max_bytes = max_file_mb * 1024 * 1024

    for raw_root in roots:
        root = Path(os.path.expandvars(str(raw_root))).expanduser()
        if not root.exists():
            gaps.append(CollectionGap("files", "path-missing", str(root)))
            continue
        if not root.is_dir():
            gaps.append(CollectionGap("files", "not-a-directory", str(root)))
            continue
        _walk_one(
            root,
            max_file_bytes=max_bytes,
            prior_cache=prior_cache,
            new_cache=new_cache,
            entries=entries,
            gaps=gaps,
        )

    return WalkResult(entries=entries, gaps=gaps, cache=new_cache)
