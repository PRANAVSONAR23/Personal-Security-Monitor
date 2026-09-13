"""Permissions — the TCC databases (user and system).

The live databases are held open WAL by `tccd`, so each is copied to a temp dir
and opened read-only. Both require Full Disk Access; without it the read fails
and the module records a gap rather than reporting "no permissions granted".

`auth_value` is NOT a boolean. Observed values:

    0  denied
    1  unknown (legacy rows)
    2  allowed
    3  limited   (e.g. limited Photos access)
    4  limited   (variant)
    5  limited   (seen on kTCCServiceSystemPolicyAppData)

v1 did `granted: bool(auth_value)`, which silently reported every limited grant
as a full one and would report any future value as granted. Here the raw value is
kept alongside an explicit tri-state, and an unrecognised value becomes "unknown"
rather than being coerced.
"""

from __future__ import annotations

import shutil
import sqlite3
import tempfile
from contextlib import suppress
from pathlib import Path
from typing import Any

from psm.collectors.base import ModuleResult

AUTH_STATES: dict[int, str] = {
    0: "denied",
    1: "unknown",
    2: "allowed",
    3: "limited",
    4: "limited",
    5: "limited",
}

CLIENT_TYPES: dict[int, str] = {0: "bundle-id", 1: "path"}


def _sources() -> list[tuple[Path, str]]:
    return [
        (Path("/Library/Application Support/com.apple.TCC/TCC.db"), "system"),
        (
            Path.home() / "Library" / "Application Support" / "com.apple.TCC" / "TCC.db",
            "user",
        ),
    ]


def collect() -> ModuleResult:
    result = ModuleResult()
    read_any = False

    for src, scope in _sources():
        if not src.exists():
            result.gap("permissions", "tcc-missing", str(src))
            continue
        try:
            result.entries.extend(_read_copy(src, scope))
            read_any = True
        except sqlite3.DatabaseError as e:
            result.gap("permissions", "tcc-unreadable", f"{src}: {e}")
        except PermissionError as e:
            result.gap(
                "permissions",
                "fda-missing",
                f"{src}: {e} — grant Full Disk Access to your terminal",
            )
        except OSError as e:
            result.gap("permissions", "tcc-copy-failed", f"{src}: {e}")

    if not read_any:
        result.ok = False
    return result


def _read_copy(src: Path, scope: str) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="psm-tcc-") as tmp:
        dst = Path(tmp) / "TCC.db"
        shutil.copy2(src, dst)
        for suffix in ("-wal", "-shm"):
            side = Path(str(src) + suffix)
            if side.exists():
                with suppress(OSError):
                    shutil.copy2(side, str(dst) + suffix)

        conn = sqlite3.connect(f"file:{dst}?mode=ro", uri=True)
        try:
            rows = conn.execute(
                "SELECT service, client, client_type, auth_value, auth_reason, "
                "       indirect_object_identifier "
                "FROM access"
            ).fetchall()
        finally:
            conn.close()

    for service, client, client_type, auth_value, auth_reason, indirect in rows:
        state = AUTH_STATES.get(int(auth_value), "unknown")
        entries.append(
            {
                "pkg": str(client),
                "client_type": CLIENT_TYPES.get(int(client_type), "unknown"),
                "permission": str(service),
                "granted": state == "allowed",
                "state": state,
                "auth_value": int(auth_value),
                "auth_reason": int(auth_reason) if auth_reason is not None else None,
                "target": _clean_indirect(indirect),
                "scope": scope,
            }
        )
    return entries


def _clean_indirect(value: object) -> str | None:
    """TCC stores the controlled app for AppleEvents-style grants here.

    It is part of the table's real primary key — `(service, client, client_type,
    indirect_object_identifier)` — so it must reach the subject key, or two rows
    such as "DeskTime may drive Brave" and "DeskTime may drive Chrome" collapse
    into one item and silently overwrite each other.
    """
    if value is None:
        return None
    text = str(value).strip()
    return None if text in ("", "UNUSED", "(null)") else text
