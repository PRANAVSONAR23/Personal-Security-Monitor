"""Join the two capture legs.

Each leg sees half the picture:

    device leg  app_pkg, but no bytes and only reverse-DNS hostnames
    router leg  real hostnames (DNS/SNI) and byte counts, but no app

Both write to `flows`, so correlation is a post-hoc pass over rows that share a
destination within a time window: a router-leg hostname fills in a device-leg
flow, and a device-leg app fills in a router-leg flow.

This is an attribution, not an observation. A device-leg flow enriched from the
router leg gets `hostname_source` from whichever leg observed the name, and an
app filled in from the device leg only ever applies to a flow to the same
destination inside the window — but two apps talking to the same CDN address in
the same second are genuinely ambiguous, and in that case nothing is filled in
rather than guessing one.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass

DEFAULT_WINDOW_S = 30


@dataclass(slots=True)
class CorrelationResult:
    hostnames_filled: int = 0
    apps_filled: int = 0
    ambiguous: int = 0


def correlate(
    conn: sqlite3.Connection, device_id: int, *, window_s: int = DEFAULT_WINDOW_S
) -> CorrelationResult:
    result = CorrelationResult()
    result.hostnames_filled = _fill_hostnames(conn, device_id, window_s)
    filled, ambiguous = _fill_apps(conn, device_id, window_s)
    result.apps_filled = filled
    result.ambiguous = ambiguous
    return result


def _fill_hostnames(conn: sqlite3.Connection, device_id: int, window_s: int) -> int:
    """Give device-leg flows the hostname the router leg observed on the wire."""
    rows = conn.execute(
        "SELECT d.id, ("
        "  SELECT r.hostname FROM flows r "
        "  WHERE r.device_id = d.device_id AND r.leg = 'router' "
        "    AND r.dst_ip = d.dst_ip AND r.hostname IS NOT NULL "
        "    AND abs(strftime('%s', r.ts) - strftime('%s', d.ts)) <= ? "
        "  ORDER BY abs(strftime('%s', r.ts) - strftime('%s', d.ts)) LIMIT 1"
        ") AS found "
        "FROM flows d WHERE d.device_id = ? AND d.leg = 'device' "
        "  AND (d.hostname IS NULL OR d.hostname_source = 'rdns')",
        (window_s, device_id),
    ).fetchall()
    filled = 0
    for row in rows:
        if row["found"] is None:
            continue
        conn.execute(
            "UPDATE flows SET hostname = ?, hostname_source = 'sni' WHERE id = ?",
            (row["found"], row["id"]),
        )
        filled += 1
    return filled


def _fill_apps(conn: sqlite3.Connection, device_id: int, window_s: int) -> tuple[int, int]:
    """Give router-leg flows the app the device leg attributed.

    Several apps reaching one address inside the window is genuinely ambiguous,
    so those are counted and left alone.
    """
    rows = conn.execute(
        "SELECT r.id, ("
        "  SELECT COUNT(DISTINCT d.app_pkg) FROM flows d "
        "  WHERE d.device_id = r.device_id AND d.leg = 'device' "
        "    AND d.dst_ip = r.dst_ip AND d.app_pkg IS NOT NULL "
        "    AND abs(strftime('%s', d.ts) - strftime('%s', r.ts)) <= ?"
        ") AS candidates, ("
        "  SELECT d.app_pkg FROM flows d "
        "  WHERE d.device_id = r.device_id AND d.leg = 'device' "
        "    AND d.dst_ip = r.dst_ip AND d.app_pkg IS NOT NULL "
        "    AND abs(strftime('%s', d.ts) - strftime('%s', r.ts)) <= ? "
        "  ORDER BY abs(strftime('%s', d.ts) - strftime('%s', r.ts)) LIMIT 1"
        ") AS found "
        "FROM flows r WHERE r.device_id = ? AND r.leg = 'router' AND r.app_pkg IS NULL",
        (window_s, window_s, device_id),
    ).fetchall()
    filled = ambiguous = 0
    for row in rows:
        if not row["candidates"]:
            continue
        if row["candidates"] > 1:
            ambiguous += 1
            continue
        conn.execute("UPDATE flows SET app_pkg = ? WHERE id = ?", (row["found"], row["id"]))
        filled += 1
    return filled, ambiguous
