"""Timeline rendering + JSONL export (Timesketch-compatible field mapping).

Timesketch expects (at minimum) `message`, `datetime`, `timestamp` (µs since epoch),
and `data_type`. We add `psm_*` fields alongside so nothing is lost.
"""

from __future__ import annotations

import datetime as _dt
import json
import re
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

_LAST_RE = re.compile(r"^(\d+)([hd])$")


def parse_last(spec: str) -> _dt.timedelta:
    """Parse a `--last` spec: '24h', '7d'. Raises ValueError otherwise."""
    m = _LAST_RE.match(spec)
    if not m:
        raise ValueError(f"invalid --last spec {spec!r} (want e.g. '24h' or '7d')")
    n, unit = int(m.group(1)), m.group(2)
    return _dt.timedelta(hours=n) if unit == "h" else _dt.timedelta(days=n)


def iso_ago(delta: _dt.timedelta) -> str:
    return (_dt.datetime.now(_dt.UTC) - delta).strftime("%Y-%m-%dT%H:%M:%SZ")


def render_timeline(console: Console, rows: list[dict[str, Any]]) -> None:
    if not rows:
        console.print("[dim]no events in the requested window[/dim]")
        return

    table = Table(title=f"timeline ({len(rows)} event{'s' if len(rows) != 1 else ''})",
                  header_style="bold")
    table.add_column("id", width=6)
    table.add_column("ts")
    table.add_column("category", width=12)
    table.add_column("action", width=8)
    table.add_column("subject")
    table.add_column("sev", width=8)
    for r in rows:
        table.add_row(
            f"#{r['id']}",
            r["ts"],
            r["category"],
            r["action"],
            r["subject_key"],
            r["severity"],
        )
    console.print(table)


def export_jsonl(rows: list[dict[str, Any]], out: Path) -> int:
    """Write Timesketch-compatible JSONL, one event per line. Returns count written."""
    out.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    with out.open("w", encoding="utf-8") as f:
        for r in rows:
            entry = _row_to_timesketch(r)
            f.write(json.dumps(entry, sort_keys=True, separators=(",", ":")))
            f.write("\n")
            written += 1
    return written


def _row_to_timesketch(row: dict[str, Any]) -> dict[str, Any]:
    ts = row["ts"]
    try:
        dt = _dt.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=_dt.UTC)
        micros = int(dt.timestamp() * 1_000_000)
    except (TypeError, ValueError):
        micros = 0
    return {
        "message": f"{row['category']} {row['action']}: {row['subject_key']}",
        "datetime": ts,
        "timestamp": micros,
        "timestamp_desc": "psm event ts",
        "data_type": f"psm:event:{row['category']}",
        "psm_event_id": row["id"],
        "psm_device_id": row["device_id"],
        "psm_snapshot_from": row.get("snap_from"),
        "psm_snapshot_to": row.get("snap_to"),
        "psm_subject_key": row["subject_key"],
        "psm_severity": row["severity"],
        "psm_row_hash": row["row_hash"],
    }
