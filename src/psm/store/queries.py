"""Hand-written SQL. No ORM — schema stays honest and the hash chain stays explicit."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable
from dataclasses import asdict
from typing import Any

from psm.core.models import Alert, CollectionGap, Device, InventoryItem, Snapshot
from psm.normalize.canonical import canonical_json


def get_meta(conn: sqlite3.Connection, key: str) -> str | None:
    row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else None


def set_meta(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute(
        "INSERT INTO meta (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )


def insert_device(conn: sqlite3.Connection, device: Device) -> int:
    cur = conn.execute(
        "INSERT INTO devices (name, platform, identifier, created_at, meta) "
        "VALUES (?, ?, ?, ?, ?)",
        (
            device.name,
            device.platform,
            device.identifier,
            device.created_at,
            json.dumps(device.meta, sort_keys=True, separators=(",", ":")),
        ),
    )
    assert cur.lastrowid is not None
    device.id = cur.lastrowid
    return device.id


def get_device_by_name(conn: sqlite3.Connection, name: str) -> Device | None:
    row = conn.execute("SELECT * FROM devices WHERE name = ?", (name,)).fetchone()
    if row is None:
        return None
    return Device(
        id=row["id"],
        name=row["name"],
        platform=row["platform"],
        identifier=row["identifier"],
        created_at=row["created_at"],
        meta=json.loads(row["meta"]),
    )


def insert_item(conn: sqlite3.Connection, item: InventoryItem) -> str:
    h = item.hash
    conn.execute(
        "INSERT OR IGNORE INTO items (hash, category, subject_key, payload) VALUES (?, ?, ?, ?)",
        (h, item.category, item.subject_key, canonical_json(item.payload)),
    )
    return h


def insert_snapshot(
    conn: sqlite3.Connection, snapshot: Snapshot, items: Iterable[InventoryItem]
) -> int:
    cur = conn.execute(
        "INSERT INTO snapshots (device_id, taken_at, kind, capabilities, tool_version, gaps) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (
            snapshot.device_id,
            snapshot.taken_at,
            snapshot.kind,
            json.dumps(sorted(snapshot.capabilities), separators=(",", ":")),
            snapshot.tool_version,
            json.dumps([asdict(g) for g in snapshot.gaps], separators=(",", ":")),
        ),
    )
    assert cur.lastrowid is not None
    snapshot.id = cur.lastrowid
    for item in items:
        h = insert_item(conn, item)
        conn.execute(
            "INSERT OR IGNORE INTO snapshot_items (snapshot_id, item_hash) VALUES (?, ?)",
            (snapshot.id, h),
        )
    return snapshot.id


def load_snapshot(conn: sqlite3.Connection, snapshot_id: int) -> Snapshot:
    row = conn.execute("SELECT * FROM snapshots WHERE id = ?", (snapshot_id,)).fetchone()
    if row is None:
        raise KeyError(f"snapshot {snapshot_id} not found")
    gaps = [CollectionGap(**g) for g in json.loads(row["gaps"])]
    return Snapshot(
        id=row["id"],
        device_id=row["device_id"],
        taken_at=row["taken_at"],
        kind=row["kind"],
        capabilities=set(json.loads(row["capabilities"])),
        tool_version=row["tool_version"],
        gaps=gaps,
    )


def load_snapshot_items(conn: sqlite3.Connection, snapshot_id: int) -> list[InventoryItem]:
    rows = conn.execute(
        "SELECT i.hash, i.category, i.subject_key, i.payload "
        "FROM snapshot_items si JOIN items i ON i.hash = si.item_hash "
        "WHERE si.snapshot_id = ?",
        (snapshot_id,),
    ).fetchall()
    return [
        InventoryItem(
            category=r["category"], subject_key=r["subject_key"], payload=json.loads(r["payload"])
        )
        for r in rows
    ]


def insert_alert(
    conn: sqlite3.Connection, alert: Alert, contributing_event_ids: Iterable[int]
) -> int:
    cur = conn.execute(
        "INSERT INTO alerts (rule_id, device_id, ts, title, detail, status) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (
            alert.rule_id,
            alert.device_id,
            alert.ts,
            alert.title,
            json.dumps(alert.detail, sort_keys=True, separators=(",", ":")),
            alert.status,
        ),
    )
    assert cur.lastrowid is not None
    alert.id = cur.lastrowid
    for event_id in contributing_event_ids:
        conn.execute(
            "INSERT INTO alert_events (alert_id, event_id) VALUES (?, ?)",
            (alert.id, event_id),
        )
    return alert.id


def load_alerts(
    conn: sqlite3.Connection, status: str | None = None
) -> list[Alert]:
    if status:
        rows = conn.execute(
            "SELECT * FROM alerts WHERE status = ? ORDER BY id DESC", (status,)
        ).fetchall()
    else:
        rows = conn.execute("SELECT * FROM alerts ORDER BY id DESC").fetchall()
    return [
        Alert(
            id=r["id"],
            rule_id=r["rule_id"],
            device_id=r["device_id"],
            title=r["title"],
            detail=json.loads(r["detail"]),
            ts=r["ts"],
            status=r["status"],
        )
        for r in rows
    ]


def set_alert_status(conn: sqlite3.Connection, alert_id: int, status: str) -> bool:
    cur = conn.execute(
        "UPDATE alerts SET status = ? WHERE id = ?", (status, alert_id)
    )
    return cur.rowcount > 0


def load_event(conn: sqlite3.Connection, event_id: int) -> dict[str, Any] | None:
    row = conn.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
    if row is None:
        return None
    return dict(row)


def load_item_payload(conn: sqlite3.Connection, item_hash: str) -> dict[str, Any] | None:
    row = conn.execute("SELECT payload FROM items WHERE hash = ?", (item_hash,)).fetchone()
    if row is None:
        return None
    payload = json.loads(row["payload"])
    return payload if isinstance(payload, dict) else None


def load_file_hash_cache(
    conn: sqlite3.Connection, device_id: int
) -> dict[str, tuple[int, int, int, str]]:
    rows = conn.execute(
        "SELECT path_norm, size, mtime_ns, file_id, sha256 FROM file_hash_cache "
        "WHERE device_id = ?",
        (device_id,),
    ).fetchall()
    return {r["path_norm"]: (r["size"], r["mtime_ns"], r["file_id"], r["sha256"]) for r in rows}


def save_file_hash_cache(
    conn: sqlite3.Connection, device_id: int, cache: dict[str, tuple[int, int, int, str]]
) -> None:
    conn.execute("DELETE FROM file_hash_cache WHERE device_id = ?", (device_id,))
    conn.executemany(
        "INSERT INTO file_hash_cache (device_id, path_norm, size, mtime_ns, file_id, sha256) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        [
            (device_id, path, size, mtime_ns, file_id, sha)
            for path, (size, mtime_ns, file_id, sha) in cache.items()
        ],
    )


def load_latest_snapshot_id(
    conn: sqlite3.Connection, device_id: int, kinds: tuple[str, ...] | None = None
) -> int | None:
    if kinds:
        placeholders = ",".join("?" * len(kinds))
        row = conn.execute(
            f"SELECT id FROM snapshots WHERE device_id = ? AND kind IN ({placeholders}) "
            f"ORDER BY id DESC LIMIT 1",
            (device_id, *kinds),
        ).fetchone()
    else:
        row = conn.execute(
            "SELECT id FROM snapshots WHERE device_id = ? ORDER BY id DESC LIMIT 1",
            (device_id,),
        ).fetchone()
    return int(row["id"]) if row else None


def load_timeline(
    conn: sqlite3.Connection,
    *,
    device_id: int | None = None,
    category: str | None = None,
    since_iso: str | None = None,
    limit: int = 500,
) -> list[dict[str, Any]]:
    """Return event rows most recent first, with optional filters. Empty list on no match."""
    clauses: list[str] = []
    params: list[Any] = []
    if device_id is not None:
        clauses.append("device_id = ?")
        params.append(device_id)
    if category is not None:
        clauses.append("category = ?")
        params.append(category)
    if since_iso is not None:
        clauses.append("ts >= ?")
        params.append(since_iso)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    sql = (
        f"SELECT * FROM events {where} ORDER BY id DESC LIMIT ?"
    )
    params.append(limit)
    rows = conn.execute(sql, tuple(params)).fetchall()
    return [dict(r) for r in rows]


def load_snapshot_index(
    conn: sqlite3.Connection, snapshot_id: int
) -> dict[str, dict[str, str]]:
    """{category: {subject_key: item_hash}} — lean form the diff engine consumes."""
    rows = conn.execute(
        "SELECT i.hash, i.category, i.subject_key "
        "FROM snapshot_items si JOIN items i ON i.hash = si.item_hash "
        "WHERE si.snapshot_id = ?",
        (snapshot_id,),
    ).fetchall()
    idx: dict[str, dict[str, str]] = {}
    for r in rows:
        idx.setdefault(r["category"], {})[r["subject_key"]] = r["hash"]
    return idx
